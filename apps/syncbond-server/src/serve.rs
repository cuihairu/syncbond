//! The serve loop (todo.md DSR-23, DSR-24): accept with a connection
//! budget and a header-read timeout, hand each connection to hyper-util
//! with upgrades so the WebSocket routes keep working, and stop on a
//! shutdown signal after a bounded drain (default-server.md §4:
//! bounded resources and an exit that keeps its promises).
//!
//! `axum::serve` has no knobs for any of this, and all of it is
//! bounded-resource requirement, not convenience: an accept loop that
//! queues every connect delays the overload instead of refusing it, a
//! client that trickles request headers forever pins a worker, and a
//! process that exits mid-request drops work it already accepted. Values
//! come from the deployer's config (`maxConnections`,
//! `headerTimeoutSeconds`, `shutdownTimeoutSeconds`; `0` disables each).
//! Serving must use `into_make_service_with_connect_info` — the
//! pairing-room creation route rate-limits per peer address
//! (relay-protocol.md §9).
//!
//! Shutdown, in order: the [`Shutdown`] signal fires, the listener is
//! dropped (a client connecting from then on is refused by the kernel,
//! not queued behind a dying server), every live connection is told to
//! finish the request it already accepted and then close
//! (hyper's graceful shutdown), and the loop waits for those connections
//! to end — for at most `drainTimeoutSeconds`, or with no deadline when
//! that is `0`. Whatever is still running when the budget elapses is
//! dropped with the process; nothing here pretends an abandoned request
//! was served.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower_service::Service as _;

/// What the serve loop needs beyond the router: the deployment budgets.
/// `0` in any field disables that limit.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// TCP connections handled at once; everything above is dropped at
    /// accept time.
    pub max_connections: usize,
    /// Seconds a client has to finish sending request headers.
    pub header_timeout_seconds: u64,
    /// Seconds the drain after a shutdown signal may take; `0` waits for
    /// every accepted connection to end with no deadline.
    pub drain_timeout_seconds: u64,
}

/// The stop signal, clonable and one-way: every clone shares one flag, so
/// the process can be told to stop from anywhere (the signal handler in
/// `main`, a test) and everything that holds a clone — the accept loop,
/// each connection, every WebSocket session — sees the same edge.
#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    state: Arc<ShutdownState>,
}

#[derive(Debug, Default)]
struct ShutdownState {
    fired: AtomicBool,
    waiters: tokio::sync::Notify,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fire the signal. Idempotent: a second call changes nothing.
    pub fn fire(&self) {
        if !self.state.fired.swap(true, Ordering::AcqRel) {
            // `notify_waiters` alone would lose the edge for a waiter that
            // has not parked yet; `wait` re-checks the flag after
            // registering, so the pair is race-free in both orders.
            self.state.waiters.notify_waiters();
        }
    }

    pub fn is_fired(&self) -> bool {
        self.state.fired.load(Ordering::Acquire)
    }

    /// Resolve when the signal fires — immediately if it already has.
    pub async fn wait(&self) {
        if self.is_fired() {
            return;
        }
        let waiters = self.state.waiters.notified();
        tokio::pin!(waiters);
        // Register before re-checking, so a `fire` between the check above
        // and the await below cannot fall through the gap.
        waiters.as_mut().enable();
        if self.is_fired() {
            return;
        }
        waiters.await;
    }
}

/// Serve `router` on `listener` until `shutdown` fires and the drain ends.
/// Returns only on a listener error; individual connections failing is
/// their own problem and is logged nowhere — a refused or reset peer is
/// expected traffic.
pub async fn serve(
    listener: TcpListener,
    router: axum::Router,
    limits: Limits,
    shutdown: Shutdown,
) -> std::io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    // One sender per live connection: the receiver ends when the last
    // connection task drops its clone, which is exactly the drain's
    // "everybody is gone" edge.
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                if limits.max_connections > 0
                    && active.load(Ordering::Relaxed) >= limits.max_connections
                {
                    // Over budget: drop immediately. The kernel closes the
                    // fd and the peer sees a bare disconnect — bounded
                    // failure beats an unbounded backlog.
                    drop(socket);
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let active = active.clone();
                let done_tx = done_tx.clone();
                let mut make_service = make_service.clone();
                let shutdown = shutdown.clone();
                let header_read_timeout = if limits.header_timeout_seconds == 0 {
                    None
                } else {
                    Some(Duration::from_secs(limits.header_timeout_seconds))
                };
                tokio::spawn(async move {
                    // Held for the task's whole life; dropped when it ends,
                    // whatever path it took out.
                    let _done = done_tx;
                    let service = match make_service.call(peer).await {
                        Ok(service) => TowerToHyperService::new(service),
                        Err(_) => {
                            active.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    // The header deadline is an HTTP/1 knob: it is reached
                    // through the auto builder's http1() part, which still
                    // serves the plain HTTP/1.1 + WebSocket upgrade surface
                    // the relay speaks.
                    let mut builder = AutoBuilder::new(TokioExecutor::new());
                    let mut http1 = builder.http1();
                    let connection = http1
                        .header_read_timeout(header_read_timeout)
                        // The deadline needs a clock the connection may
                        // create timers on; the tokio one is that runtime's.
                        .timer(TokioTimer::new())
                        .serve_connection_with_upgrades(TokioIo::new(socket), service);
                    let mut connection = std::pin::pin!(connection);
                    tokio::select! {
                        _ = connection.as_mut() => {}
                        _ = shutdown.wait() => {
                            // Finish what was already accepted, refuse
                            // anything further on this socket, then close:
                            // a keep-alive connection that stops here never
                            // sees a request it cannot be answered for.
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.as_mut().await;
                        }
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            _ = shutdown.wait() => break,
        }
    }
    // Stop accepting. Dropping the listener closes the socket, so a
    // connect from here on is refused at the kernel instead of being
    // queued behind a server that will never answer it.
    drop(listener);
    // The loop's own sender clone must go too: the drain ends when the
    // *last* sender drops, and this one outlives every connection task.
    drop(done_tx);
    let drained = async { while done_rx.recv().await.is_some() {} };
    if limits.drain_timeout_seconds == 0 {
        drained.await;
    } else {
        // Past the budget the remaining connections are abandoned: the
        // caller is exiting, and a request still running then was not
        // answered — the client retries against a fresh process.
        let _ =
            tokio::time::timeout(Duration::from_secs(limits.drain_timeout_seconds), drained).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::io;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn limits(drain_timeout_seconds: u64) -> Limits {
        Limits {
            max_connections: 0,
            header_timeout_seconds: 0,
            drain_timeout_seconds,
        }
    }

    /// One request over a real socket. Returns the raw response bytes.
    async fn request(address: SocketAddr, path: &str) -> io::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8_lossy(&response).into_owned())
    }

    /// A router whose one route takes `delay_ms`, so a request is provably
    /// still in flight when the signal fires.
    fn slow_router(delay_ms: u64) -> axum::Router {
        let delayed = move || async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            "ok"
        };
        axum::Router::new().route("/slow", get(delayed))
    }

    type Serving = tokio::task::JoinHandle<std::io::Result<()>>;

    async fn boot(delay_ms: u64, limits: Limits) -> (SocketAddr, Shutdown, Serving) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Shutdown::new();
        let serving = tokio::spawn(serve(
            listener,
            slow_router(delay_ms),
            limits,
            shutdown.clone(),
        ));
        (address, shutdown, serving)
    }

    #[tokio::test]
    async fn a_request_accepted_before_the_signal_still_gets_its_response() {
        let (address, shutdown, serving) = boot(300, limits(5)).await;
        let client = tokio::spawn(request(address, "/slow"));
        // The handler is mid-flight by now; the server is told to stop
        // while it still owes this client an answer.
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.fire();
        let response = client.await.unwrap().unwrap();
        assert!(
            response.contains("200 OK") && response.ends_with("ok"),
            "an accepted request must be finished, not dropped: {response:?}"
        );
        let stopped = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the serve loop ends once the drain is over");
        assert!(stopped.is_ok(), "the serve loop reports no listener error");
    }

    #[tokio::test]
    async fn a_connect_after_the_signal_is_refused() {
        let (address, shutdown, serving) = boot(0, limits(5)).await;
        shutdown.fire();
        let stopped = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("an idle drain ends at once");
        assert!(stopped.is_ok(), "the serve loop reports no listener error");
        assert!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "the listener must be closed, so a late connect fails instead of hanging"
        );
    }

    #[tokio::test]
    async fn a_signal_before_any_connection_returns_at_once() {
        let (_address, shutdown, serving) = boot(0, limits(5)).await;
        shutdown.fire();
        let stopped = tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("nothing to drain means nothing to wait for");
        assert!(stopped.is_ok(), "the serve loop reports no listener error");
    }

    #[tokio::test]
    async fn the_drain_is_bounded_by_the_shutdown_budget() {
        // The handler outlives the drain budget, so the loop must give up
        // on it: bounded exit, not a process that hangs on a stuck client.
        let (address, shutdown, serving) = boot(30_000, limits(1)).await;
        let client = tokio::spawn(request(address, "/slow"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        shutdown.fire();
        let stopped = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the drain budget must end the wait");
        assert!(stopped.is_ok(), "the serve loop reports no listener error");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(4),
            "the drain must last about shutdownTimeoutSeconds, took {elapsed:?}"
        );
        client.abort();
    }
}
