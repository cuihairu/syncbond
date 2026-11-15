//! The serve loop (todo.md DSR-23, default-server.md §4): accept with a
//! connection budget and a header-read timeout, then hand each connection
//! to hyper-util with upgrades so the WebSocket routes keep working.
//!
//! `axum::serve` has no knobs for either, and both are bounded-resource
//! requirements, not conveniences: an accept loop that queues every
//! connect delays the overload instead of refusing it, and a client that
//! trickles request headers forever pins a worker. Both values come from
//! the deployer's config (`maxConnections`, `headerTimeoutSeconds`;
//! `0` disables each). Serving must use
//! `into_make_service_with_connect_info` — the pairing-room creation
//! route rate-limits per peer address (relay-protocol.md §9).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower_service::Service as _;

/// What the accept loop needs beyond the router: the two deployment
/// budgets. `0` in either field disables that limit.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_connections: usize,
    pub header_timeout_seconds: u64,
}

/// Serve `router` on `listener` until the process stops. Returns only on
/// a listener error; individual connections failing is their own problem
/// and is logged nowhere — a refused or reset peer is expected traffic.
pub async fn serve(
    listener: TcpListener,
    router: axum::Router,
    limits: Limits,
) -> std::io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    loop {
        let (socket, peer) = listener.accept().await?;
        if limits.max_connections > 0 && active.load(Ordering::Relaxed) >= limits.max_connections {
            // Over budget: drop immediately. The kernel closes the fd and
            // the peer sees a bare disconnect — bounded failure beats an
            // unbounded backlog.
            drop(socket);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let active = active.clone();
        let mut make_service = make_service.clone();
        let header_read_timeout = if limits.header_timeout_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(limits.header_timeout_seconds))
        };
        tokio::spawn(async move {
            let service = match make_service.call(peer).await {
                Ok(service) => TowerToHyperService::new(service),
                Err(_) => return,
            };
            // The header deadline is an HTTP/1 knob: it is reached through
            // the auto builder's http1() part, which still serves the
            // plain HTTP/1.1 + WebSocket upgrade surface the relay speaks.
            let mut builder = AutoBuilder::new(TokioExecutor::new());
            let mut http1 = builder.http1();
            let connection = http1
                .header_read_timeout(header_read_timeout)
                // The deadline needs a clock the connection may create
                // timers on; the tokio one is that runtime's.
                .timer(TokioTimer::new())
                .serve_connection_with_upgrades(TokioIo::new(socket), service);
            let _ = connection.await;
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
