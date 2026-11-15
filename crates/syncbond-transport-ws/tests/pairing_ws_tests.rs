//! End-to-end pairing through an in-process relay (todo.md DSR-27): both
//! entries, the timeouts, cancellation, and the wrong-code path — the
//! same relay surface the server's own suite exercises, driven here by
//! this transport's real client machinery.

use std::sync::Arc;
use std::time::{Duration, Instant};

use syncbond_core::identity::DeviceIdentity;
use syncbond_core::pairing::PairingSession;
use syncbond_server::test_support::boot_relay;
use syncbond_transport_ws::{
    create_invite, pair_as_host, pair_as_joiner, WsPairingError, WsPairingOptions,
};

fn options(relay_url: String) -> WsPairingOptions {
    WsPairingOptions {
        relay_url,
        ..Default::default()
    }
}

/// A session holds live keys and is deliberately not `Debug`, so a failing
/// expectation is unwrapped by hand.
fn expect_error(result: Result<PairingSession, WsPairingError>, what: &str) -> WsPairingError {
    match result {
        Ok(_) => panic!("{what}: a session appeared where the pairing must fail"),
        Err(error) => error,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_devices_pair_and_exchange_application_frames() {
    let relay = boot_relay();
    let options = options(format!("http://{}", relay.address));

    let invite = create_invite(&options).await.expect("room created");
    let host_identity = DeviceIdentity::generate();
    let joiner_identity = DeviceIdentity::generate();

    // The code travels the out-of-band channel (the on_code callback);
    // the invite facts travel with it.
    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let joiner = {
        let options = options.clone();
        let invite = invite.clone();
        let identity = joiner_identity.clone();
        tokio::spawn(async move {
            let code = code_rx.await.expect("the host shows a code");
            pair_as_joiner(&options, &identity, &code, &invite).await
        })
    };

    let host_identity_for_assert = host_identity.clone();
    let mut code_tx = Some(code_tx);
    let (host_session, joiner_session) = tokio::join!(
        async {
            let identity = host_identity_for_assert;
            pair_as_host(&options, &identity, &invite, |code| {
                if let Some(code_tx) = code_tx.take() {
                    let _ = code_tx.send(code.to_owned());
                }
            })
            .await
        },
        async { joiner.await.expect("the joiner task never panics") },
    );
    let host_session = host_session.expect("host pairs");
    let joiner_session = joiner_session.expect("joiner pairs");

    // Each end learned exactly the other's identity, and the session is
    // the same conversation.
    assert_eq!(
        host_session.peer_identity.device_id,
        joiner_identity.device_id
    );
    assert_eq!(
        joiner_session.peer_identity.device_id,
        host_identity.device_id
    );
    assert_eq!(host_session.group_id, joiner_session.group_id);
    assert!(!host_session.group_id.is_empty());

    // Application frames cross the bounded bridge in both directions.
    // The session's methods are blocking: they run off the runtime.
    let host_session = Arc::new(host_session);
    let joiner_session = Arc::new(joiner_session);
    tokio::task::spawn_blocking({
        let session = host_session.clone();
        move || session.seal_and_send(b"ping from the host")
    })
    .await
    .expect("blocking task runs")
    .expect("host send");
    let received = tokio::task::spawn_blocking({
        let session = joiner_session.clone();
        move || session.recv_and_open()
    })
    .await
    .expect("blocking task runs")
    .expect("joiner recv");
    assert_eq!(received, b"ping from the host".to_vec());

    tokio::task::spawn_blocking({
        let session = joiner_session.clone();
        move || session.seal_and_send(b"pong from the joiner")
    })
    .await
    .expect("blocking task runs")
    .expect("joiner send");
    let received = tokio::task::spawn_blocking({
        let session = host_session.clone();
        move || session.recv_and_open()
    })
    .await
    .expect("blocking task runs")
    .expect("host recv");
    assert_eq!(received, b"pong from the joiner".to_vec());
}

#[tokio::test]
async fn a_host_alone_times_out_within_its_budget() {
    let relay = boot_relay();
    let mut options = options(format!("http://{}", relay.address));
    options.pairing_timeout_ms = 800;
    let invite = create_invite(&options).await.expect("room created");
    let identity = DeviceIdentity::generate();

    let started = Instant::now();
    let error = expect_error(
        pair_as_host(&options, &identity, &invite, |_| {
            // The code is shown; nobody ever types it.
        })
        .await,
        "no peer ever joins",
    );
    assert!(matches!(error, WsPairingError::Timeout));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the budget is 800 ms, not minutes: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_joiner_alone_times_out_within_its_budget() {
    let relay = boot_relay();
    let mut options = options(format!("http://{}", relay.address));
    options.pairing_timeout_ms = 800;
    let invite = create_invite(&options).await.expect("room created");
    let identity = DeviceIdentity::generate();

    // A well-formed code that no host ever echoes: the exchange itself
    // must still end on the budget, not hang on the wire.
    let started = Instant::now();
    let error = expect_error(
        pair_as_joiner(&options, &identity, "K7Q2M4", &invite).await,
        "no peer ever joins",
    );
    assert!(matches!(error, WsPairingError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_departure_ends_the_waiting_host_promptly() {
    let relay = boot_relay();
    let mut options = options(format!("http://{}", relay.address));
    // Far beyond the test's patience: if the host ends, it ended because
    // the relay told it the peer was gone, not because of the budget.
    options.pairing_timeout_ms = 30_000;
    let invite = create_invite(&options).await.expect("room created");

    let host = {
        let options = options.clone();
        let invite = invite.clone();
        tokio::spawn(async move {
            let identity = DeviceIdentity::generate();
            pair_as_host(&options, &identity, &invite, |_| {}).await
        })
    };

    // A participant that joins and then vanishes mid-handshake: no close
    // handshake, just a dropped socket. Whichever SPAKE2 role the host
    // was handed, it can never complete against this peer — so a prompt
    // end can only come from the departure propagating through the relay.
    let raw_join = {
        let address = relay.address.clone();
        let room = invite.room_id.clone();
        let capability = invite.capability.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
            use tokio_tungstenite::tungstenite::http::HeaderValue;
            let url = format!("ws://{address}/v1/pairing/{room}");
            let mut request = url
                .as_str()
                .into_client_request()
                .expect("a well-formed join request");
            request.headers_mut().insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {capability}")).expect("a header value"),
            );
            let (socket, _) = tokio::time::timeout(
                Duration::from_secs(5),
                tokio_tungstenite::connect_async(request),
            )
            .await
            .expect("the raw join completes within its budget")
            .expect("the room admits the second participant");
            drop(socket);
        })
    };

    let started = Instant::now();
    let error = expect_error(
        host.await.expect("the host task never panics"),
        "the peer's departure must end the pairing",
    );
    let _ = raw_join.await;
    assert!(
        !matches!(error, WsPairingError::Timeout),
        "the host must end on the peer's departure, not its budget: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the goodbye must arrive promptly: {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_code_fails_both_ends_without_hanging() {
    let relay = boot_relay();
    let mut options = options(format!("http://{}", relay.address));
    options.pairing_timeout_ms = 30_000;
    let invite = create_invite(&options).await.expect("room created");

    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let joiner = {
        let options = options.clone();
        let invite = invite.clone();
        tokio::spawn(async move {
            let wrong_code = code_rx.await.expect("the host shows a code");
            let identity = DeviceIdentity::generate();
            pair_as_joiner(&options, &identity, &wrong_code, &invite).await
        })
    };

    let host_identity = DeviceIdentity::generate();
    let mut code_tx = Some(code_tx);
    let started = Instant::now();
    let (host, joiner) = tokio::join!(
        async {
            pair_as_host(&options, &host_identity, &invite, |code| {
                // Hand the joiner a well-formed but different code: valid
                // SPAKE2 inputs, mismatched secrets.
                let mut wrong = code.to_owned().into_bytes();
                wrong[0] = if wrong[0] == b'A' { b'B' } else { b'A' };
                if let Some(code_tx) = code_tx.take() {
                    let _ = code_tx.send(String::from_utf8(wrong).unwrap());
                }
            })
            .await
        },
        async { joiner.await.expect("the joiner task never panics") },
    );
    let host_error = expect_error(host, "a mismatched code cannot pair");
    let joiner_error = expect_error(joiner, "a mismatched code cannot pair");
    assert!(
        matches!(host_error, WsPairingError::Core(_)),
        "the host's verdict is the core's typed failure: {host_error}"
    );
    assert!(
        matches!(joiner_error, WsPairingError::Core(_)),
        "the joiner's verdict is the core's typed failure: {joiner_error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "both ends end by verdict, not by budget: {:?}",
        started.elapsed()
    );
}
