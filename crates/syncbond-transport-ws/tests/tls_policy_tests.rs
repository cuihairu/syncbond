//! The TLS validation policy against a real certificate: a private CA
//! certifies a server; the transport must reject it under the public
//! roots ([`TlsPolicy::Validate`]), accept it under a pinned CA
//! ([`TlsPolicy::ValidateCa`]), and accept it only when explicitly told
//! to ([`TlsPolicy::AcceptInvalid`]). The test listener completes the
//! handshake and answers with a canned 500, so "TLS passed" is visible
//! as an HTTP-stage error — never a TLS one.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use syncbond_transport_ws::{create_invite, TlsPolicy, WsPairingOptions};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A CA and a server certificate it signed, for 127.0.0.1.
struct TestChain {
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    ca_cert: CertificateDer<'static>,
}

fn generate_chain() -> TestChain {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("a CA key pair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("a self-signed CA");

    let server_key = KeyPair::generate().expect("a server key pair");
    let server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("server params");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("a CA-signed server certificate");

    TestChain {
        server_cert: server.der().to_owned(),
        server_key: PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        ca_cert: ca.der().to_owned(),
    }
}

/// Serve TLS on loopback: accept, handshake, answer one canned 500,
/// close. Repeats until the task is aborted — the transport may open more
/// than one connection while mapping a failure.
async fn serve_tls(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> String {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("a consistent cert and key");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let address = listener.local_addr().expect("a bound address").to_string();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The handshake decides this test; what follows is just a
                // readable end so the client's HTTP stage completes.
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let _ = stream
                        .write_all(b"HTTP/1.1 500 policy probe\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = stream.flush().await;
                    let mut sink = [0u8; 256];
                    let _ = stream.read(&mut sink).await;
                }
            });
        }
    });
    address
}

#[tokio::test]
async fn the_public_roots_reject_a_private_ca() {
    let chain = generate_chain();
    let address = serve_tls(chain.server_cert, chain.server_key).await;

    let options = WsPairingOptions {
        relay_url: format!("https://{address}"),
        tls: TlsPolicy::Validate,
        connect_timeout_ms: 5_000,
        ..Default::default()
    };
    let error = create_invite(&options)
        .await
        .expect_err("a private CA is not a public one");
    assert!(
        matches!(error, syncbond_transport_ws::WsPairingError::Tls(_)),
        "validation failure must be the Tls variant: {error}"
    );
}

#[tokio::test]
async fn a_pinned_ca_validates_the_same_chain() {
    let chain = generate_chain();
    let address = serve_tls(chain.server_cert, chain.server_key).await;

    let options = WsPairingOptions {
        relay_url: format!("https://{address}"),
        tls: TlsPolicy::ValidateCa(chain.ca_cert.as_ref().to_vec()),
        connect_timeout_ms: 5_000,
        ..Default::default()
    };
    // TLS passes; the canned 500 is an HTTP-stage failure (not TLS) —
    // proof the validation path let a legitimately pinned chain through.
    let error = create_invite(&options)
        .await
        .expect_err("the probe server answers 500");
    match error {
        syncbond_transport_ws::WsPairingError::Protocol(message) => {
            assert!(
                message.contains("500"),
                "the failure is the probe server's HTTP answer: {message}"
            );
        }
        other => panic!("TLS must validate under the pinned CA; got: {other}"),
    }
}

#[tokio::test]
async fn accept_invalid_is_explicit_and_gets_through_tls() {
    let chain = generate_chain();
    let address = serve_tls(chain.server_cert, chain.server_key).await;

    let options = WsPairingOptions {
        relay_url: format!("https://{address}"),
        tls: TlsPolicy::AcceptInvalid,
        connect_timeout_ms: 5_000,
        ..Default::default()
    };
    let error = create_invite(&options)
        .await
        .expect_err("the probe server answers 500");
    assert!(
        !matches!(error, syncbond_transport_ws::WsPairingError::Tls(_)),
        "accept-invalid never reports a TLS validation failure: {error}"
    );
}
