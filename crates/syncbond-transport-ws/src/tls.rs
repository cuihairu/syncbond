//! TLS client configuration per [`TlsPolicy`] (todo.md DSR-27). The
//! default is validation — webpki roots, or exactly one pinned CA — and
//! `AcceptInvalid` is a deliberate, separate construction so a caller
//! cannot end up with it by accident. The `ring` provider is compiled in
//! (see Cargo.toml); no process-level default is installed, so embedding
//! hosts keep whatever provider they prefer.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::error::WsPairingError;
use crate::options::TlsPolicy;

/// The client config for a hop, per policy.
pub(crate) fn client_config(policy: &TlsPolicy) -> Result<ClientConfig, WsPairingError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| WsPairingError::Tls(error.to_string()))?;
    match policy {
        TlsPolicy::Validate | TlsPolicy::ValidateCa(_) => {
            // Validate: the webpki roots, the public CA set.
            // ValidateCa: exactly one pinned CA (DER) replaces the public
            // roots — the self-hosted deployment that refuses to trust
            // anything it did not pin.
            let mut roots = rustls::RootCertStore::empty();
            match policy {
                TlsPolicy::Validate => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                TlsPolicy::ValidateCa(der) => roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|error| WsPairingError::Tls(format!("pinned CA rejected: {error}")))?,
                TlsPolicy::AcceptInvalid => unreachable!("matched above"),
            }
            Ok(builder.with_root_certificates(roots).with_no_client_auth())
        }
        TlsPolicy::AcceptInvalid => Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer {
                schemes: provider
                    .signature_verification_algorithms
                    .supported_schemes(),
            }))
            .with_no_client_auth()),
    }
}

/// Label an opaque I/O error as TLS when rustls produced it, so the
/// [`WsPairingError::Tls`] variant is exactly the validation outcome and
/// nothing else.
pub(crate) fn classify_io(error: &std::io::Error) -> WsPairingError {
    let message = error.to_string();
    let is_tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
        .is_some();
    if is_tls {
        WsPairingError::Tls(message)
    } else {
        WsPairingError::Io(message)
    }
}

/// The `AcceptInvalid` verifier: chain and name checks skipped, signature
/// machinery still driven by the provider's advertised schemes.
#[derive(Debug)]
struct AcceptAnyServer {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
