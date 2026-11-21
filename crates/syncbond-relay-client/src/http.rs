//! One-request HTTP/1.1 over a raw socket, the same shape the pairing
//! transport speaks: `Connection: close`, one JSON body in, status line
//! and body out. Bearer auth when a token is given. A full HTTP client
//! is out of scope — this speaks exactly the relay's channel contract.

use std::sync::Arc;
use std::time::Duration;

use syncbond_relay_protocol::error::ErrorBody;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::client::RelayLocation;
use crate::error::RelayClientError;
use crate::tls::{self, TlsPolicy};

/// Pull pages can carry megabytes of ciphertext; the pairing hop's 1 MiB
/// cap does not fit this surface. The relay's own pull byte budget
/// stays under this regardless.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// (status, body) for one request. The relay honors `Connection: close`,
/// so the response ends at EOF; a `Content-Length` is still honored when
/// the body is complete early.
pub(crate) async fn request(
    location: &RelayLocation,
    policy: &TlsPolicy,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), RelayClientError> {
    let connect = tokio::time::timeout(timeout, TcpStream::connect(location.authority()))
        .await
        .map_err(|_| RelayClientError::Timeout)?
        .map_err(|error| tls::classify_io(&error))?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nConnection: close\r\n",
        host = location.authority(),
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    if location.secure {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(policy)?));
        // SNI and the Host header both use the URL's host part; for an IP
        // literal `ServerName` accepts the address form.
        let name = rustls::pki_types::ServerName::try_from(location.host.clone())
            .map_err(|error| RelayClientError::Tls(format!("server name: {error}")))?;
        let tls_stream = tokio::time::timeout(timeout, connector.connect(name, connect))
            .await
            .map_err(|_| RelayClientError::Timeout)?
            .map_err(|error| tls::classify_io(&error))?;
        let raw = exchange(tls_stream, request, body).await?;
        parse_response(raw)
    } else {
        let raw = exchange(connect, request, body).await?;
        parse_response(raw)
    }
}

/// Parse the body as `T` when the status is the expected one; otherwise
/// the relay's frozen failure shape is the error.
pub(crate) fn expect_json<T: serde::de::DeserializeOwned>(
    location: &RelayLocation,
    response: (u16, Vec<u8>),
    want: u16,
    what: &str,
) -> Result<T, RelayClientError> {
    let (status, body) = response;
    if status == want {
        return serde_json::from_slice(&body)
            .map_err(|error| RelayClientError::Protocol(format!("{what} response: {error}")));
    }
    let relayed: ErrorBody = serde_json::from_slice(&body).map_err(|error| {
        RelayClientError::Protocol(format!(
            "{status} from {} with an unreadable body: {error}",
            location.authority()
        ))
    })?;
    Err(RelayClientError::Relay {
        code: relayed.error.code,
        status,
        message: relayed.error.message,
    })
}

/// Write the request and read the response to EOF (`Connection: close`).
/// A `Content-Length` ends the read early when the body is complete.
async fn exchange<S>(
    mut stream: S,
    request: String,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, RelayClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| RelayClientError::Io(error.to_string()))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .map_err(|error| RelayClientError::Io(error.to_string()))?;
    }

    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await;
        match read {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                // A complete body per Content-Length ends the read even
                // before EOF.
                if let Some(need) = content_length_target(&response) {
                    if response.len() >= need {
                        break;
                    }
                }
                if response.len() > MAX_RESPONSE_BYTES {
                    return Err(RelayClientError::Protocol(
                        "relay response exceeded 16 MiB".into(),
                    ));
                }
            }
            Err(error) => return Err(tls::classify_io(&error)),
        }
    }
    Ok(response)
}

fn content_length_target(response: &[u8]) -> Option<usize> {
    let header_end = find_header_end(response)?;
    let text = std::str::from_utf8(&response[..header_end]).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn parse_response(raw: Vec<u8>) -> Result<(u16, Vec<u8>), RelayClientError> {
    let header_end = find_header_end(&raw)
        .ok_or_else(|| RelayClientError::Protocol("response has no header end".into()))?;
    let status_line =
        std::str::from_utf8(&raw[..raw.windows(2).position(|w| w == b"\r\n").unwrap_or(0)])
            .map_err(|_| RelayClientError::Protocol("status line is not utf-8".into()))?
            .to_owned();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            RelayClientError::Protocol(format!("unreadable status line: {status_line:?}"))
        })?;
    Ok((status, raw[header_end..].to_vec()))
}
