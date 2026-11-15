//! The one REST hop this transport needs: creating the pairing room
//! (§3 `POST /v1/pairing/rooms`). A full HTTP client is out of scope —
//! this speaks exactly one request shape against the relay contract:
//! HTTP/1.1, one JSON body, `Connection: close`, status line + body in.

use std::sync::Arc;
use std::time::Duration;

use syncbond_relay_protocol::dto::{CreateRoomRequest, RoomCreated};
use syncbond_relay_protocol::error::ErrorBody;
use syncbond_relay_protocol::RELAY_PROTOCOL_VERSION;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::error::WsPairingError;
use crate::options::RelayLocation;
use crate::tls;

/// Create a room. Returns the invite facts the relay showed once: room id
/// and capability. A non-201 is mapped to the frozen error code the body
/// carries (§6), so callers switch on `code`, never on prose.
pub(crate) async fn create_room(
    location: &RelayLocation,
    tls_policy: &crate::options::TlsPolicy,
    timeout: Duration,
) -> Result<RoomCreated, WsPairingError> {
    let request = serde_json::to_vec(&CreateRoomRequest {
        protocol_version: RELAY_PROTOCOL_VERSION,
        // The relay echoes it; the transport never correlates requests by
        // hand, so a stable literal is honest here.
        request_id: "sb-ws-room-create".to_owned(),
    })
    .expect("a closed-shape DTO always serializes");

    let body = request_impl(
        location,
        tls_policy,
        "POST",
        "/v1/pairing/rooms",
        Some(&request),
        timeout,
    )
    .await?;

    let created: RoomCreated = parse_json_body(location, &body.1, body.0)?;
    Ok(created)
}

/// (status, body) for one request. The relay honors `Connection: close`,
/// so the response ends at EOF; a `Content-Length` is still honored when
/// the body is complete early.
async fn request_impl(
    location: &RelayLocation,
    tls_policy: &crate::options::TlsPolicy,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), WsPairingError> {
    let connect = tokio::time::timeout(timeout, TcpStream::connect(&location.authority))
        .await
        .map_err(|_| WsPairingError::Timeout)?
        .map_err(|error| tls::classify_io(&error))?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\n",
        location.authority
    );
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    if location.secure {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(tls_policy)?));
        // SNI and the Host header both use the URL's host part; for an IP
        // literal `ServerName` accepts the address form.
        let name = rustls::pki_types::ServerName::try_from(location.host.clone())
            .map_err(|error| WsPairingError::Tls(format!("server name: {error}")))?;
        let tls_stream = tokio::time::timeout(timeout, connector.connect(name, connect))
            .await
            .map_err(|_| WsPairingError::Timeout)?
            .map_err(|error| tls::classify_io(&error))?;
        let raw = exchange(tls_stream, request, body).await?;
        parse_response(raw)
    } else {
        let raw = exchange(connect, request, body).await?;
        parse_response(raw)
    }
}

/// Write the request and read the response to EOF (`Connection: close`).
/// A `Content-Length` ends the read early when the body is complete.
async fn exchange<S>(
    mut stream: S,
    request: String,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, WsPairingError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| WsPairingError::Io(error.to_string()))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .map_err(|error| WsPairingError::Io(error.to_string()))?;
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
                if response.len() > 1024 * 1024 {
                    return Err(WsPairingError::Protocol(
                        "relay response exceeded 1 MiB".into(),
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

fn parse_response(raw: Vec<u8>) -> Result<(u16, Vec<u8>), WsPairingError> {
    let header_end = find_header_end(&raw)
        .ok_or_else(|| WsPairingError::Protocol("response has no header end".into()))?;
    let status_line =
        std::str::from_utf8(&raw[..raw.windows(2).position(|w| w == b"\r\n").unwrap_or(0)])
            .map_err(|_| WsPairingError::Protocol("status line is not utf-8".into()))?
            .to_owned();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            WsPairingError::Protocol(format!("unreadable status line: {status_line:?}"))
        })?;
    Ok((status, raw[header_end..].to_vec()))
}

fn parse_json_body(
    location: &RelayLocation,
    body: &[u8],
    status: u16,
) -> Result<RoomCreated, WsPairingError> {
    if status == 201 {
        return serde_json::from_slice(body)
            .map_err(|error| WsPairingError::Protocol(format!("room creation response: {error}")));
    }
    // The frozen failure shape (§6): {"error":{"code","message"}}.
    let relayed: ErrorBody = serde_json::from_slice(body).map_err(|error| {
        WsPairingError::Protocol(format!(
            "{status} from {} with unreadable body: {error}",
            location.authority
        ))
    })?;
    Err(WsPairingError::Relay {
        code: relayed.error.code,
        status: relayed.error.code.http_status(),
        message: relayed.error.message,
    })
}
