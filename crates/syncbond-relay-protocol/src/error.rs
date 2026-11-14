//! Stable error codes, HTTP status mapping and the failure body shape.
//! Frozen in docs/design/relay-protocol.md §6: clients switch on `code`,
//! never on `message`.

use serde::{Deserialize, Serialize};

/// Every failure the relay can report. The string form is the wire value
/// and is frozen: adding a variant is a contract change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayErrorCode {
    VersionUnsupported,
    BadRequest,
    Unauthorized,
    Forbidden,
    ChannelNotFound,
    PayloadTooLarge,
    BatchTooLarge,
    IdempotencyConflict,
    CursorInvalid,
    PageTooLarge,
    ItemTooLarge,
    QuotaExceeded,
    RateLimited,
    RoomNotFound,
    RoomFull,
    RoomExpired,
    Internal,
}

impl RelayErrorCode {
    /// The exact wire string ("version_unsupported", …). Deriving it from
    /// the serde rename keeps code and wire value from drifting; the
    /// `contract_fixtures` test pins every string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VersionUnsupported => "version_unsupported",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::ChannelNotFound => "channel_not_found",
            Self::PayloadTooLarge => "payload_too_large",
            Self::BatchTooLarge => "batch_too_large",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::CursorInvalid => "cursor_invalid",
            Self::PageTooLarge => "page_too_large",
            Self::ItemTooLarge => "item_too_large",
            Self::QuotaExceeded => "quota_exceeded",
            Self::RateLimited => "rate_limited",
            Self::RoomNotFound => "room_not_found",
            Self::RoomFull => "room_full",
            Self::RoomExpired => "room_expired",
            Self::Internal => "internal",
        }
    }

    /// The HTTP status this code is served with.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::VersionUnsupported
            | Self::BadRequest
            | Self::CursorInvalid
            | Self::PageTooLarge
            | Self::ItemTooLarge => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::ChannelNotFound | Self::RoomNotFound => 404,
            Self::IdempotencyConflict | Self::RoomFull => 409,
            Self::PayloadTooLarge | Self::BatchTooLarge => 413,
            Self::RoomExpired => 410,
            Self::Internal => 500,
            Self::RateLimited => 429,
            Self::QuotaExceeded => 507,
        }
    }

    /// Whether retrying the same request can succeed later.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::BatchTooLarge
                | Self::QuotaExceeded
                | Self::RateLimited
                | Self::RoomFull
                | Self::Internal
        )
    }
}

/// A typed relay failure: code plus a human-readable message (never relied
/// upon by clients) and the retryability of its code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", code.as_str())]
pub struct RelayError {
    pub code: RelayErrorCode,
    pub message: String,
}

impl RelayError {
    pub fn new(code: RelayErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn is_retryable(&self) -> bool {
        self.code.is_retryable()
    }
}

/// The failure body every error response uses:
/// `{"protocolVersion":1,"requestId":…|null,"error":{"code":…,"message":…,"retryable":…}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorBody {
    pub protocol_version: u16,
    /// `None` serializes as `null`: the request was not parseable enough to
    /// echo an id.
    pub request_id: Option<String>,
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorDetail {
    pub code: RelayErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl ErrorBody {
    pub fn new(protocol_version: u16, request_id: Option<&str>, error: &RelayError) -> Self {
        Self {
            protocol_version,
            request_id: request_id.map(str::to_string),
            error: ErrorDetail {
                code: error.code,
                message: error.message.clone(),
                retryable: error.is_retryable(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping is total and frozen: every variant has a status and a
    /// retryability, and the wire strings match the contract table.
    #[test]
    fn every_code_has_a_status_and_a_wire_string() {
        let codes = [
            (
                RelayErrorCode::VersionUnsupported,
                400,
                false,
                "version_unsupported",
            ),
            (RelayErrorCode::BadRequest, 400, false, "bad_request"),
            (RelayErrorCode::Unauthorized, 401, false, "unauthorized"),
            (RelayErrorCode::Forbidden, 403, false, "forbidden"),
            (
                RelayErrorCode::ChannelNotFound,
                404,
                false,
                "channel_not_found",
            ),
            (
                RelayErrorCode::PayloadTooLarge,
                413,
                false,
                "payload_too_large",
            ),
            (RelayErrorCode::BatchTooLarge, 413, true, "batch_too_large"),
            (
                RelayErrorCode::IdempotencyConflict,
                409,
                false,
                "idempotency_conflict",
            ),
            (RelayErrorCode::CursorInvalid, 400, false, "cursor_invalid"),
            (RelayErrorCode::PageTooLarge, 400, false, "page_too_large"),
            (RelayErrorCode::ItemTooLarge, 400, false, "item_too_large"),
            (RelayErrorCode::QuotaExceeded, 507, true, "quota_exceeded"),
            (RelayErrorCode::RateLimited, 429, true, "rate_limited"),
            (RelayErrorCode::RoomNotFound, 404, false, "room_not_found"),
            (RelayErrorCode::RoomFull, 409, true, "room_full"),
            (RelayErrorCode::RoomExpired, 410, false, "room_expired"),
            (RelayErrorCode::Internal, 500, true, "internal"),
        ];
        for (code, status, retryable, wire) in codes {
            assert_eq!(code.http_status(), status, "{wire}");
            assert_eq!(code.is_retryable(), retryable, "{wire}");
            assert_eq!(code.as_str(), wire);
            // The serde rename must agree with the hand-written string.
            let serialized = serde_json::to_value(code).unwrap();
            assert_eq!(serialized, wire, "{wire}");
            let round_trip: RelayErrorCode = serde_json::from_value(serialized).unwrap();
            assert_eq!(round_trip, code, "{wire}");
        }
    }

    #[test]
    fn error_body_serializes_null_request_id() {
        let error = RelayError::new(
            RelayErrorCode::CursorInvalid,
            "cursor 99999 is ahead of channel head 42",
        );
        let body = ErrorBody::new(1, None, &error);
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["requestId"], serde_json::Value::Null);
        assert_eq!(value["error"]["code"], "cursor_invalid");
        assert_eq!(value["error"]["retryable"], false);
        let round_trip: ErrorBody = serde_json::from_value(value).unwrap();
        assert_eq!(round_trip, body);
    }
}
