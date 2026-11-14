//! Server configuration: a single JSON file, closed shape, validated at
//! startup. Invalid configuration exits non-zero before anything is
//! created (DSR-11). Frozen contract values (room TTL, frame caps, rate
//! limits) are NOT configurable; see docs/design/relay-protocol.md §9.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// Listen address. The default binds loopback only: public exposure
    /// requires a TLS reverse proxy in front.
    pub listen: SocketAddr,
    /// Data directory holding the SQLite database and the admin bootstrap
    /// credential file.
    pub data_dir: PathBuf,
    /// Per-channel byte budget; `0` disables the limit.
    #[serde(default = "default_channel_quota")]
    pub channel_quota_bytes: u64,
    /// Whole-database byte budget; `0` disables the limit. Reads are never
    /// blocked by a quota.
    #[serde(default = "default_disk_quota")]
    pub disk_quota_bytes: u64,
    /// Origins allowed to open browser WebSocket connections. Empty means
    /// no browser origins are allowed (non-browser clients are unaffected).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_channel_quota() -> u64 {
    1024 * 1024 * 1024
}

fn default_disk_quota() -> u64 {
    8 * 1024 * 1024 * 1024
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            data_dir: PathBuf::from("./data"),
            channel_quota_bytes: default_channel_quota(),
            disk_quota_bytes: default_disk_quota(),
            allowed_origins: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("config file {path} is not valid JSON: {source}")]
    Malformed {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    /// Load and validate. Unknown fields and a malformed listen address
    /// fail loudly here, before the server touches any state.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = serde_json::from_str(&raw).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("dataDir must not be empty".into()));
        }
        if self.data_dir == Path::new("/") {
            return Err(ConfigError::Invalid(
                "dataDir must not be the filesystem root".into(),
            ));
        }
        // Quotas may be zero (disabled) but must not be absurd: a value
        // below one envelope (4 MiB) other than 0 can never admit a write.
        let min_quota = syncbond_relay_protocol::limits::MAX_ENVELOPE_BYTES as u64;
        for (name, quota) in [
            ("channelQuotaBytes", self.channel_quota_bytes),
            ("diskQuotaBytes", self.disk_quota_bytes),
        ] {
            if quota != 0 && quota < min_quota {
                return Err(ConfigError::Invalid(format!(
                    "{name} must be 0 (disabled) or at least {min_quota} (one envelope)"
                )));
            }
        }
        for origin in &self.allowed_origins {
            if origin.is_empty() || origin.contains(char::is_whitespace) {
                return Err(ConfigError::Invalid(format!(
                    "allowedOrigins entries must be non-empty and contain no whitespace, got {origin:?}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bind_loopback_and_use_the_frozen_quotas() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(
            config.listen,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            "the default must not expose the server publicly"
        );
        assert_eq!(config.channel_quota_bytes, 1024 * 1024 * 1024);
        assert_eq!(config.disk_quota_bytes, 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let raw = r#"{"listen":"127.0.0.1:8080","dataDir":"./data","roomTtlMs":5000}"#;
        let config: Result<Config, _> = serde_json::from_str(raw);
        assert!(
            config.is_err(),
            "frozen contract values must not be configurable"
        );
    }

    #[test]
    fn validation_rejects_absurd_and_dangerous_values() {
        let config = Config {
            data_dir: PathBuf::new(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        let config = Config {
            data_dir: PathBuf::from("/"),
            ..Config::default()
        };
        assert!(
            config.validate().is_err(),
            "the root must not be a data dir"
        );

        let config = Config {
            channel_quota_bytes: 1,
            ..Config::default()
        };
        assert!(
            config.validate().is_err(),
            "a quota below one envelope can never admit a write"
        );
        let config = Config {
            channel_quota_bytes: 0,
            ..Config::default()
        };
        config
            .validate()
            .expect("0 disables the quota and is accepted");

        let config = Config {
            allowed_origins: vec!["https://ok.example".into(), "bad origin".into()],
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_file_round_trips() {
        let config = Config {
            listen: SocketAddr::from(([10, 0, 0, 5], 9000)),
            ..Config::default()
        };
        let raw = serde_json::to_string_pretty(&config).unwrap();
        let parsed: Config = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, config);
    }
}
