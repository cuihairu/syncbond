//! Shared plumbing for the syncbond command-line demos: a minimal
//! length-prefixed TCP transport, a file-backed [`SyncStorage`], and the
//! persisted device state used by the relay demo.
//!
//! These exist so the demos can run as two real processes; the core itself
//! stays transport-agnostic.

pub mod persist;
pub mod tcp_transport;

pub use persist::{load_device, save_device, FileStorage, PersistedDevice};
pub use tcp_transport::TcpTransport;

/// Parse `--flag value` style arguments. Unknown flags and missing values
/// are hard errors: the demos are meant to be copy-pasted from the README.
pub fn require_flag(args: &[String], flag: &str) -> Result<String, String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            return args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"));
        }
        index += 1;
    }
    Err(format!("missing required flag {flag}"))
}

pub fn optional_flag(args: &[String], flag: &str) -> Option<String> {
    require_flag(args, flag).ok()
}

/// Read one line from stdin after printing a prompt.
pub fn prompt(prompt_text: &str) -> std::io::Result<String> {
    use std::io::Write;
    print!("{prompt_text}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
