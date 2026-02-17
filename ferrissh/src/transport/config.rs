//! SSH connection configuration.

use std::path::PathBuf;
use std::time::Duration;

/// Host key verification mode, analogous to OpenSSH's `StrictHostKeyChecking`.
#[derive(Debug, Clone, Default)]
pub enum HostKeyVerification {
    /// Reject unknown and changed keys. Connection fails if the host
    /// is not already in known_hosts.
    Strict,

    /// Accept and auto-learn unknown keys, but reject changed keys.
    /// This is the default and matches common SSH client behavior.
    #[default]
    AcceptNew,

    /// Accept all keys without checking. For testing and lab use only.
    Disabled,
}

/// SSH connection configuration.
#[derive(Debug, Clone)]
pub struct SshConfig {
    /// Target host (hostname or IP address).
    pub host: String,

    /// SSH port (default: 22).
    pub port: u16,

    /// Username for authentication.
    pub username: String,

    /// Authentication method.
    pub auth: AuthMethod,

    /// Connection timeout.
    pub timeout: Duration,

    /// Terminal width for PTY.
    pub terminal_width: u32,

    /// Terminal height for PTY.
    pub terminal_height: u32,

    /// Host key verification mode.
    pub host_key_verification: HostKeyVerification,

    /// Path to known_hosts file.
    pub known_hosts_path: Option<PathBuf>,

    /// SSH keepalive interval.
    ///
    /// When set, sends SSH keepalive packets at this interval to prevent
    /// NAT/firewall timeouts and detect dead peers. Default: 30 seconds.
    ///
    /// Set to `None` to disable keepalive packets entirely.
    pub keepalive_interval: Option<Duration>,

    /// Maximum number of unanswered keepalive packets before disconnecting.
    ///
    /// If the remote peer does not respond to this many consecutive keepalive
    /// packets, the connection is considered dead. Default: 3.
    ///
    /// Only meaningful when `keepalive_interval` is set.
    pub keepalive_max: usize,

    /// Session inactivity timeout.
    ///
    /// If set, the SSH session is closed after this duration of no data
    /// in either direction. Default: `None` (no inactivity timeout).
    ///
    /// This is separate from the operation timeout (which controls how long
    /// individual commands wait for a prompt). Most users should leave this
    /// at `None` and rely on keepalive for connection health.
    pub inactivity_timeout: Option<Duration>,
}

impl SshConfig {
    /// Get the socket address for connection.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Authentication method for SSH connections.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// No authentication (for testing only).
    None,

    /// Password authentication.
    Password(String),

    /// Private key authentication.
    PrivateKey {
        /// Path to the private key file.
        path: PathBuf,
        /// Optional passphrase for encrypted keys.
        passphrase: Option<String>,
    },
}
