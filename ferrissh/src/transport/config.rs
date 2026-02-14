//! SSH connection configuration.

use std::path::PathBuf;
use std::time::Duration;

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

    /// Whether to verify the host key.
    pub verify_host_key: bool,

    /// Path to known_hosts file.
    pub known_hosts_path: Option<PathBuf>,
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
