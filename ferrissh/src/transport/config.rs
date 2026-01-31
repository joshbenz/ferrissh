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
    /// Create a new SSH config with required fields.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 22,
            username: username.into(),
            auth: AuthMethod::None,
            timeout: Duration::from_secs(30),
            terminal_width: 511,
            terminal_height: 24,
            verify_host_key: false, // TODO: Default to true once known_hosts is implemented
            known_hosts_path: None,
        }
    }

    /// Set the SSH port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set password authentication.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.auth = AuthMethod::Password(password.into());
        self
    }

    /// Set private key authentication.
    pub fn private_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.auth = AuthMethod::PrivateKey {
            path: key_path.into(),
            passphrase: None,
        };
        self
    }

    /// Set private key authentication with passphrase.
    pub fn private_key_with_passphrase(
        mut self,
        key_path: impl Into<PathBuf>,
        passphrase: impl Into<String>,
    ) -> Self {
        self.auth = AuthMethod::PrivateKey {
            path: key_path.into(),
            passphrase: Some(passphrase.into()),
        };
        self
    }

    /// Set connection timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set terminal dimensions.
    pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
        self.terminal_width = width;
        self.terminal_height = height;
        self
    }

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

    /// SSH agent authentication.
    Agent,
}
