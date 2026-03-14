//! SSH connection configuration.

use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;

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
#[derive(Clone)]
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

    /// SSH channel window size in bytes.
    ///
    /// Controls the SSH flow-control window — the maximum amount of
    /// unacknowledged data the remote side can send before waiting for a
    /// window adjustment. Larger values allow higher throughput but use
    /// more memory per channel.
    ///
    /// Default: `None` (uses the russh default of 2 MiB).
    pub window_size: Option<u32>,

    /// Maximum SSH packet size in bytes.
    ///
    /// The maximum size of a single SSH data packet. Larger values reduce
    /// framing overhead but increase per-packet memory.
    ///
    /// Default: `None` (uses the russh default of 32 KiB).
    pub maximum_packet_size: Option<u32>,
}

impl SshConfig {
    /// Get the socket address for connection.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Authentication method for SSH connections.
#[derive(Clone)]
pub enum AuthMethod {
    /// No authentication (for testing only).
    None,

    /// Password authentication.
    Password(SecretString),

    /// Private key authentication.
    PrivateKey {
        /// Path to the private key file.
        path: PathBuf,
        /// Optional passphrase for encrypted keys.
        passphrase: Option<SecretString>,
    },
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Password(_) => write!(f, "Password(****)"),
            Self::PrivateKey { path, passphrase } => f
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "****"))
                .finish(),
        }
    }
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authmethod_debug_redacts_password() {
        let auth = AuthMethod::Password(SecretString::from("super_secret_password"));
        let debug_output = format!("{:?}", auth);
        assert!(!debug_output.contains("super_secret_password"));
        assert!(debug_output.contains("****"));
    }

    #[test]
    fn test_authmethod_debug_redacts_passphrase() {
        let auth = AuthMethod::PrivateKey {
            path: PathBuf::from("/home/user/.ssh/id_rsa"),
            passphrase: Some(SecretString::from("my_passphrase")),
        };
        let debug_output = format!("{:?}", auth);
        assert!(!debug_output.contains("my_passphrase"));
        assert!(debug_output.contains("****"));
        assert!(debug_output.contains("id_rsa"));
    }

    #[test]
    fn test_sshconfig_debug_redacts_credentials() {
        let config = SshConfig {
            host: "192.168.1.1".to_string(),
            port: 22,
            username: "admin".to_string(),
            auth: AuthMethod::Password(SecretString::from("secret_password")),
            timeout: Duration::from_secs(30),
            terminal_width: 120,
            terminal_height: 24,
            host_key_verification: HostKeyVerification::AcceptNew,
            known_hosts_path: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            inactivity_timeout: None,
            window_size: None,
            maximum_packet_size: None,
        };
        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("secret_password"));
        assert!(debug_output.contains("192.168.1.1"));
    }
}
