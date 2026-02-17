//! Builder for creating device drivers.

use std::path::PathBuf;
use std::time::Duration;

use super::generic::GenericDriver;
use crate::error::{DriverError, PlatformError, Result};
use crate::platform::{Platform, PlatformDefinition};
use crate::transport::config::{AuthMethod, HostKeyVerification, SshConfig};

/// Builder for constructing device drivers.
///
/// # Example
///
/// ```rust,no_run
/// use ferrissh::{DriverBuilder, Platform};
///
/// # async fn example() -> Result<(), ferrissh::Error> {
/// let driver = DriverBuilder::new("192.168.1.1")
///     .username("admin")
///     .password("secret")
///     .platform(Platform::Linux)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct DriverBuilder {
    host: String,
    port: u16,
    username: Option<String>,
    auth: AuthMethod,
    platform: Option<Platform>,
    timeout: Duration,
    terminal_width: Option<u32>,
    terminal_height: Option<u32>,
    normalize_output: bool,
    host_key_verification: HostKeyVerification,
    known_hosts_path: Option<PathBuf>,
    keepalive_interval: Option<Option<Duration>>,
    keepalive_max: Option<usize>,
    inactivity_timeout: Option<Option<Duration>>,
}

impl DriverBuilder {
    /// Create a new driver builder for the specified host.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 22,
            username: None,
            auth: AuthMethod::None,
            platform: None,
            timeout: Duration::from_secs(30),
            terminal_width: None,
            terminal_height: None,
            normalize_output: true,
            host_key_verification: HostKeyVerification::AcceptNew,
            known_hosts_path: None,
            keepalive_interval: None,
            keepalive_max: None,
            inactivity_timeout: None,
        }
    }

    /// Set the SSH port (default: 22).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the username for authentication.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
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

    /// Set the platform.
    pub fn platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Set the connection timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether command output is normalized (default: true).
    ///
    /// When enabled, command echo and trailing prompts are stripped from output,
    /// and vendor-specific post-processing is applied. Disable this to get raw
    /// device output in `Response::result`.
    pub fn normalize_output(mut self, normalize: bool) -> Self {
        self.normalize_output = normalize;
        self
    }

    /// Set the host key verification mode (default: `AcceptNew`).
    ///
    /// - `Strict`: Reject unknown and changed keys
    /// - `AcceptNew`: Accept new keys (auto-learn), reject changed keys (default)
    /// - `Disabled`: Accept all keys (for testing only)
    pub fn host_key_verification(mut self, mode: HostKeyVerification) -> Self {
        self.host_key_verification = mode;
        self
    }

    /// Set a custom known_hosts file path.
    ///
    /// If not set, defaults to `~/.ssh/known_hosts`.
    pub fn known_hosts_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts_path = Some(path.into());
        self
    }

    /// Disable host key verification entirely.
    ///
    /// Equivalent to `.host_key_verification(HostKeyVerification::Disabled)`.
    /// Only use this for testing or lab environments.
    pub fn danger_disable_host_key_verification(mut self) -> Self {
        self.host_key_verification = HostKeyVerification::Disabled;
        self
    }

    /// Set terminal dimensions, overriding the platform's defaults.
    pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
        self.terminal_width = Some(width);
        self.terminal_height = Some(height);
        self
    }

    /// Set the SSH keepalive interval (default: 30 seconds).
    ///
    /// Sends SSH keepalive packets at this interval to prevent NAT/firewall
    /// timeouts and detect dead peers. Set to `None` to disable.
    pub fn keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Set the maximum number of unanswered keepalive packets before
    /// disconnecting (default: 3).
    ///
    /// Only meaningful when keepalive is enabled.
    pub fn keepalive_max(mut self, max: usize) -> Self {
        self.keepalive_max = Some(max);
        self
    }

    /// Set the session inactivity timeout.
    ///
    /// If set, the SSH session is closed after this duration of no data
    /// in either direction. Default: `None` (no inactivity timeout).
    ///
    /// This is separate from the operation timeout set via [`timeout()`](Self::timeout).
    /// Most users should leave this at `None` and rely on keepalive for
    /// connection health.
    pub fn inactivity_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inactivity_timeout = Some(timeout);
        self
    }

    /// Build the driver.
    ///
    /// This creates the driver but does not connect. Call `open()` on the
    /// returned driver to establish the connection.
    pub fn build(self) -> Result<GenericDriver> {
        let username = self.username.ok_or_else(|| DriverError::InvalidConfig {
            message: "Username is required".to_string(),
        })?;

        if matches!(self.auth, AuthMethod::None) {
            return Err(DriverError::InvalidConfig {
                message: "Authentication method is required - call password() or private_key()"
                    .to_string(),
            }
            .into());
        }

        let platform = self
            .platform
            .ok_or_else(|| PlatformError::InvalidDefinition {
                message: "Platform must be specified".to_string(),
            })?;
        let platform = PlatformDefinition::from(platform);

        let ssh_config = SshConfig {
            host: self.host,
            port: self.port,
            username,
            auth: self.auth,
            timeout: self.timeout,
            terminal_width: self.terminal_width.unwrap_or(platform.terminal_width),
            terminal_height: self.terminal_height.unwrap_or(platform.terminal_height),
            host_key_verification: self.host_key_verification,
            known_hosts_path: self.known_hosts_path,
            keepalive_interval: self
                .keepalive_interval
                .unwrap_or(Some(Duration::from_secs(30))),
            keepalive_max: self.keepalive_max.unwrap_or(3),
            inactivity_timeout: self.inactivity_timeout.unwrap_or(None),
        };

        Ok(GenericDriver::new(
            ssh_config,
            platform,
            self.normalize_output,
        ))
    }
}
