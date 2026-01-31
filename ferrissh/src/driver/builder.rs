//! Builder for creating device drivers.

use std::path::PathBuf;
use std::time::Duration;

use super::generic::GenericDriver;
use crate::error::{PlatformError, Result};
use crate::platform::{PlatformDefinition, PlatformRegistry};
use crate::transport::config::{AuthMethod, SshConfig};

/// Builder for constructing device drivers.
///
/// # Example
///
/// ```rust,no_run
/// use ferrissh::driver::DriverBuilder;
///
/// # async fn example() -> Result<(), ferrissh::Error> {
/// let driver = DriverBuilder::new("192.168.1.1")
///     .username("admin")
///     .password("secret")
///     .platform("linux")
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct DriverBuilder {
    host: String,
    port: u16,
    username: Option<String>,
    auth: AuthMethod,
    platform_name: Option<String>,
    custom_platform: Option<PlatformDefinition>,
    timeout: Duration,
    terminal_width: u32,
    terminal_height: u32,
}

impl DriverBuilder {
    /// Create a new driver builder for the specified host.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 22,
            username: None,
            auth: AuthMethod::None,
            platform_name: None,
            custom_platform: None,
            timeout: Duration::from_secs(30),
            terminal_width: 511,
            terminal_height: 24,
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

    /// Set the platform name (e.g., "linux", "cisco_iosxe").
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform_name = Some(platform.into());
        self
    }

    /// Set a custom platform definition.
    pub fn custom_platform(mut self, platform: PlatformDefinition) -> Self {
        self.custom_platform = Some(platform);
        self
    }

    /// Set the connection timeout.
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

    /// Build the driver.
    ///
    /// This creates the driver but does not connect. Call `open()` on the
    /// returned driver to establish the connection.
    pub async fn build(self) -> Result<GenericDriver> {
        // Get username
        let username = self.username.ok_or_else(|| {
            PlatformError::InvalidDefinition {
                message: "Username is required".to_string(),
            }
        })?;

        // Get platform definition
        let platform = if let Some(custom) = self.custom_platform {
            custom
        } else if let Some(name) = self.platform_name {
            PlatformRegistry::global()
                .read()
                .map_err(|_| PlatformError::InvalidDefinition {
                    message: "Failed to acquire registry lock".to_string(),
                })?
                .get(&name)
                .ok_or_else(|| PlatformError::UnknownPlatform { name })?
                .clone()
        } else {
            return Err(PlatformError::InvalidDefinition {
                message: "Platform must be specified".to_string(),
            }
            .into());
        };

        // Build SSH config
        let ssh_config = SshConfig {
            host: self.host,
            port: self.port,
            username,
            auth: self.auth,
            timeout: self.timeout,
            terminal_width: self.terminal_width,
            terminal_height: self.terminal_height,
            verify_host_key: false,
            known_hosts_path: None,
        };

        Ok(GenericDriver::new(ssh_config, platform))
    }
}
