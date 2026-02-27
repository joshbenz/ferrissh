//! SSH session management.
//!
//! A [`Session`] represents an authenticated SSH connection to a device.
//! It is `Clone + Send + Sync` (Arc-based) and cheap to share across tasks
//! or store in connection pools.
//!
//! Use [`SessionBuilder`] to establish a connection, then call
//! [`Session::open_channel()`] to create one or more independent PTY shells.
//!
//! # Example
//!
//! ```rust,no_run
//! use ferrissh::{SessionBuilder, Platform};
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let session = SessionBuilder::new("192.168.1.1")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::Linux)
//!     .connect()
//!     .await?;
//!
//! let mut ch1 = session.open_channel().await?;
//! let mut ch2 = session.open_channel().await?;
//!
//! let r1 = ch1.send_command("uname -a").await?;
//! let r2 = ch2.send_command("hostname").await?;
//!
//! ch1.close().await?;
//! ch2.close().await?;
//! session.close().await?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::debug;
use regex::bytes::Regex;
use tokio::sync::watch;

use crate::channel::{PtyChannel, PtyConfig};
use crate::driver::channel::Channel;
use crate::error::{DisconnectReason, DriverError, PlatformError, Result};
use crate::platform::{Platform, PlatformDefinition};
use secrecy::SecretString;

use crate::transport::SshTransport;
use crate::transport::config::{AuthMethod, HostKeyVerification, SshConfig};

/// Inner state of an SSH session, shared via `Arc`.
struct SessionInner {
    /// The SSH transport.
    transport: SshTransport,

    /// Platform definition.
    platform: Arc<PlatformDefinition>,

    /// SSH configuration (kept for opening channels).
    ssh_config: SshConfig,

    /// Combined prompt pattern for all privilege levels.
    prompt_pattern: Regex,

    /// Sender for disconnect notifications.
    disconnect_tx: Arc<watch::Sender<Option<DisconnectReason>>>,

    /// Receiver template for disconnect notifications (clonable).
    disconnect_rx: watch::Receiver<Option<DisconnectReason>>,

    /// When the session was established.
    connected_since: Instant,
}

/// An authenticated SSH connection to a device.
///
/// `Session` is `Clone + Send + Sync` — cloning is cheap (increments a
/// reference count). Use [`open_channel()`](Session::open_channel) to create
/// independent PTY shells on the same underlying SSH connection.
///
/// Obtain a `Session` via [`SessionBuilder::connect()`] or
/// [`GenericDriver::session()`](crate::GenericDriver).
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

impl Session {
    /// Create a new session from its components.
    pub(crate) fn new(
        transport: SshTransport,
        platform: PlatformDefinition,
        ssh_config: SshConfig,
    ) -> Self {
        let disconnect_tx = transport.disconnect_tx().clone();
        let disconnect_rx = transport.disconnect_rx().clone();

        let prompt_pattern = build_combined_pattern(&platform);

        Self {
            inner: Arc::new(SessionInner {
                transport,
                platform: Arc::new(platform),
                ssh_config,
                prompt_pattern,
                disconnect_tx,
                disconnect_rx,
                connected_since: Instant::now(),
            }),
        }
    }

    /// Open a new PTY channel on this session.
    ///
    /// Each channel gets its own interactive shell, privilege state, and
    /// pattern buffer. The channel waits for the initial prompt, executes
    /// `on_open_commands`, and determines the initial privilege level before
    /// returning.
    pub async fn open_channel(&self) -> Result<Channel> {
        let russh_channel = self.inner.transport.open_channel().await?;
        let pty = PtyChannel::new(russh_channel, PtyConfig::default());

        let auth_password = match &self.inner.ssh_config.auth {
            AuthMethod::Password(pwd) => Some(pwd.clone()),
            _ => None,
        };

        let mut channel = Channel::new(
            self.clone(),
            pty,
            self.inner.ssh_config.timeout,
            self.inner.prompt_pattern.clone(),
            true, // normalize
            self.inner.disconnect_rx.clone(),
            auth_password,
        );

        // Wait for initial prompt, run on_open, determine privilege
        match channel.initialize().await {
            Ok(()) => Ok(channel),
            Err(e) => {
                // Close the PTY to avoid leaking the russh channel
                channel.close().await.ok();
                Err(e)
            }
        }
    }

    /// Check if the underlying SSH transport is still alive.
    pub fn is_alive(&self) -> bool {
        self.inner.transport.is_alive()
    }

    /// Get the platform definition.
    pub fn platform(&self) -> &PlatformDefinition {
        &self.inner.platform
    }

    /// When this session was established.
    pub fn connected_since(&self) -> Instant {
        self.inner.connected_since
    }

    /// Get the combined prompt pattern.
    pub fn prompt_pattern(&self) -> &Regex {
        &self.inner.prompt_pattern
    }

    /// Get a clonable disconnect receiver.
    pub fn disconnect_receiver(&self) -> watch::Receiver<Option<DisconnectReason>> {
        self.inner.disconnect_rx.clone()
    }

    /// Get the disconnect sender.
    pub(crate) fn disconnect_tx(&self) -> &Arc<watch::Sender<Option<DisconnectReason>>> {
        &self.inner.disconnect_tx
    }

    /// Close the SSH connection.
    ///
    /// Signals disconnect to all channels, then closes the transport.
    /// Since `Session` is `Clone`, this can be called from any clone —
    /// all clones share the same underlying connection.
    pub async fn close(&self) -> Result<()> {
        debug!("closing session");

        // Signal graceful close
        self.inner.disconnect_tx.send_if_modified(|value| {
            if value.is_none() {
                *value = Some(DisconnectReason::Closed);
                true
            } else {
                false
            }
        });

        self.inner
            .transport
            .disconnect()
            .await
            .map_err(crate::error::Error::Transport)?;

        Ok(())
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("host", &self.inner.ssh_config.host)
            .field("port", &self.inner.ssh_config.port)
            .field("platform", &self.inner.platform.name)
            .field("alive", &self.is_alive())
            .finish()
    }
}

/// Build a combined regex pattern that matches any privilege level's prompt.
fn build_combined_pattern(platform: &PlatformDefinition) -> Regex {
    let patterns: Vec<String> = platform
        .privilege_levels
        .values()
        .map(|level| format!("(?:{})", level.pattern.as_str()))
        .collect();

    let combined = patterns.join("|");
    Regex::new(&combined).unwrap_or_else(|_| crate::driver::channel::FALLBACK_PROMPT.clone())
}

// =============================================================================
// SessionBuilder
// =============================================================================

/// Builder for establishing an SSH session.
///
/// Similar to [`DriverBuilder`](crate::DriverBuilder) but produces a
/// [`Session`] instead of a [`GenericDriver`](crate::GenericDriver).
/// Use this when you need direct access to multiple channels.
///
/// # Example
///
/// ```rust,no_run
/// use ferrissh::{SessionBuilder, Platform};
///
/// # async fn example() -> Result<(), ferrissh::Error> {
/// let session = SessionBuilder::new("192.168.1.1")
///     .username("admin")
///     .password("secret")
///     .platform(Platform::Linux)
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct SessionBuilder {
    host: String,
    port: u16,
    username: Option<String>,
    auth: AuthMethod,
    platform: Option<Platform>,
    timeout: Duration,
    terminal_width: Option<u32>,
    terminal_height: Option<u32>,
    host_key_verification: HostKeyVerification,
    known_hosts_path: Option<PathBuf>,
    keepalive_interval: Option<Option<Duration>>,
    keepalive_max: Option<usize>,
    inactivity_timeout: Option<Option<Duration>>,
}

impl SessionBuilder {
    /// Create a new session builder for the specified host.
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
        self.auth = AuthMethod::Password(SecretString::from(password.into()));
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
            passphrase: Some(SecretString::from(passphrase.into())),
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

    /// Set the host key verification mode (default: `AcceptNew`).
    pub fn host_key_verification(mut self, mode: HostKeyVerification) -> Self {
        self.host_key_verification = mode;
        self
    }

    /// Set a custom known_hosts file path.
    pub fn known_hosts_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.known_hosts_path = Some(path.into());
        self
    }

    /// Disable host key verification entirely.
    pub fn danger_disable_host_key_verification(mut self) -> Self {
        self.host_key_verification = HostKeyVerification::Disabled;
        self
    }

    /// Set terminal dimensions.
    pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
        self.terminal_width = Some(width);
        self.terminal_height = Some(height);
        self
    }

    /// Set the SSH keepalive interval.
    pub fn keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Set the maximum number of unanswered keepalive packets.
    pub fn keepalive_max(mut self, max: usize) -> Self {
        self.keepalive_max = Some(max);
        self
    }

    /// Set the session inactivity timeout.
    pub fn inactivity_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inactivity_timeout = Some(timeout);
        self
    }

    /// Connect to the SSH server and authenticate.
    ///
    /// Returns a [`Session`] representing the authenticated connection.
    /// No channel is opened yet — call [`Session::open_channel()`] to
    /// create PTY shells.
    pub async fn connect(self) -> Result<Session> {
        if self.host.is_empty() {
            return Err(DriverError::InvalidConfig {
                message: "Host cannot be empty".to_string(),
            }
            .into());
        }
        if self.port == 0 {
            return Err(DriverError::InvalidConfig {
                message: "Port cannot be 0".to_string(),
            }
            .into());
        }

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

        debug!(
            "connecting to {}:{} (platform: {})",
            ssh_config.host, ssh_config.port, platform.name
        );

        let transport = SshTransport::connect(ssh_config.clone()).await?;

        Ok(Session::new(transport, platform, ssh_config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_builder_empty_host() {
        let result = SessionBuilder::new("")
            .username("admin")
            .password("secret")
            .platform(Platform::Linux)
            .connect()
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Host cannot be empty"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_session_builder_port_zero() {
        let result = SessionBuilder::new("192.168.1.1")
            .port(0)
            .username("admin")
            .password("secret")
            .platform(Platform::Linux)
            .connect()
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Port cannot be 0"), "got: {}", err);
    }
}
