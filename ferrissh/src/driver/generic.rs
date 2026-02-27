//! Generic driver implementation that works with any platform.
//!
//! `GenericDriver` wraps a [`Session`] + [`Channel`], providing the simple
//! build-then-open API for users who need a single PTY shell per connection.
//! For multi-channel use, call [`open_channel()`](GenericDriver::open_channel)
//! or access the underlying [`Session`] directly.

use std::time::{Duration, Instant};

use log::{debug, warn};
use tokio::sync::watch;

use super::Driver;
use super::SessionState;
use super::channel::Channel;
use super::config_session::GenericConfigSession;
use super::interactive::{InteractiveEvent, InteractiveResult};
use super::privilege::PrivilegeManager;
use super::response::Response;
use crate::error::{DisconnectReason, DriverError, Result};
use crate::platform::PlatformDefinition;
use crate::session::Session;
use crate::transport::SshTransport;
use crate::transport::config::SshConfig;

/// Generic driver that works with any platform definition.
///
/// This is the main driver implementation — a thin wrapper around
/// [`Session`] + [`Channel`]. It handles:
/// - SSH transport management (via Session)
/// - Command execution with prompt detection (via Channel)
/// - Privilege level navigation (via Channel)
/// - Vendor-specific behavior hooks
///
/// For multi-channel use, call [`open_channel()`](Self::open_channel).
pub struct GenericDriver {
    /// SSH configuration (kept for build-then-open pattern).
    ssh_config: SshConfig,

    /// Platform definition (kept for build-then-open pattern).
    platform: PlatformDefinition,

    /// Whether to normalize command output.
    normalize: bool,

    /// The underlying SSH session (None when disconnected).
    session: Option<Session>,

    /// The primary PTY channel (None when disconnected).
    channel: Option<Channel>,
}

impl GenericDriver {
    /// Create a new generic driver.
    pub fn new(ssh_config: SshConfig, platform: PlatformDefinition, normalize: bool) -> Self {
        Self {
            ssh_config,
            platform,
            normalize,
            session: None,
            channel: None,
        }
    }

    /// Get the current prompt pattern.
    pub fn prompt_pattern(&self) -> Option<&regex::bytes::Regex> {
        self.channel.as_ref().map(|c| c.prompt_pattern())
    }

    /// Get a reference to the platform definition.
    pub fn platform(&self) -> &PlatformDefinition {
        self.channel
            .as_ref()
            .map(|c| c.platform())
            .unwrap_or(&self.platform)
    }

    /// Get the privilege manager.
    pub fn privilege_manager(&self) -> Option<&PrivilegeManager> {
        self.channel.as_ref().map(|c| c.privilege_manager())
    }

    /// Get a mutable reference to the privilege manager.
    pub fn privilege_manager_mut(&mut self) -> Option<&mut PrivilegeManager> {
        self.channel.as_mut().map(|c| c.privilege_manager_mut())
    }

    /// Set the default timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        if let Some(ref mut ch) = self.channel {
            ch.set_timeout(timeout);
        }
    }

    /// Rebuild the combined prompt pattern from current privilege levels.
    pub fn rebuild_prompt_pattern(&mut self) {
        if let Some(ref mut ch) = self.channel {
            ch.rebuild_prompt_pattern();
        }
    }

    /// Enter a generic configuration session.
    ///
    /// Returns an RAII guard that holds `&mut Channel`, preventing concurrent
    /// use during the session. Works for any vendor with a config
    /// privilege level.
    ///
    /// For vendor-specific features (named sessions, diff), use the vendor's
    /// own session type (e.g., `AristaConfigSession::new(&mut driver, "name")`).
    pub async fn config_session(&mut self) -> Result<GenericConfigSession<'_>> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;
        GenericConfigSession::new(channel).await
    }

    /// Get the current session state.
    pub fn session_state(&self) -> SessionState {
        self.state()
    }

    /// When the current session was established.
    pub fn connected_since(&self) -> Option<Instant> {
        self.session.as_ref().map(|s| s.connected_since())
    }

    /// When the last command completed successfully.
    pub fn last_command_at(&self) -> Option<Instant> {
        self.channel.as_ref().and_then(|c| c.last_command_at())
    }

    /// Get a clonable disconnect receiver for use in `tokio::select!`.
    ///
    /// Returns `None` if the driver is not connected.
    pub fn disconnect_receiver(&self) -> Option<watch::Receiver<Option<DisconnectReason>>> {
        self.session.as_ref().map(|s| s.disconnect_receiver())
    }

    /// Get a reference to the underlying session.
    ///
    /// Returns `None` if the driver is not connected.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Get a mutable reference to the underlying channel.
    ///
    /// Returns `None` if the driver is not connected.
    pub fn channel(&mut self) -> Option<&mut Channel> {
        self.channel.as_mut()
    }

    /// Open an additional PTY channel on the same SSH connection.
    ///
    /// The new channel gets its own shell, privilege state, and pattern buffer.
    /// The driver must be connected (i.e., `open()` must have been called).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use ferrissh::{DriverBuilder, Driver, Platform};
    ///
    /// # async fn example() -> Result<(), ferrissh::Error> {
    /// let mut driver = DriverBuilder::new("192.168.1.1")
    ///     .username("admin")
    ///     .password("secret")
    ///     .platform(Platform::Linux)
    ///     .build()?;
    /// driver.open().await?;
    ///
    /// let mut ch2 = driver.open_channel().await?;
    /// let resp = ch2.send_command("hostname").await?;
    ///
    /// ch2.close().await?;
    /// driver.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn open_channel(&self) -> Result<Channel> {
        let session = self.session.as_ref().ok_or(DriverError::NotConnected)?;
        session.open_channel().await
    }

    /// Decompose the driver into its session and channel components.
    ///
    /// Returns `None` if the driver is not connected.
    pub fn into_parts(mut self) -> Option<(Session, Channel)> {
        let session = self.session.take()?;
        let channel = self.channel.take()?;
        Some((session, channel))
    }
}

impl Drop for GenericDriver {
    fn drop(&mut self) {
        if self.session.is_some() && self.channel.is_some() {
            warn!("GenericDriver dropped while still connected — call close() first");
        }
    }
}

impl Driver for GenericDriver {
    async fn open(&mut self) -> Result<()> {
        if self.session.is_some() {
            return Err(DriverError::AlreadyConnected.into());
        }

        debug!(
            "opening connection to {} (platform: {})",
            self.ssh_config.host, self.platform.name
        );

        // Connect
        let transport = SshTransport::connect(self.ssh_config.clone()).await?;
        let session = Session::new(transport, self.platform.clone(), self.ssh_config.clone());

        // Open a channel (waits for prompt, runs on_open, determines privilege)
        let mut channel = match session.open_channel().await {
            Ok(ch) => ch,
            Err(e) => {
                // Clean up session if channel open fails
                session.close().await.ok();
                return Err(e);
            }
        };
        channel.set_normalize(self.normalize);

        self.session = Some(session);
        self.channel = Some(channel);

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let current_state = self.state();
        match current_state {
            SessionState::Ready => {
                debug!("closing connection");

                if let Some(mut channel) = self.channel.take() {
                    channel.close().await?;
                }

                if let Some(session) = self.session.take() {
                    session.close().await?;
                }
            }
            SessionState::Dead => {
                debug!("cleaning up dead connection");
                self.channel.take();
                self.session.take();
            }
            SessionState::Disconnected | SessionState::Closing => {}
        }
        Ok(())
    }

    async fn send_command(&mut self, command: &str) -> Result<Response> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;
        channel.send_command(command).await
    }

    async fn acquire_privilege(&mut self, target: &str) -> Result<()> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;
        channel.acquire_privilege(target).await
    }

    async fn send_interactive(&mut self, events: &[InteractiveEvent]) -> Result<InteractiveResult> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;
        channel.send_interactive(events).await
    }

    async fn send_config(&mut self, commands: &[&str]) -> Result<Vec<Response>> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;
        channel.send_config(commands).await
    }

    fn is_open(&self) -> bool {
        self.channel.as_ref().is_some_and(|c| c.is_open())
    }

    fn is_alive(&self) -> bool {
        self.channel.as_ref().is_some_and(|c| c.is_alive())
    }

    fn current_privilege(&self) -> Option<&str> {
        self.channel.as_ref().and_then(|c| c.current_privilege())
    }

    fn state(&self) -> SessionState {
        match (&self.session, &self.channel) {
            (Some(_), Some(ch)) => match ch.channel_state() {
                super::channel::ChannelState::Ready => SessionState::Ready,
                super::channel::ChannelState::Closing => SessionState::Closing,
                super::channel::ChannelState::Dead => SessionState::Dead,
            },
            _ => SessionState::Disconnected,
        }
    }
}
