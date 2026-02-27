//! Generic driver implementation that works with any platform.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use regex::bytes::Regex;
use tokio::sync::watch;

use super::Driver;
use super::SessionState;
use super::config_session::GenericConfigSession;
use super::interactive::{InteractiveEvent, InteractiveResult, InteractiveStep};
use super::payload::Payload;
use super::privilege::PrivilegeManager;
use super::response::Response;
use crate::channel::{PtyChannel, PtyConfig};
use crate::error::{ChannelError, DisconnectReason, DriverError, Error, Result, TransportError};
use crate::platform::PlatformDefinition;
use crate::transport::SshTransport;
use crate::transport::config::SshConfig;
use log::{debug, trace, warn};

/// Generic driver that works with any platform definition.
///
/// This is the main driver implementation that handles:
/// - SSH transport management
/// - Command execution with prompt detection
/// - Privilege level navigation
/// - Vendor-specific behavior hooks
pub struct GenericDriver {
    /// SSH configuration.
    ssh_config: SshConfig,

    /// Platform definition.
    platform: PlatformDefinition,

    /// SSH transport (None when disconnected).
    transport: Option<SshTransport>,

    /// PTY channel for interactive session (None when disconnected).
    channel: Option<PtyChannel>,

    /// Privilege level manager.
    privilege_manager: PrivilegeManager,

    /// Default timeout for operations.
    timeout: Duration,

    /// Combined prompt pattern for all privilege levels.
    prompt_pattern: Regex,

    /// Whether to normalize command output.
    normalize: bool,

    /// Current session state.
    state: SessionState,

    /// Sender for disconnect notifications (shared with SshHandler).
    disconnect_tx: Option<Arc<watch::Sender<Option<DisconnectReason>>>>,

    /// Receiver for disconnect notifications.
    disconnect_rx: Option<watch::Receiver<Option<DisconnectReason>>>,

    /// When the current session was established.
    connected_since: Option<Instant>,

    /// When the last command completed successfully.
    last_command_at: Option<Instant>,
}

impl GenericDriver {
    /// Create a new generic driver.
    pub fn new(ssh_config: SshConfig, platform: PlatformDefinition, normalize: bool) -> Self {
        let timeout = ssh_config.timeout;

        // Build privilege manager
        let privilege_manager = PrivilegeManager::new(platform.privilege_levels.clone());

        // Build combined prompt pattern
        let prompt_pattern = Self::build_combined_pattern(&platform);

        Self {
            ssh_config,
            platform,
            transport: None,
            channel: None,
            privilege_manager,
            timeout,
            prompt_pattern,
            normalize,
            state: SessionState::Disconnected,
            disconnect_tx: None,
            disconnect_rx: None,
            connected_since: None,
            last_command_at: None,
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
        Regex::new(&combined).unwrap_or_else(|_| Regex::new(r"[$#>]\s*$").unwrap())
    }

    /// Get the current prompt pattern.
    pub fn prompt_pattern(&self) -> &Regex {
        &self.prompt_pattern
    }

    /// Get a reference to the platform definition.
    pub fn platform(&self) -> &PlatformDefinition {
        &self.platform
    }

    /// Get the privilege manager.
    pub fn privilege_manager(&self) -> &PrivilegeManager {
        &self.privilege_manager
    }

    /// Get a mutable reference to the privilege manager.
    pub fn privilege_manager_mut(&mut self) -> &mut PrivilegeManager {
        &mut self.privilege_manager
    }

    /// Set the default timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Rebuild the combined prompt pattern from current privilege levels.
    ///
    /// Must be called after registering or removing dynamic privilege levels
    /// so the driver can recognize new prompt patterns.
    pub fn rebuild_prompt_pattern(&mut self) {
        let patterns: Vec<String> = self
            .privilege_manager
            .levels()
            .values()
            .map(|level| format!("(?:{})", level.pattern.as_str()))
            .collect();

        let combined = patterns.join("|");
        self.prompt_pattern =
            Regex::new(&combined).unwrap_or_else(|_| Regex::new(r"[$#>]\s*$").unwrap());
    }

    /// Enter a generic configuration session.
    ///
    /// Returns an RAII guard that holds `&mut self`, preventing concurrent
    /// driver use during the session. Works for any vendor with a config
    /// privilege level.
    ///
    /// For vendor-specific features (named sessions, diff), use the vendor's
    /// own session type (e.g., `AristaConfigSession::new(&mut driver, "name")`).
    pub async fn config_session(&mut self) -> Result<GenericConfigSession<'_>> {
        GenericConfigSession::new(self).await
    }

    /// Extract the prompt string from the tail of a raw byte buffer.
    ///
    /// Returns the prompt as a small `String` and the byte offset where
    /// the prompt match starts (relative to the full buffer).
    fn extract_prompt(&self, data: &[u8]) -> String {
        let search_depth = self
            .channel
            .as_ref()
            .map(|c| c.search_depth())
            .unwrap_or(1000);
        let tail_start = data.len().saturating_sub(search_depth);
        let tail = &data[tail_start..];
        if let Some(m) = self.prompt_pattern.find(tail) {
            let matched = String::from_utf8_lossy(&tail[m.start()..])
                .trim()
                .to_string();
            trace!("prompt matched: {:?}", matched);
            matched
        } else {
            trace!("no prompt match in {} bytes of output", data.len());
            String::new()
        }
    }

    /// Read until the prompt is matched, then determine current privilege.
    async fn read_until_prompt(&mut self) -> Result<(BytesMut, String)> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

        let data = channel
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let prompt = self.extract_prompt(&data);

        Ok((data, prompt))
    }

    /// Normalize output in place on a `BytesMut` buffer.
    ///
    /// 1. Normalize linefeeds in place
    /// 2. Strip command echo from the beginning
    /// 3. Strip trailing prompt (last line)
    /// 4. Apply vendor-specific post-processing
    fn normalize_output_in_place(&self, buf: &mut BytesMut, command: &str) {
        debug!(
            "normalize_output: command={:?}, buf_len={}",
            command,
            buf.len()
        );

        normalize_linefeeds_in_place(buf);
        strip_echo_in_place(buf, command);

        // Trim leading newlines
        let leading = buf.iter().take_while(|&&b| b == b'\n').count();
        if leading > 0 {
            let _ = buf.split_to(leading);
        }

        strip_trailing_prompt_in_place(buf);

        // Apply vendor-specific post-processing if present
        if let Some(ref behavior) = self.platform.behavior {
            behavior.post_process_output(buf);
        }

        debug!("normalize_output: result_len={}", buf.len());
    }

    /// Execute on_open commands from platform definition.
    async fn execute_on_open_commands(&mut self) -> Result<()> {
        for cmd in &self.platform.on_open_commands.clone() {
            self.send_command(cmd).await?;
        }
        Ok(())
    }

    /// Check that the session is in `Ready` state.
    ///
    /// Also performs a non-blocking check of the disconnect watch channel
    /// to catch idle disconnects that happened since the last operation.
    fn check_ready(&mut self) -> Result<()> {
        if self.state != SessionState::Ready {
            return Err(DriverError::NotConnected.into());
        }

        // Non-blocking check for async disconnect
        if let Some(ref mut rx) = self.disconnect_rx {
            match rx.has_changed() {
                Ok(true) => {
                    let reason = rx.borrow_and_update().clone();
                    if let Some(reason) = reason {
                        self.handle_disconnect(reason);
                        return Err(DriverError::NotConnected.into());
                    }
                }
                Err(_) => {
                    // Sender dropped — connection is gone
                    self.handle_disconnect(DisconnectReason::TransportError(
                        "connection lost".into(),
                    ));
                    return Err(DriverError::NotConnected.into());
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Transition to `Dead` state on connection loss.
    fn handle_disconnect(&mut self, reason: DisconnectReason) {
        debug!("handle_disconnect: {:?}", reason);
        self.state = SessionState::Dead;
        self.channel.take();
        self.transport.take();
        if let Some(ref tx) = self.disconnect_tx {
            tx.send_if_modified(|value| {
                if value.is_none() {
                    *value = Some(reason);
                    true
                } else {
                    false
                }
            });
        }
    }

    /// Check if an error indicates a dead connection.
    fn is_connection_error(e: &Error) -> bool {
        matches!(
            e,
            Error::Channel(ChannelError::Eof)
                | Error::Channel(ChannelError::Disconnected)
                | Error::Transport(TransportError::Disconnected)
                | Error::Transport(TransportError::Ssh(_))
        )
    }

    /// Get the current session state.
    pub fn session_state(&self) -> SessionState {
        self.state
    }

    /// When the current session was established.
    pub fn connected_since(&self) -> Option<Instant> {
        self.connected_since
    }

    /// When the last command completed successfully.
    pub fn last_command_at(&self) -> Option<Instant> {
        self.last_command_at
    }

    /// Get a clonable disconnect receiver for use in `tokio::select!`.
    ///
    /// Returns `None` if the driver is not connected.
    pub fn disconnect_receiver(&self) -> Option<watch::Receiver<Option<DisconnectReason>>> {
        self.disconnect_rx.clone()
    }
}

impl Drop for GenericDriver {
    fn drop(&mut self) {
        if self.state == SessionState::Ready {
            warn!("GenericDriver dropped while still connected — call close() first");
        }
    }
}

impl Driver for GenericDriver {
    async fn open(&mut self) -> Result<()> {
        if self.state != SessionState::Disconnected {
            return Err(DriverError::AlreadyConnected.into());
        }

        debug!(
            "opening connection to {} (platform: {})",
            self.ssh_config.host, self.platform.name
        );

        // Connect
        let transport = SshTransport::connect(self.ssh_config.clone()).await?;

        // Clone disconnect handles from transport
        self.disconnect_tx = Some(transport.disconnect_tx().clone());
        self.disconnect_rx = Some(transport.disconnect_rx().clone());

        // Open a PTY channel
        let russh_channel = transport.open_channel().await?;
        let pty_channel = PtyChannel::new(russh_channel, PtyConfig::default());

        self.transport = Some(transport);
        self.channel = Some(pty_channel);
        self.state = SessionState::Ready;
        self.connected_since = Some(Instant::now());

        // Wait for initial prompt
        let (_data, prompt) = self.read_until_prompt().await?;

        // Determine initial privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            self.privilege_manager.set_current(&level_name)?;
            debug!("initial privilege level: {:?}", level_name);
        }

        // Execute on_open commands from platform definition
        if !self.platform.on_open_commands.is_empty() {
            debug!(
                "executing {} on-open commands",
                self.platform.on_open_commands.len()
            );
        }
        self.execute_on_open_commands().await?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        match self.state {
            SessionState::Ready => {
                debug!("closing connection");

                // Execute on_close commands while still Ready
                if self.channel.is_some() {
                    for cmd in &self.platform.on_close_commands.clone() {
                        let _ = self.send_command(cmd).await;
                    }
                }

                self.state = SessionState::Closing;

                // Signal graceful close
                if let Some(ref tx) = self.disconnect_tx {
                    tx.send_if_modified(|value| {
                        if value.is_none() {
                            *value = Some(DisconnectReason::Closed);
                            true
                        } else {
                            false
                        }
                    });
                }

                self.channel.take();

                if let Some(transport) = self.transport.take() {
                    transport.close().await?;
                }

                self.disconnect_tx.take();
                self.disconnect_rx.take();
                self.state = SessionState::Disconnected;
                self.connected_since = None;
                self.last_command_at = None;
            }
            SessionState::Dead => {
                debug!("cleaning up dead connection");
                self.channel.take();
                self.transport.take();
                self.disconnect_tx.take();
                self.disconnect_rx.take();
                self.state = SessionState::Disconnected;
                self.connected_since = None;
                self.last_command_at = None;
            }
            SessionState::Disconnected | SessionState::Closing => {}
        }
        Ok(())
    }

    async fn send_command(&mut self, command: &str) -> Result<Response> {
        self.check_ready()?;

        debug!("send_command: {:?}", command);

        let start = Instant::now();

        // Send the command
        let send_result = self
            .channel
            .as_mut()
            .ok_or(DriverError::NotConnected)?
            .send(command)
            .await;

        if let Err(e) = send_result {
            if Self::is_connection_error(&e) {
                self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
            }
            return Err(e);
        }

        // Wait for prompt
        let read_result = self
            .channel
            .as_mut()
            .ok_or(DriverError::NotConnected)?
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await;

        let mut data = match read_result {
            Ok(data) => data,
            Err(e) => {
                if Self::is_connection_error(&e) {
                    self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                }
                return Err(e);
            }
        };

        let elapsed = start.elapsed();

        // Extract prompt from the tail (small String, always cheap)
        let prompt = self.extract_prompt(&data);

        // Update current privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }

        // Normalize output in place
        if self.normalize {
            self.normalize_output_in_place(&mut data, command);
        }

        // Check for failure patterns (byte-level search, no string conversion)
        for pattern in &self.platform.failed_when_contains {
            if memchr::memmem::find(&data, pattern.as_bytes()).is_some() {
                debug!("send_command: completed in {:?}, success=false", elapsed);
                let payload = Payload::from_bytes_mut(data);
                return Ok(Response::failed(
                    command,
                    payload,
                    prompt,
                    elapsed,
                    pattern.clone(),
                ));
            }
        }

        self.last_command_at = Some(Instant::now());

        debug!("send_command: completed in {:?}, success=true", elapsed);
        let payload = Payload::from_bytes_mut(data);
        Ok(Response::new(command, payload, prompt, elapsed))
    }

    async fn acquire_privilege(&mut self, target: &str) -> Result<()> {
        self.check_ready()?;

        let current = self
            .privilege_manager
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        if current == target {
            return Ok(()); // Already at target
        }

        debug!("acquire_privilege: {} -> {}", current, target);

        // Find path from current to target
        let path = self.privilege_manager.find_path(&current, target)?;

        // Navigate the path
        for i in 0..path.len() - 1 {
            let from = &path[i];
            let to = &path[i + 1];

            let transition = self
                .privilege_manager
                .get_transition(from, to)
                .ok_or_else(|| DriverError::NoPrivilegePath {
                    from: from.clone(),
                    to: to.clone(),
                })?;

            debug!(
                "privilege transition: {} -> {} via {:?}",
                from, to, transition.command
            );

            // Send the transition command
            let send_result = self
                .channel
                .as_mut()
                .ok_or(DriverError::NotConnected)?
                .send(&transition.command)
                .await;

            if let Err(e) = send_result {
                if Self::is_connection_error(&e) {
                    self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                }
                return Err(e);
            }

            // Handle authentication if needed
            if let Some(ref auth_pattern) = transition.auth_prompt {
                // Wait for auth prompt
                let auth_result = self
                    .channel
                    .as_mut()
                    .ok_or(DriverError::NotConnected)?
                    .read_until_pattern(auth_pattern, self.timeout)
                    .await;

                if let Err(e) = auth_result {
                    if Self::is_connection_error(&e) {
                        self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                    }
                    return Err(e);
                }

                // Send password (from auth method)
                if let crate::transport::config::AuthMethod::Password(ref pwd) =
                    self.ssh_config.auth
                {
                    let pwd_result = self
                        .channel
                        .as_mut()
                        .ok_or(DriverError::NotConnected)?
                        .send(pwd)
                        .await;

                    if let Err(e) = pwd_result {
                        if Self::is_connection_error(&e) {
                            self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                        }
                        return Err(e);
                    }
                }
            }

            // Wait for new prompt
            let prompt_result = self.read_until_prompt().await;
            let (_, prompt) = match prompt_result {
                Ok(r) => r,
                Err(e) => {
                    if Self::is_connection_error(&e) {
                        self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                    }
                    return Err(e);
                }
            };

            // Verify we reached the expected privilege
            if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
                let level_name = level.name.clone();
                self.privilege_manager.set_current(&level_name)?;
                if level_name != *to {
                    return Err(
                        DriverError::PrivilegeAcquisitionFailed { target: to.clone() }.into(),
                    );
                }
            }
        }

        Ok(())
    }

    async fn send_interactive(&mut self, events: &[InteractiveEvent]) -> Result<InteractiveResult> {
        self.check_ready()?;

        let total_start = Instant::now();
        let mut steps = Vec::with_capacity(events.len());

        for event in events {
            let step_start = Instant::now();

            // Log the input (masked if hidden)
            let log_input = if event.hidden {
                "********".to_string()
            } else {
                event.input.clone()
            };
            debug!("send_interactive: sending '{}'", log_input);

            // Send input
            let send_result = self
                .channel
                .as_mut()
                .ok_or(DriverError::NotConnected)?
                .send(&event.input)
                .await;

            if let Err(e) = send_result {
                if Self::is_connection_error(&e) {
                    self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                }
                return Err(e);
            }

            // Read until expected pattern
            let timeout = event.timeout.unwrap_or(self.timeout);
            let read_result = self
                .channel
                .as_mut()
                .ok_or(DriverError::NotConnected)?
                .read_until_pattern(&event.pattern, timeout)
                .await;

            let mut data = match read_result {
                Ok(d) => d,
                Err(e) => {
                    if Self::is_connection_error(&e) {
                        self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                    }
                    return Err(e);
                }
            };

            let step_elapsed = step_start.elapsed();

            // Normalize output in place
            if self.normalize {
                self.normalize_output_in_place(&mut data, &event.input);
            }

            let output = Payload::from_bytes_mut(data);

            // Check for failure patterns
            let step = {
                let mut failed_step = None;
                for pattern in &self.platform.failed_when_contains {
                    if output.contains(pattern) {
                        failed_step = Some(InteractiveStep::failed(
                            log_input.clone(),
                            output.clone(),
                            step_elapsed,
                            pattern.clone(),
                        ));
                        break;
                    }
                }
                failed_step
                    .unwrap_or_else(|| InteractiveStep::success(log_input, output, step_elapsed))
            };

            steps.push(step);
        }

        // Update privilege level based on final output
        if let Some(last_step) = steps.last()
            && let Ok(level) = self
                .privilege_manager
                .determine_from_prompt(&last_step.output)
        {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }

        Ok(InteractiveResult::new(steps, total_start.elapsed()))
    }

    async fn send_config(&mut self, commands: &[&str]) -> Result<Vec<Response>> {
        debug!("send_config: {} commands", commands.len());

        // Save current privilege level
        let original_privilege = self.privilege_manager.current().map(|l| l.name.clone());

        // Find a configuration privilege level reachable from the current position.
        // For platforms with disconnected subgraphs (e.g., Nokia SROS with both
        // MD-CLI and Classic CLI), this ensures we pick the right config level.
        let config_privilege = if let Some(ref current_name) = original_privilege {
            self.platform
                .privilege_levels
                .keys()
                .filter(|name| name.to_lowercase().contains("config"))
                .find(|name| self.privilege_manager.find_path(current_name, name).is_ok())
                .cloned()
        } else {
            self.platform
                .privilege_levels
                .keys()
                .find(|name| name.to_lowercase().contains("config"))
                .cloned()
        };

        if let Some(config_priv) = config_privilege {
            // Acquire configuration privilege
            self.acquire_privilege(&config_priv).await?;

            // Send all commands
            let responses = self.send_commands(commands).await?;

            // Return to original privilege if we had one
            if let Some(original) = original_privilege
                && original != config_priv
            {
                self.acquire_privilege(&original).await?;
            }

            Ok(responses)
        } else {
            // No config privilege defined, just send commands as-is
            self.send_commands(commands).await
        }
    }

    fn is_open(&self) -> bool {
        self.state == SessionState::Ready
    }

    fn is_alive(&self) -> bool {
        self.state == SessionState::Ready && self.transport.as_ref().is_some_and(|t| t.is_alive())
    }

    fn current_privilege(&self) -> Option<&str> {
        self.privilege_manager.current().map(|l| l.name.as_str())
    }

    fn state(&self) -> SessionState {
        self.state
    }
}

// =============================================================================
// In-place normalization functions
// =============================================================================

/// Normalize line endings in place within a `BytesMut` buffer.
///
/// Converts `\r\n`, `\r\r\n`, `\n\r`, and standalone `\r` to `\n`.
/// Uses `memchr` for SIMD-accelerated scanning — regions without `\r`
/// are skipped at near-memcpy speed.
fn normalize_linefeeds_in_place(buf: &mut BytesMut) {
    // Fast path: no \r means nothing to do
    if memchr::memchr(b'\r', buf).is_none() {
        return;
    }

    let len = buf.len();
    let mut read = 0;
    let mut write = 0;

    while read < len {
        let b = buf[read];

        if b == b'\r' {
            // Consume all consecutive \r
            let mut cr_end = read + 1;
            while cr_end < len && buf[cr_end] == b'\r' {
                cr_end += 1;
            }

            if cr_end < len && buf[cr_end] == b'\n' {
                // \r+\n → \n
                buf[write] = b'\n';
                write += 1;
                read = cr_end + 1;
            } else {
                // standalone \r (no following \n) → \n
                buf[write] = b'\n';
                write += 1;
                read = cr_end;
            }
        } else if b == b'\n' && read + 1 < len && buf[read + 1] == b'\r' {
            // \n\r → \n
            buf[write] = b'\n';
            write += 1;
            read += 2;
        } else {
            if write != read {
                buf[write] = buf[read];
            }
            write += 1;
            read += 1;
        }
    }

    buf.truncate(write);
}

/// Strip the command echo from the beginning of the buffer.
///
/// If the first line matches the command, advance past it.
fn strip_echo_in_place(buf: &mut BytesMut, command: &str) {
    if buf.is_empty() {
        return;
    }

    if let Some(nl_pos) = memchr::memchr(b'\n', buf) {
        // Check if the first line equals the command
        if &buf[..nl_pos] == command.as_bytes() {
            let _ = buf.split_to(nl_pos + 1);
        }
    } else {
        // No newline — entire buffer is one "line"
        if &buf[..] == command.as_bytes() {
            buf.clear();
        }
    }
}

/// Strip the trailing prompt (last line) from the buffer.
///
/// Finds the last newline and truncates there.
fn strip_trailing_prompt_in_place(buf: &mut BytesMut) {
    if let Some(pos) = memchr::memrchr(b'\n', buf) {
        buf.truncate(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // normalize_linefeeds_in_place — unit tests
    // =========================================================================

    #[test]
    fn test_normalize_lf_passthrough() {
        let mut buf = BytesMut::from("a\nb\nc");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb\nc");
    }

    #[test]
    fn test_normalize_crlf() {
        let mut buf = BytesMut::from("a\r\nb\r\nc");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb\nc");
    }

    #[test]
    fn test_normalize_cr_only() {
        let mut buf = BytesMut::from("a\rb\rc");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb\nc");
    }

    #[test]
    fn test_normalize_mixed() {
        let mut buf = BytesMut::from("a\r\nb\nc\rd");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb\nc\nd");
    }

    #[test]
    fn test_normalize_double_cr_lf() {
        let mut buf = BytesMut::from("a\r\r\nb");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb");
    }

    #[test]
    fn test_normalize_lf_cr() {
        let mut buf = BytesMut::from("a\n\rb");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb");
    }

    #[test]
    fn test_normalize_empty() {
        let mut buf = BytesMut::new();
        normalize_linefeeds_in_place(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_normalize_no_linefeeds() {
        let mut buf = BytesMut::from("just plain text");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"just plain text");
    }

    #[test]
    fn test_normalize_only_cr() {
        let mut buf = BytesMut::from("\r");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"\n");
    }

    #[test]
    fn test_normalize_only_crlf() {
        let mut buf = BytesMut::from("\r\n");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"\n");
    }

    #[test]
    fn test_normalize_triple_cr_lf() {
        let mut buf = BytesMut::from("a\r\r\r\nb");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\nb");
    }

    #[test]
    fn test_normalize_cr_at_end() {
        let mut buf = BytesMut::from("text\r");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"text\n");
    }

    #[test]
    fn test_normalize_cr_at_start() {
        let mut buf = BytesMut::from("\rtext");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"\ntext");
    }

    #[test]
    fn test_normalize_consecutive_crlf() {
        let mut buf = BytesMut::from("a\r\n\r\nb");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\n\nb");
    }

    #[test]
    fn test_normalize_lf_cr_lf() {
        // \n\r\n → \n\n (\n\r becomes \n, then remaining \n stays)
        let mut buf = BytesMut::from("a\n\r\nb");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"a\n\nb");
    }

    #[test]
    fn test_normalize_preserves_length_when_no_cr() {
        let mut buf = BytesMut::from("no\ncr\nhere");
        let len_before = buf.len();
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(buf.len(), len_before);
    }

    #[test]
    fn test_normalize_shrinks_buffer() {
        let mut buf = BytesMut::from("a\r\nb\r\nc");
        let len_before = buf.len();
        normalize_linefeeds_in_place(&mut buf);
        assert!(buf.len() < len_before);
    }

    #[test]
    fn test_normalize_all_cr() {
        let mut buf = BytesMut::from("\r\r\r");
        normalize_linefeeds_in_place(&mut buf);
        // Three consecutive \r with no following \n → standalone \r → \n
        assert_eq!(&buf[..], b"\n");
    }

    #[test]
    fn test_normalize_alternating_cr_lf() {
        let mut buf = BytesMut::from("\r\n\r\n\r\n");
        normalize_linefeeds_in_place(&mut buf);
        assert_eq!(&buf[..], b"\n\n\n");
    }

    // =========================================================================
    // strip_echo_in_place — unit tests
    // =========================================================================

    #[test]
    fn test_strip_echo_matches() {
        let mut buf = BytesMut::from("ls -la\nfile1\nfile2");
        strip_echo_in_place(&mut buf, "ls -la");
        assert_eq!(&buf[..], b"file1\nfile2");
    }

    #[test]
    fn test_strip_echo_no_match() {
        let mut buf = BytesMut::from("different\nfile1\nfile2");
        strip_echo_in_place(&mut buf, "ls -la");
        assert_eq!(&buf[..], b"different\nfile1\nfile2");
    }

    #[test]
    fn test_strip_echo_partial_match() {
        let mut buf = BytesMut::from("ls -la /tmp\nfile1");
        strip_echo_in_place(&mut buf, "ls -la");
        assert_eq!(&buf[..], b"ls -la /tmp\nfile1");
    }

    #[test]
    fn test_strip_echo_empty_buffer() {
        let mut buf = BytesMut::new();
        strip_echo_in_place(&mut buf, "ls");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_strip_echo_no_newline_matches() {
        let mut buf = BytesMut::from("ls");
        strip_echo_in_place(&mut buf, "ls");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_strip_echo_no_newline_no_match() {
        let mut buf = BytesMut::from("pwd");
        strip_echo_in_place(&mut buf, "ls");
        assert_eq!(&buf[..], b"pwd");
    }

    #[test]
    fn test_strip_echo_only_newline_after_command() {
        let mut buf = BytesMut::from("ls\n");
        strip_echo_in_place(&mut buf, "ls");
        assert_eq!(&buf[..], b"");
    }

    #[test]
    fn test_strip_echo_command_is_prefix_of_first_line() {
        // "show" != "show version" — should NOT strip
        let mut buf = BytesMut::from("show version\noutput\nprompt");
        strip_echo_in_place(&mut buf, "show");
        assert_eq!(&buf[..], b"show version\noutput\nprompt");
    }

    #[test]
    fn test_strip_echo_empty_command() {
        // Empty command shouldn't strip the first line
        let mut buf = BytesMut::from("output\nprompt");
        strip_echo_in_place(&mut buf, "");
        assert_eq!(&buf[..], b"output\nprompt");
    }

    // =========================================================================
    // strip_trailing_prompt_in_place — unit tests
    // =========================================================================

    #[test]
    fn test_strip_trailing_prompt_normal() {
        let mut buf = BytesMut::from("output\nrouter>");
        strip_trailing_prompt_in_place(&mut buf);
        assert_eq!(&buf[..], b"output");
    }

    #[test]
    fn test_strip_trailing_prompt_multiline() {
        let mut buf = BytesMut::from("line1\nline2\nline3\nrouter>");
        strip_trailing_prompt_in_place(&mut buf);
        assert_eq!(&buf[..], b"line1\nline2\nline3");
    }

    #[test]
    fn test_strip_trailing_prompt_no_newline() {
        let mut buf = BytesMut::from("no newline");
        strip_trailing_prompt_in_place(&mut buf);
        // No newline → nothing to strip
        assert_eq!(&buf[..], b"no newline");
    }

    #[test]
    fn test_strip_trailing_prompt_empty() {
        let mut buf = BytesMut::new();
        strip_trailing_prompt_in_place(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_strip_trailing_prompt_only_newline() {
        let mut buf = BytesMut::from("\n");
        strip_trailing_prompt_in_place(&mut buf);
        assert_eq!(&buf[..], b"");
    }

    #[test]
    fn test_strip_trailing_prompt_trailing_newline_content() {
        let mut buf = BytesMut::from("output\nprompt with spaces ");
        strip_trailing_prompt_in_place(&mut buf);
        assert_eq!(&buf[..], b"output");
    }

    // =========================================================================
    // Full pipeline (normalize_and_strip helper)
    // =========================================================================

    fn normalize_and_strip(raw: &str, command: &str) -> String {
        let mut buf = BytesMut::from(raw);
        normalize_linefeeds_in_place(&mut buf);
        strip_echo_in_place(&mut buf, command);
        // Trim leading newlines
        let leading = buf.iter().take_while(|&&b| b == b'\n').count();
        if leading > 0 {
            let _ = buf.split_to(leading);
        }
        strip_trailing_prompt_in_place(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn test_strip_echo_lf() {
        assert_eq!(
            normalize_and_strip("ls -la\nfile1\nfile2\nuser@host:~$ ", "ls -la"),
            "file1\nfile2"
        );
    }

    #[test]
    fn test_strip_echo_crlf() {
        assert_eq!(
            normalize_and_strip("ls -la\r\nfile1\r\nfile2\r\nuser@host:~$ ", "ls -la"),
            "file1\nfile2"
        );
    }

    #[test]
    fn test_no_echo_present() {
        assert_eq!(
            normalize_and_strip("file1\nfile2\nuser@host:~$ ", "ls -la"),
            "file1\nfile2"
        );
    }

    #[test]
    fn test_echo_partial_match_not_stripped() {
        assert_eq!(
            normalize_and_strip("ls -la /tmp\nfile1\nuser@host:~$ ", "ls -la"),
            "ls -la /tmp\nfile1"
        );
    }

    #[test]
    fn test_strip_linux_prompt() {
        assert_eq!(
            normalize_and_strip("show version\nJUNOS 21.4R1\nuser@router> ", "show version"),
            "JUNOS 21.4R1"
        );
    }

    #[test]
    fn test_strip_prompt_with_crlf() {
        assert_eq!(
            normalize_and_strip("pwd\r\n/home/user\r\nuser@host:~$ ", "pwd"),
            "/home/user"
        );
    }

    #[test]
    fn test_single_line_output() {
        assert_eq!(
            normalize_and_strip("whoami\nroot\nuser@host:~$ ", "whoami"),
            "root"
        );
    }

    #[test]
    fn test_no_newline_at_all() {
        assert_eq!(normalize_and_strip("ls", "ls"), "");
    }

    #[test]
    fn test_only_prompt_after_echo() {
        assert_eq!(
            normalize_and_strip("ls\nuser@host:~$ ", "ls"),
            "user@host:~$ "
        );
    }

    #[test]
    fn test_multiline_output() {
        assert_eq!(
            normalize_and_strip(
                "uname -a\nLinux host 6.1.0 #1 SMP x86_64 GNU/Linux\n[user@host ~]$ ",
                "uname -a"
            ),
            "Linux host 6.1.0 #1 SMP x86_64 GNU/Linux"
        );
    }

    #[test]
    fn test_large_output() {
        let mut raw = String::from("show route\n");
        for i in 0..100 {
            raw.push_str(&format!("10.0.{}.0/24 via 192.168.1.1\n", i));
        }
        raw.push_str("router> ");

        let result = normalize_and_strip(&raw, "show route");
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 100);
        assert_eq!(lines[0], "10.0.0.0/24 via 192.168.1.1");
        assert_eq!(lines[99], "10.0.99.0/24 via 192.168.1.1");
    }

    // =========================================================================
    // Real-world PTY output patterns
    // =========================================================================

    #[test]
    fn test_real_linux_pwd() {
        assert_eq!(
            normalize_and_strip("pwd\n/home/fabioswartz\n[fabioswartz@voidstar ~]$ ", "pwd"),
            "/home/fabioswartz"
        );
    }

    #[test]
    fn test_real_linux_whoami() {
        assert_eq!(
            normalize_and_strip("whoami\nfabioswartz\n[fabioswartz@voidstar ~]$ ", "whoami"),
            "fabioswartz"
        );
    }

    #[test]
    fn test_real_linux_uname() {
        assert_eq!(
            normalize_and_strip(
                "uname -a\nLinux voidstar 6.18.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 02 Jan 2026 17:52:55 +0000 x86_64 GNU/Linux\n[fabioswartz@voidstar ~]$ ",
                "uname -a"
            ),
            "Linux voidstar 6.18.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 02 Jan 2026 17:52:55 +0000 x86_64 GNU/Linux"
        );
    }

    #[test]
    fn test_juniper_show_version() {
        assert_eq!(
            normalize_and_strip(
                "show version\nHostname: router1\nModel: mx240\nJunos: 21.4R3-S5\nuser@router1> ",
                "show version"
            ),
            "Hostname: router1\nModel: mx240\nJunos: 21.4R3-S5"
        );
    }

    #[test]
    fn test_network_device_crlf() {
        assert_eq!(
            normalize_and_strip(
                "show interfaces terse\r\nge-0/0/0  up  up\r\nge-0/0/1  up  down\r\nuser@router> ",
                "show interfaces terse"
            ),
            "ge-0/0/0  up  up\nge-0/0/1  up  down"
        );
    }

    #[test]
    fn test_network_device_double_cr() {
        assert_eq!(
            normalize_and_strip(
                "show version\r\r\nJUNOS 21.4R1\r\r\nuser@router> ",
                "show version"
            ),
            "JUNOS 21.4R1"
        );
    }

    // =========================================================================
    // End-to-end pipeline → Payload
    // =========================================================================

    fn pipeline_to_payload(raw: &str, command: &str) -> Payload {
        let mut buf = BytesMut::from(raw);
        normalize_linefeeds_in_place(&mut buf);
        strip_echo_in_place(&mut buf, command);
        let leading = buf.iter().take_while(|&&b| b == b'\n').count();
        if leading > 0 {
            let _ = buf.split_to(leading);
        }
        strip_trailing_prompt_in_place(&mut buf);
        Payload::from_bytes_mut(buf)
    }

    #[test]
    fn test_pipeline_basic() {
        let payload =
            pipeline_to_payload("show version\nJunos: 21.4R1\nuser@router> ", "show version");
        assert_eq!(&*payload, "Junos: 21.4R1");
        assert!(payload.contains("21.4R1"));
        assert_eq!(payload.lines().count(), 1);
    }

    #[test]
    fn test_pipeline_crlf() {
        let payload = pipeline_to_payload("pwd\r\n/home/user\r\nhost:~$ ", "pwd");
        assert_eq!(&*payload, "/home/user");
    }

    #[test]
    fn test_pipeline_multiline() {
        let payload = pipeline_to_payload(
            "show route\n10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\nrouter> ",
            "show route",
        );
        assert_eq!(payload.lines().count(), 3);
        assert!(payload.contains("10.0.1.0/24"));
    }

    #[test]
    fn test_pipeline_payload_clone_is_zero_copy() {
        let payload = pipeline_to_payload("cmd\noutput data here\nprompt> ", "cmd");
        let cloned = payload.clone();
        assert_eq!(payload.as_bytes().as_ptr(), cloned.as_bytes().as_ptr());
    }

    #[test]
    fn test_pipeline_payload_display() {
        let payload = pipeline_to_payload("echo hi\nhello world\nuser$ ", "echo hi");
        assert_eq!(format!("{}", payload), "hello world");
    }

    #[test]
    fn test_pipeline_empty_output() {
        // Command that produces no output (just echo + prompt)
        let payload = pipeline_to_payload(
            "set cli screen-length 0\nrouter> ",
            "set cli screen-length 0",
        );
        assert_eq!(&*payload, "router> ");
    }

    #[test]
    fn test_pipeline_large_output() {
        let mut raw = String::from("show bgp\n");
        for i in 0..1000 {
            raw.push_str(&format!("192.168.{}.{}/32 Active\n", i / 256, i % 256));
        }
        raw.push_str("router# ");
        let payload = pipeline_to_payload(&raw, "show bgp");
        assert_eq!(payload.lines().count(), 1000);
    }

    #[test]
    fn test_pipeline_to_response() {
        let payload =
            pipeline_to_payload("show version\nHostname: router1\nrouter> ", "show version");
        let resp = Response::new(
            "show version",
            payload,
            "router>",
            Duration::from_millis(50),
        );
        assert!(resp.is_success());
        assert!(resp.contains("router1"));
        assert_eq!(resp.lines().count(), 1);
        assert_eq!(format!("{}", resp), "Hostname: router1");
    }

    #[test]
    fn test_pipeline_failed_response() {
        let payload = pipeline_to_payload(
            "bad cmd\nsyntax error: unknown command\nrouter> ",
            "bad cmd",
        );
        let resp = Response::failed(
            "bad cmd",
            payload,
            "router>",
            Duration::from_millis(30),
            "syntax error",
        );
        assert!(!resp.is_success());
        assert!(resp.contains("syntax error"));
    }
}
