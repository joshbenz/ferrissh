//! PTY channel for command execution on a single SSH shell.
//!
//! A [`Channel`] represents one interactive PTY shell on an SSH connection.
//! It handles command execution, privilege navigation, output normalization,
//! and disconnect detection.
//!
//! Channels are created via [`Session::open_channel()`](crate::Session::open_channel)
//! or [`GenericDriver::open_channel()`](super::GenericDriver::open_channel).

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use regex::bytes::Regex;
use tokio::sync::watch;

use secrecy::{ExposeSecret, SecretString};

use super::config_session::GenericConfigSession;
use super::interactive::{InteractiveEvent, InteractiveResult, InteractiveStep};
use super::payload::Payload;
use super::privilege::PrivilegeManager;
use super::response::Response;
use super::stream::{CommandStream, StreamConfig};
use crate::channel::PtyChannel;
use crate::error::{ChannelError, DisconnectReason, DriverError, Error, Result, TransportError};
use crate::platform::PlatformDefinition;
use crate::session::Session;
use log::{debug, trace, warn};

/// Fallback prompt pattern used when the combined platform pattern fails to compile.
pub(crate) static FALLBACK_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[$#>]\s*$").expect("hardcoded fallback regex must compile"));

/// The state of a channel's PTY shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Connected and ready for commands.
    Ready,
    /// Graceful close in progress.
    Closing,
    /// Channel died (transport error or server disconnect).
    Dead,
}

/// A single PTY shell channel on an SSH session.
///
/// Each channel has its own interactive shell, privilege state, and pattern
/// buffer. Commands are sent via `&mut self` — one task per channel.
///
/// Created via [`Session::open_channel()`](crate::Session::open_channel)
/// or [`GenericDriver::open_channel()`](super::GenericDriver::open_channel).
pub struct Channel {
    /// The session this channel belongs to.
    session: Session,

    /// The PTY channel for I/O.
    pty: PtyChannel,

    /// Privilege level manager (per-channel state).
    privilege_manager: PrivilegeManager,

    /// Default timeout for operations.
    timeout: Duration,

    /// Combined prompt pattern (can diverge from session for dynamic levels).
    prompt_pattern: Regex,

    /// Whether to normalize command output.
    normalize: bool,

    /// Current channel state.
    state: ChannelState,

    /// Receiver for disconnect notifications.
    disconnect_rx: watch::Receiver<Option<DisconnectReason>>,

    /// When the last command completed successfully.
    last_command_at: Option<Instant>,

    /// True while a `CommandStream` is active and hasn't been drained.
    stream_dirty: bool,

    /// Password for privilege escalation (extracted from auth config).
    auth_password: Option<SecretString>,
}

impl Channel {
    /// Create a new channel (called by Session::open_channel).
    pub(crate) fn new(
        session: Session,
        pty: PtyChannel,
        timeout: Duration,
        prompt_pattern: Regex,
        normalize: bool,
        disconnect_rx: watch::Receiver<Option<DisconnectReason>>,
        auth_password: Option<SecretString>,
    ) -> Self {
        let privilege_manager = PrivilegeManager::new(session.platform().privilege_levels.clone());

        Self {
            session,
            pty,
            privilege_manager,
            timeout,
            prompt_pattern,
            normalize,
            state: ChannelState::Ready,
            disconnect_rx,
            last_command_at: None,
            stream_dirty: false,
            auth_password,
        }
    }

    /// Initialize the channel after creation.
    ///
    /// Waits for the initial prompt, determines the privilege level,
    /// and executes on_open commands.
    pub(crate) async fn initialize(&mut self) -> Result<()> {
        // Wait for initial prompt
        let (_data, prompt) = self.read_until_prompt().await?;

        // Determine initial privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            self.privilege_manager.set_current(&level_name)?;
            debug!("initial privilege level: {:?}", level_name);
        }

        // Execute on_open commands
        let on_open = self.session.platform().on_open_commands.clone();
        if !on_open.is_empty() {
            debug!("executing {} on-open commands", on_open.len());
        }
        for cmd in &on_open {
            self.send_command(cmd).await?;
        }

        Ok(())
    }

    /// Send a command and wait for the prompt.
    pub async fn send_command(&mut self, command: &str) -> Result<Response> {
        self.check_ready()?;

        debug!("send_command: {:?}", command);

        let start = Instant::now();

        // Send the command
        let send_result = self.pty.send(command).await;

        if let Err(e) = send_result {
            if Self::is_connection_error(&e) {
                self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
            }
            return Err(e);
        }

        // Wait for prompt
        let read_result = self
            .pty
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

        // Extract prompt from the tail
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

        // Check for failure patterns
        for pattern in &self.session.platform().failed_when_contains {
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

    /// Send multiple commands sequentially.
    pub async fn send_commands(&mut self, commands: &[&str]) -> Result<Vec<Response>> {
        let mut responses = Vec::with_capacity(commands.len());
        for cmd in commands {
            responses.push(self.send_command(cmd).await?);
        }
        Ok(responses)
    }

    /// Send a command and return a streaming iterator over output chunks.
    ///
    /// Unlike [`send_command()`](Self::send_command), this returns a
    /// [`CommandStream`] that yields normalized output incrementally as it
    /// arrives from the device. Useful for large outputs where callers want
    /// to process data before the entire response is received.
    ///
    /// The returned `CommandStream` borrows `&mut self`, preventing concurrent
    /// channel use until the stream is dropped.
    ///
    /// # Important
    ///
    /// Callers **must** drive the stream to completion (until
    /// [`next_chunk()`](CommandStream::next_chunk) returns `Ok(None)`) before
    /// issuing further commands. Dropping the stream before the prompt is
    /// detected leaves unread data on the channel and will cause subsequent
    /// commands to fail with [`DriverError::StreamNotDrained`].
    pub async fn send_command_stream(&mut self, command: &str) -> Result<CommandStream<'_>> {
        self.check_ready()?;
        debug!("send_command_stream: {:?}", command);

        let start = Instant::now();

        // Send the command
        let send_result = self.pty.send(command).await;
        if let Err(e) = send_result {
            if Self::is_connection_error(&e) {
                self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
            }
            return Err(e);
        }

        let config = StreamConfig {
            prompt_pattern: self.prompt_pattern.clone(),
            search_depth: self.pty.search_depth(),
            timeout: self.timeout,
            normalize: self.normalize,
            processor: self
                .session
                .platform()
                .behavior
                .as_ref()
                .and_then(|b| b.stream_processor()),
            failed_when_contains: self.session.platform().failed_when_contains.clone(),
        };

        self.stream_dirty = true;
        Ok(CommandStream::new(self, command, config, start))
    }

    /// Acquire a specific privilege level.
    pub async fn acquire_privilege(&mut self, target: &str) -> Result<()> {
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
            let send_result = self.pty.send(&transition.command).await;

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
                    .pty
                    .read_until_pattern(auth_pattern, self.timeout)
                    .await;

                if let Err(e) = auth_result {
                    if Self::is_connection_error(&e) {
                        self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                    }
                    return Err(e);
                }

                // Send password
                if let Some(ref pwd) = self.auth_password {
                    let pwd_result = self.pty.send(pwd.expose_secret()).await;

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
            match self.privilege_manager.determine_from_prompt(&prompt) {
                Ok(level) => {
                    let level_name = level.name.clone();
                    self.privilege_manager.set_current(&level_name)?;
                    if level_name != *to {
                        return Err(
                            DriverError::PrivilegeAcquisitionFailed { target: to.clone() }.into(),
                        );
                    }
                }
                Err(_) => {
                    warn!(
                        "privilege transition {} -> {}: could not determine privilege from prompt, state may be inconsistent",
                        from, to
                    );
                    return Err(
                        DriverError::PrivilegeAcquisitionFailed { target: to.clone() }.into(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Send an interactive command sequence.
    pub async fn send_interactive(
        &mut self,
        events: &[InteractiveEvent],
    ) -> Result<InteractiveResult> {
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
            let send_result = self.pty.send(&event.input).await;

            if let Err(e) = send_result {
                if Self::is_connection_error(&e) {
                    self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                }
                return Err(e);
            }

            // Read until expected pattern
            let timeout = event.timeout.unwrap_or(self.timeout);
            let read_result = self.pty.read_until_pattern(&event.pattern, timeout).await;

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
                for pattern in &self.session.platform().failed_when_contains {
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

    /// Send commands in configuration mode.
    pub async fn send_config(&mut self, commands: &[&str]) -> Result<Vec<Response>> {
        debug!("send_config: {} commands", commands.len());

        // Save current privilege level
        let original_privilege = self.privilege_manager.current().map(|l| l.name.clone());

        // Find a configuration privilege level reachable from the current position.
        let config_privilege = if let Some(ref current_name) = original_privilege {
            self.session
                .platform()
                .privilege_levels
                .keys()
                .filter(|name| name.to_lowercase().contains("config"))
                .find(|name| self.privilege_manager.find_path(current_name, name).is_ok())
                .cloned()
        } else {
            self.session
                .platform()
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

    /// Enter a generic configuration session.
    pub async fn config_session(&mut self) -> Result<GenericConfigSession<'_>> {
        GenericConfigSession::new(self).await
    }

    /// Check if the channel is connected and ready.
    pub fn is_open(&self) -> bool {
        self.state == ChannelState::Ready
    }

    /// Check if the channel's session is still alive.
    pub fn is_alive(&self) -> bool {
        self.state == ChannelState::Ready && self.session.is_alive()
    }

    /// Get the current privilege level name.
    pub fn current_privilege(&self) -> Option<&str> {
        self.privilege_manager.current().map(|l| l.name.as_str())
    }

    /// Get the channel state.
    pub fn channel_state(&self) -> ChannelState {
        self.state
    }

    /// Get the session this channel belongs to.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get the platform definition.
    pub fn platform(&self) -> &PlatformDefinition {
        self.session.platform()
    }

    /// Get the privilege manager.
    pub fn privilege_manager(&self) -> &PrivilegeManager {
        &self.privilege_manager
    }

    /// Get a mutable reference to the privilege manager.
    pub fn privilege_manager_mut(&mut self) -> &mut PrivilegeManager {
        &mut self.privilege_manager
    }

    /// Get the current prompt pattern.
    pub fn prompt_pattern(&self) -> &Regex {
        &self.prompt_pattern
    }

    /// Set the default timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set whether command output is normalized.
    pub fn set_normalize(&mut self, normalize: bool) {
        self.normalize = normalize;
    }

    /// When the last command completed successfully.
    pub fn last_command_at(&self) -> Option<Instant> {
        self.last_command_at
    }

    /// Rebuild the combined prompt pattern from current privilege levels.
    pub fn rebuild_prompt_pattern(&mut self) {
        let patterns: Vec<String> = self
            .privilege_manager
            .levels()
            .values()
            .map(|level| format!("(?:{})", level.pattern.as_str()))
            .collect();

        let combined = patterns.join("|");
        self.prompt_pattern = Regex::new(&combined).unwrap_or_else(|_| FALLBACK_PROMPT.clone());
    }

    /// Close this channel.
    ///
    /// Runs on_close commands and drops the PTY. Does NOT close the session.
    pub async fn close(&mut self) -> Result<()> {
        if self.state != ChannelState::Ready {
            return Ok(());
        }

        debug!("closing channel");
        self.state = ChannelState::Closing;

        // Execute on_close commands (best-effort via PTY, since check_ready requires Ready)
        let on_close = self.session.platform().on_close_commands.clone();
        for cmd in &on_close {
            if let Err(e) = self.pty.send(cmd).await {
                warn!("on_close command {:?} failed to send: {}", cmd, e);
                break;
            }
            // Best-effort wait for prompt
            if let Err(e) = self
                .pty
                .read_until_pattern(&self.prompt_pattern, self.timeout)
                .await
            {
                warn!("on_close command {:?} failed to complete: {}", cmd, e);
                break;
            }
        }

        self.state = ChannelState::Dead;

        Ok(())
    }

    // =========================================================================
    // Internal methods
    // =========================================================================

    /// Get a mutable reference to the PTY channel.
    ///
    /// Used by [`CommandStream`] to call `read_chunk()`.
    pub(crate) fn pty(&mut self) -> &mut PtyChannel {
        &mut self.pty
    }

    /// Update the current privilege level from a prompt string.
    ///
    /// Used by [`CommandStream`] when it detects the final prompt.
    pub(crate) fn update_privilege_from_prompt(&mut self, prompt: &str) {
        if let Ok(level) = self.privilege_manager.determine_from_prompt(prompt) {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }
    }

    /// Record that a command completed successfully.
    ///
    /// Used by [`CommandStream`] when the stream finishes.
    pub(crate) fn mark_command_complete(&mut self) {
        self.last_command_at = Some(Instant::now());
        self.stream_dirty = false;
    }

    /// If `e` indicates a dead connection, transition to `Dead` state and
    /// signal the disconnect watch.
    ///
    /// Used by [`CommandStream`] to mirror the error handling in
    /// [`send_command()`](Self::send_command).
    pub(crate) fn handle_error(&mut self, e: &Error) {
        if Self::is_connection_error(e) {
            self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
        }
    }

    /// Check that the channel is in `Ready` state.
    fn check_ready(&mut self) -> Result<()> {
        if self.state != ChannelState::Ready {
            return Err(DriverError::NotConnected.into());
        }

        if self.stream_dirty {
            return Err(DriverError::StreamNotDrained.into());
        }

        // Non-blocking check for async disconnect
        match self.disconnect_rx.has_changed() {
            Ok(true) => {
                let reason = self.disconnect_rx.borrow_and_update().clone();
                if let Some(reason) = reason {
                    self.handle_disconnect(reason);
                    return Err(DriverError::NotConnected.into());
                }
            }
            Err(_) => {
                // Sender dropped — connection is gone
                self.handle_disconnect(DisconnectReason::TransportError("connection lost".into()));
                return Err(DriverError::NotConnected.into());
            }
            _ => {}
        }

        Ok(())
    }

    /// Extract the prompt string from the tail of a raw byte buffer.
    fn extract_prompt(&self, data: &[u8]) -> String {
        let search_depth = self.pty.search_depth();
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
        let data = self
            .pty
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let prompt = self.extract_prompt(&data);

        Ok((data, prompt))
    }

    /// Normalize output in place on a `BytesMut` buffer.
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
        if let Some(ref behavior) = self.session.platform().behavior {
            behavior.post_process_output(buf);
        }

        debug!("normalize_output: result_len={}", buf.len());
    }

    /// Transition to `Dead` state on connection loss.
    fn handle_disconnect(&mut self, reason: DisconnectReason) {
        debug!("handle_disconnect: {:?}", reason);
        self.state = ChannelState::Dead;
        if let Some(tx) = Arc::into_inner(self.session.disconnect_tx().clone()) {
            // We're the last holder — signal disconnect
            tx.send_if_modified(|value| {
                if value.is_none() {
                    *value = Some(reason);
                    true
                } else {
                    false
                }
            });
        } else {
            // Other holders exist — try to signal via the shared sender
            self.session.disconnect_tx().send_if_modified(|value| {
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
}

impl Drop for Channel {
    fn drop(&mut self) {
        if self.state == ChannelState::Ready {
            warn!("Channel dropped while still connected — call close() first");
        }
    }
}

// =============================================================================
// In-place normalization functions
// =============================================================================

/// Normalize line endings in place within a `BytesMut` buffer.
///
/// Converts `\r\n`, `\r\r\n`, `\n\r`, and standalone `\r` to `\n`.
/// Uses `memchr` for SIMD-accelerated scanning.
pub(crate) fn normalize_linefeeds_in_place(buf: &mut BytesMut) {
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
pub(crate) fn strip_echo_in_place(buf: &mut BytesMut, command: &str) {
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
pub(crate) fn strip_trailing_prompt_in_place(buf: &mut BytesMut) {
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
        let mut buf = BytesMut::from("show version\noutput\nprompt");
        strip_echo_in_place(&mut buf, "show");
        assert_eq!(&buf[..], b"show version\noutput\nprompt");
    }

    #[test]
    fn test_strip_echo_empty_command() {
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
    fn test_fallback_prompt_compiles() {
        // Verify the LazyLock FALLBACK_PROMPT can be accessed without panic
        let _ = FALLBACK_PROMPT.clone();
        assert!(FALLBACK_PROMPT.is_match(b"router# "));
        assert!(FALLBACK_PROMPT.is_match(b"user$ "));
        assert!(FALLBACK_PROMPT.is_match(b"switch> "));
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
