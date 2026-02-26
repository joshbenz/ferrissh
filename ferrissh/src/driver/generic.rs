//! Generic driver implementation that works with any platform.

use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex as TextRegex;
use regex::bytes::Regex;
use tokio::sync::watch;

use super::Driver;
use super::SessionState;
use super::config_session::GenericConfigSession;
use super::interactive::{InteractiveEvent, InteractiveResult, InteractiveStep};
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

    /// Read until the prompt is matched, then determine current privilege.
    async fn read_until_prompt(&mut self) -> Result<(String, String)> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

        let data = channel
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let output = String::from_utf8_lossy(&data).to_string();

        // Find the prompt at the end (search only the tail, not the full buffer)
        let search_depth = self
            .channel
            .as_ref()
            .map(|c| c.search_depth())
            .unwrap_or(1000);
        let tail_start = data.len().saturating_sub(search_depth);
        let tail = &data[tail_start..];
        let prompt = if let Some(m) = self.prompt_pattern.find(tail) {
            let matched = String::from_utf8_lossy(&tail[m.start()..]).to_string();
            trace!(
                "prompt matched: {:?} (from {} bytes of output)",
                matched,
                data.len()
            );
            matched
        } else {
            trace!(
                "no prompt match in {} bytes of output (tail: {:?})",
                data.len(),
                String::from_utf8_lossy(tail)
            );
            String::new()
        };

        Ok((output, prompt))
    }

    /// Universal output normalization: strip command echo and trailing prompt.
    ///
    /// Then apply vendor-specific post-processing if a behavior is set.
    fn normalize_output(&self, raw: &str, command: &str) -> String {
        let result = strip_echo_and_prompt(raw, command);

        // Apply vendor-specific post-processing if present
        if let Some(ref behavior) = self.platform.behavior {
            behavior.post_process_output(&result)
        } else {
            result
        }
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
        let (_, prompt) = self.read_until_prompt().await?;

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

        let data = match read_result {
            Ok(data) => data,
            Err(e) => {
                if Self::is_connection_error(&e) {
                    self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                }
                return Err(e);
            }
        };

        let elapsed = start.elapsed();
        let raw_result = String::from_utf8_lossy(&data).to_string();

        // Find the prompt (search only the tail, not the full buffer)
        let search_depth = self
            .channel
            .as_ref()
            .map(|c| c.search_depth())
            .unwrap_or(1000);
        let tail_start = data.len().saturating_sub(search_depth);
        let tail = &data[tail_start..];
        let prompt = if let Some(m) = self.prompt_pattern.find(tail) {
            let matched = String::from_utf8_lossy(&tail[m.start()..])
                .trim()
                .to_string();
            trace!("send_command prompt matched: {:?}", matched);
            matched
        } else {
            trace!(
                "send_command: no prompt match in tail ({} bytes)",
                tail.len()
            );
            String::new()
        };

        // Update current privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }

        // Normalize output (strip echo + prompt, then vendor post-processing)
        let result = if self.normalize {
            self.normalize_output(&raw_result, command)
        } else {
            raw_result.clone()
        };

        // Check for failure patterns
        for pattern in &self.platform.failed_when_contains {
            if result.contains(pattern) {
                debug!("send_command: completed in {:?}, success=false", elapsed);
                return Ok(Response::failed(
                    command,
                    result.clone(),
                    raw_result,
                    prompt,
                    elapsed,
                    pattern.clone(),
                ));
            }
        }

        self.last_command_at = Some(Instant::now());

        debug!("send_command: completed in {:?}, success=true", elapsed);
        Ok(Response::new(command, result, raw_result, prompt, elapsed))
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

            let data = match read_result {
                Ok(d) => d,
                Err(e) => {
                    if Self::is_connection_error(&e) {
                        self.handle_disconnect(DisconnectReason::TransportError(e.to_string()));
                    }
                    return Err(e);
                }
            };

            let step_elapsed = step_start.elapsed();
            let raw_output = String::from_utf8_lossy(&data).to_string();

            // Normalize output (strip echo + prompt, then vendor post-processing)
            let output = if self.normalize {
                self.normalize_output(&raw_output, &event.input)
            } else {
                raw_output.clone()
            };

            // Check for failure patterns
            let step = {
                let mut failed_step = None;
                for pattern in &self.platform.failed_when_contains {
                    if output.contains(pattern) {
                        failed_step = Some(InteractiveStep::failed(
                            log_input.clone(),
                            output.clone(),
                            raw_output.clone(),
                            step_elapsed,
                            pattern.clone(),
                        ));
                        break;
                    }
                }
                failed_step.unwrap_or_else(|| {
                    InteractiveStep::success(log_input, output, raw_output, step_elapsed)
                })
            };

            steps.push(step);
        }

        // Update privilege level based on final output
        if let Some(last_step) = steps.last()
            && let Ok(level) = self
                .privilege_manager
                .determine_from_prompt(&last_step.raw_output)
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

/// Normalize line endings in raw PTY output.
///
/// Converts `\r\n`, `\r\r\n`, `\n\r`, and standalone `\r` to `\n`.
/// This matches the behavior of Python's netmiko and scrapli.
fn normalize_linefeeds(raw: &str) -> String {
    // Match any \r+\n, \n\r, or standalone \r and replace with \n
    static RE: std::sync::LazyLock<TextRegex> =
        std::sync::LazyLock::new(|| TextRegex::new(r"\r+\n|\n\r|\r").unwrap());
    RE.replace_all(raw, "\n").into_owned()
}

/// Strip command echo and trailing prompt from raw PTY output.
///
/// This handles the universal normalization that applies to all platforms:
/// 1. Normalize line endings (\r\n, \r → \n)
/// 2. Remove the command echo (first line if it matches the command)
/// 3. Remove the trailing prompt (last line)
fn strip_echo_and_prompt(raw: &str, command: &str) -> String {
    debug!("normalize_output: raw={:?}, command={:?}", raw, command);

    // Normalize all line endings to \n
    let normalized = normalize_linefeeds(raw);

    // Strip command echo from the beginning.
    let output = if let Some(pos) = normalized.find('\n') {
        if &normalized[..pos] == command {
            &normalized[pos + 1..]
        } else {
            &normalized[..]
        }
    } else {
        normalized.strip_prefix(command).unwrap_or(&normalized)
    };
    let output = output.trim_start_matches('\n');

    // Strip trailing prompt (last line)
    let stripped = if let Some(pos) = output.rfind('\n') {
        &output[..pos]
    } else {
        output
    };

    debug!("normalize_output: result={:?}", stripped);
    stripped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Linefeed normalization
    // =========================================================================

    #[test]
    fn test_normalize_lf_passthrough() {
        assert_eq!(normalize_linefeeds("a\nb\nc"), "a\nb\nc");
    }

    #[test]
    fn test_normalize_crlf() {
        assert_eq!(normalize_linefeeds("a\r\nb\r\nc"), "a\nb\nc");
    }

    #[test]
    fn test_normalize_cr_only() {
        assert_eq!(normalize_linefeeds("a\rb\rc"), "a\nb\nc");
    }

    #[test]
    fn test_normalize_mixed() {
        assert_eq!(normalize_linefeeds("a\r\nb\nc\rd"), "a\nb\nc\nd");
    }

    #[test]
    fn test_normalize_double_cr_lf() {
        // Some devices send \r\r\n
        assert_eq!(normalize_linefeeds("a\r\r\nb"), "a\nb");
    }

    #[test]
    fn test_normalize_lf_cr() {
        assert_eq!(normalize_linefeeds("a\n\rb"), "a\nb");
    }

    // =========================================================================
    // Echo stripping
    // =========================================================================

    #[test]
    fn test_strip_echo_lf() {
        let raw = "ls -la\nfile1\nfile2\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "ls -la"), "file1\nfile2");
    }

    #[test]
    fn test_strip_echo_crlf() {
        let raw = "ls -la\r\nfile1\r\nfile2\r\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "ls -la"), "file1\nfile2");
    }

    #[test]
    fn test_no_echo_present() {
        let raw = "file1\nfile2\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "ls -la"), "file1\nfile2");
    }

    #[test]
    fn test_echo_partial_match_not_stripped() {
        let raw = "ls -la /tmp\nfile1\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "ls -la"), "ls -la /tmp\nfile1");
    }

    // =========================================================================
    // Prompt stripping
    // =========================================================================

    #[test]
    fn test_strip_linux_prompt() {
        let raw = "show version\nJUNOS 21.4R1\nuser@router> ";
        assert_eq!(strip_echo_and_prompt(raw, "show version"), "JUNOS 21.4R1");
    }

    #[test]
    fn test_strip_prompt_with_crlf() {
        let raw = "pwd\r\n/home/user\r\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "pwd"), "/home/user");
    }

    // =========================================================================
    // Single-line output
    // =========================================================================

    #[test]
    fn test_single_line_output() {
        let raw = "whoami\nroot\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "whoami"), "root");
    }

    #[test]
    fn test_no_newline_at_all() {
        let raw = "ls";
        assert_eq!(strip_echo_and_prompt(raw, "ls"), "");
    }

    #[test]
    fn test_only_prompt_after_echo() {
        let raw = "ls\nuser@host:~$ ";
        assert_eq!(strip_echo_and_prompt(raw, "ls"), "user@host:~$ ");
    }

    // =========================================================================
    // Multi-line output
    // =========================================================================

    #[test]
    fn test_multiline_output() {
        let raw = "uname -a\nLinux host 6.1.0 #1 SMP x86_64 GNU/Linux\n[user@host ~]$ ";
        assert_eq!(
            strip_echo_and_prompt(raw, "uname -a"),
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

        let result = strip_echo_and_prompt(&raw, "show route");
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
        let raw = "pwd\n/home/fabioswartz\n[fabioswartz@voidstar ~]$ ";
        assert_eq!(strip_echo_and_prompt(raw, "pwd"), "/home/fabioswartz");
    }

    #[test]
    fn test_real_linux_whoami() {
        let raw = "whoami\nfabioswartz\n[fabioswartz@voidstar ~]$ ";
        assert_eq!(strip_echo_and_prompt(raw, "whoami"), "fabioswartz");
    }

    #[test]
    fn test_real_linux_uname() {
        let raw = "uname -a\nLinux voidstar 6.18.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 02 Jan 2026 17:52:55 +0000 x86_64 GNU/Linux\n[fabioswartz@voidstar ~]$ ";
        assert_eq!(
            strip_echo_and_prompt(raw, "uname -a"),
            "Linux voidstar 6.18.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 02 Jan 2026 17:52:55 +0000 x86_64 GNU/Linux"
        );
    }

    #[test]
    fn test_juniper_show_version() {
        let raw = "show version\nHostname: router1\nModel: mx240\nJunos: 21.4R3-S5\nuser@router1> ";
        assert_eq!(
            strip_echo_and_prompt(raw, "show version"),
            "Hostname: router1\nModel: mx240\nJunos: 21.4R3-S5"
        );
    }

    #[test]
    fn test_network_device_crlf() {
        // \r\n from network devices gets normalized to \n
        let raw =
            "show interfaces terse\r\nge-0/0/0  up  up\r\nge-0/0/1  up  down\r\nuser@router> ";
        assert_eq!(
            strip_echo_and_prompt(raw, "show interfaces terse"),
            "ge-0/0/0  up  up\nge-0/0/1  up  down"
        );
    }

    #[test]
    fn test_network_device_double_cr() {
        // Some devices send \r\r\n
        let raw = "show version\r\r\nJUNOS 21.4R1\r\r\nuser@router> ";
        assert_eq!(strip_echo_and_prompt(raw, "show version"), "JUNOS 21.4R1");
    }
}
