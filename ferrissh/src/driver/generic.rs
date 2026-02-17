//! Generic driver implementation that works with any platform.

use std::time::{Duration, Instant};

use regex::Regex as TextRegex;
use regex::bytes::Regex;

use super::Driver;
use super::config_session::GenericConfigSession;
use super::interactive::{InteractiveEvent, InteractiveResult, InteractiveStep};
use super::privilege::PrivilegeManager;
use super::response::Response;
use crate::channel::{PtyChannel, PtyConfig};
use crate::error::{DriverError, Result};
use crate::platform::PlatformDefinition;
use crate::transport::SshTransport;
use crate::transport::config::SshConfig;
use log::debug;

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
            String::from_utf8_lossy(&tail[m.start()..]).to_string()
        } else {
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
}

impl Driver for GenericDriver {
    async fn open(&mut self) -> Result<()> {
        if self.transport.is_some() {
            return Err(DriverError::AlreadyConnected.into());
        }

        // Connect
        let transport = SshTransport::connect(self.ssh_config.clone()).await?;

        // Open a PTY channel
        let russh_channel = transport.open_channel().await?;
        let pty_channel = PtyChannel::new(russh_channel, PtyConfig::default());

        self.transport = Some(transport);
        self.channel = Some(pty_channel);

        // Wait for initial prompt
        let (_, prompt) = self.read_until_prompt().await?;

        // Determine initial privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            self.privilege_manager.set_current(&level_name)?;
        }

        // Execute on_open commands from platform definition
        self.execute_on_open_commands().await?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // Execute on_close commands before disconnecting
        if self.channel.is_some() {
            for cmd in &self.platform.on_close_commands.clone() {
                let _ = self.send_command(cmd).await;
            }
        }

        // Drop the channel first
        self.channel.take();

        if let Some(transport) = self.transport.take() {
            transport.close().await?;
        }
        Ok(())
    }

    async fn send_command(&mut self, command: &str) -> Result<Response> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

        let start = Instant::now();

        // Send the command
        channel.send(command).await?;

        // Wait for prompt
        let data = channel
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

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
            String::from_utf8_lossy(&tail[m.start()..])
                .trim()
                .to_string()
        } else {
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

        Ok(Response::new(command, result, raw_result, prompt, elapsed))
    }

    async fn acquire_privilege(&mut self, target: &str) -> Result<()> {
        let current = self
            .privilege_manager
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        if current == target {
            return Ok(()); // Already at target
        }

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

            // Send the transition command
            let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

            channel.send(&transition.command).await?;

            // Handle authentication if needed
            if let Some(ref auth_pattern) = transition.auth_prompt {
                // Wait for auth prompt
                let _ = channel
                    .read_until_pattern(auth_pattern, self.timeout)
                    .await?;

                // Send password (from auth method)
                if let crate::transport::config::AuthMethod::Password(ref pwd) =
                    self.ssh_config.auth
                {
                    channel.send(pwd).await?;
                }
            }

            // Wait for new prompt
            let (_, prompt) = self.read_until_prompt().await?;

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

            // Borrow channel for I/O, then release before normalize_output
            let (data, step_elapsed) = {
                let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

                channel.send(&event.input).await?;

                let timeout = event.timeout.unwrap_or(self.timeout);
                let data = channel.read_until_pattern(&event.pattern, timeout).await?;

                (data, step_start.elapsed())
            };

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
        // Save current privilege level
        let original_privilege = self.privilege_manager.current().map(|l| l.name.clone());

        // Find the configuration privilege level
        // Look for a level with "config" in the name, or use platform's default
        let config_privilege = self
            .platform
            .privilege_levels
            .keys()
            .find(|name| name.to_lowercase().contains("config"))
            .cloned();

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
        self.transport.is_some() && self.channel.is_some()
    }

    fn current_privilege(&self) -> Option<&str> {
        self.privilege_manager.current().map(|l| l.name.as_str())
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
