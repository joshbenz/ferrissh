//! Generic driver implementation that works with any platform.

use std::time::{Duration, Instant};

use regex::bytes::Regex;

use super::Driver;
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

    /// Read until the prompt is matched, then determine current privilege.
    async fn read_until_prompt(&mut self) -> Result<(String, String)> {
        let channel = self.channel.as_mut().ok_or(DriverError::NotConnected)?;

        let data = channel
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let output = String::from_utf8_lossy(&data).to_string();

        // Find the prompt at the end
        let prompt = if let Some(m) = self.prompt_pattern.find(&data) {
            String::from_utf8_lossy(&data[m.start()..]).to_string()
        } else {
            String::new()
        };

        Ok((output, prompt))
    }

    /// Universal output normalization: strip command echo and trailing prompt.
    ///
    /// Then apply vendor-specific post-processing if a behavior is set.
    fn normalize_output(&self, raw: &str, command: &str) -> String {
        debug!("normalize_output: raw={:?}, command={:?}", raw, command);

        // Strip command echo from the beginning.
        // The PTY may echo the command followed by \r\n, \n, or \r,
        // so we look for the first line and check if it matches the command.
        let output = if let Some(pos) = raw.find('\n') {
            let first_line = raw[..pos].trim_end_matches('\r');
            if first_line == command {
                &raw[pos + 1..]
            } else {
                raw
            }
        } else {
            raw.strip_prefix(command).unwrap_or(raw)
        };
        let output = output.trim_start_matches(['\r', '\n']);

        // Strip trailing prompt (last line)
        let stripped = if let Some(pos) = output.rfind('\n') {
            output[..pos].trim_end_matches('\r')
        } else {
            output
        };

        debug!("normalize_output: result={:?}", stripped);

        // Apply vendor-specific post-processing if present
        if let Some(ref behavior) = self.platform.behavior {
            behavior.post_process_output(stripped)
        } else {
            stripped.to_string()
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

        // Find the prompt
        let prompt = if let Some(m) = self.prompt_pattern.find(&data) {
            String::from_utf8_lossy(&data[m.start()..])
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
