//! Generic driver implementation that works with any platform.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use regex::bytes::Regex;

use super::privilege::PrivilegeManager;
use super::response::Response;
use super::Driver;
use crate::error::{DriverError, Result};
use crate::platform::{DefaultBehavior, PlatformDefinition, VendorBehavior};
use crate::transport::config::SshConfig;
use crate::transport::SshTransport;

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

    /// Vendor behavior implementation.
    behavior: Arc<dyn VendorBehavior>,

    /// SSH transport (None when disconnected).
    transport: Option<SshTransport>,

    /// Privilege level manager.
    privilege_manager: PrivilegeManager,

    /// Default timeout for operations.
    timeout: Duration,

    /// Combined prompt pattern for all privilege levels.
    prompt_pattern: Regex,
}

impl GenericDriver {
    /// Create a new generic driver.
    pub fn new(ssh_config: SshConfig, platform: PlatformDefinition) -> Self {
        let timeout = ssh_config.timeout;

        // Build privilege manager
        let privilege_manager = PrivilegeManager::new(platform.privilege_levels.clone());

        // Get behavior or use default
        let behavior = platform
            .behavior
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultBehavior));

        // Build combined prompt pattern
        let prompt_pattern = Self::build_combined_pattern(&platform);

        Self {
            ssh_config,
            platform,
            behavior,
            transport: None,
            privilege_manager,
            timeout,
            prompt_pattern,
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
        let transport = self
            .transport
            .as_mut()
            .ok_or(DriverError::NotConnected)?;

        let data = transport
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let output = String::from_utf8_lossy(&data).to_string();

        // Find the prompt at the end
        let prompt = if let Some(m) = self.prompt_pattern.find(data.as_slice()) {
            String::from_utf8_lossy(&data[m.start()..]).to_string()
        } else {
            String::new()
        };

        Ok((output, prompt))
    }

    /// Execute on_open commands from platform definition.
    async fn execute_on_open_commands(&mut self) -> Result<()> {
        for cmd in &self.platform.on_open_commands.clone() {
            self.send_command(cmd).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Driver for GenericDriver {
    async fn open(&mut self) -> Result<()> {
        if self.transport.is_some() {
            return Err(DriverError::AlreadyConnected.into());
        }

        // Connect
        let transport = SshTransport::connect(self.ssh_config.clone()).await?;
        self.transport = Some(transport);

        // Wait for initial prompt
        let (_, prompt) = self.read_until_prompt().await?;

        // Determine initial privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            self.privilege_manager.set_current(&level_name)?;
        }

        // Execute on_open behavior
        // Note: We need to clone the Arc to avoid borrow issues
        let behavior = self.behavior.clone();
        behavior.on_open(self).await?;

        // Execute on_open commands
        self.execute_on_open_commands().await?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(transport) = self.transport.take() {
            // Execute on_close behavior
            let behavior = self.behavior.clone();
            behavior.on_close(self).await?;

            transport.close().await?;
        }
        Ok(())
    }

    async fn send_command(&mut self, command: &str) -> Result<Response> {
        let transport = self
            .transport
            .as_mut()
            .ok_or(DriverError::NotConnected)?;

        let start = Instant::now();

        // Send the command
        transport.send(command).await?;

        // Wait for prompt
        let data = transport
            .read_until_pattern(&self.prompt_pattern, self.timeout)
            .await?;

        let elapsed = start.elapsed();
        let raw_result = String::from_utf8_lossy(&data).to_string();

        // Find the prompt
        let prompt = if let Some(m) = self.prompt_pattern.find(data.as_slice()) {
            String::from_utf8_lossy(&data[m.start()..]).trim().to_string()
        } else {
            String::new()
        };

        // Update current privilege level
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }

        // Normalize output
        let result = self.behavior.normalize_output(&raw_result, command);

        // Check for failures
        if let Some(failure_msg) = self.behavior.detect_failure(&result) {
            return Ok(Response::failed(
                command,
                result,
                raw_result,
                prompt,
                elapsed,
                failure_msg,
            ));
        }

        // Also check platform's failed_when_contains
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

    async fn send_commands(&mut self, commands: &[&str]) -> Result<Vec<Response>> {
        let mut responses = Vec::with_capacity(commands.len());
        for cmd in commands {
            responses.push(self.send_command(cmd).await?);
        }
        Ok(responses)
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
            let transport = self
                .transport
                .as_mut()
                .ok_or(DriverError::NotConnected)?;

            transport.send(&transition.command).await?;

            // Handle authentication if needed
            if transition.needs_auth {
                if let Some(ref auth_pattern) = transition.auth_prompt {
                    // Wait for auth prompt
                    let _ = transport
                        .read_until_pattern(auth_pattern, self.timeout)
                        .await?;

                    // Send password (from auth method)
                    if let crate::transport::config::AuthMethod::Password(ref pwd) = self.ssh_config.auth {
                        transport.send(pwd).await?;
                    }
                }
            }

            // Wait for new prompt
            let (_, prompt) = self.read_until_prompt().await?;

            // Verify we reached the expected privilege
            if let Ok(level) = self.privilege_manager.determine_from_prompt(&prompt) {
                let level_name = level.name.clone();
                self.privilege_manager.set_current(&level_name)?;
                if level_name != *to {
                    return Err(DriverError::PrivilegeAcquisitionFailed {
                        target: to.clone(),
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    fn is_open(&self) -> bool {
        self.transport.is_some()
    }
}
