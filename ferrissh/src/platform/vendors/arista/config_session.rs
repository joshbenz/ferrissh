//! Arista EOS named configuration session.
//!
//! Provides RAII-guarded access to Arista's `configure session` feature.
//! Named sessions provide an isolated candidate configuration that can be
//! committed, aborted, or detached for later re-attachment.
//!
//! # Example
//!
//! ```rust,no_run
//! use ferrissh::{Driver, DriverBuilder, Platform, ConfigSession, Diffable};
//! use ferrissh::platform::vendors::arista::AristaConfigSession;
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let mut driver = DriverBuilder::new("switch.example.com")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::AristaEos)
//!     .build()?;
//! driver.open().await?;
//!
//! let mut session = AristaConfigSession::new(driver.channel().unwrap(), "my-changes").await?;
//! session.send_command("interface Ethernet1").await?;
//! session.send_command("description Updated via ferrissh").await?;
//!
//! let diff = session.diff().await?;
//! println!("Changes:\n{}", diff);
//!
//! session.commit().await?; // consumes session
//! # Ok(())
//! # }
//! ```

use log::{debug, warn};

use std::time::Duration;

use crate::driver::channel::Channel;
use crate::driver::config_session::{ConfigSession, ConfirmableCommit, Diffable, NamedSession};
use crate::driver::response::Response;
use crate::error::{DriverError, Result};
use crate::platform::PrivilegeLevel;

use super::platform::PLATFORM_NAME;

/// Arista EOS named configuration session guard.
///
/// Holds `&mut Channel` to prevent concurrent channel use.
/// Implements [`ConfigSession`], [`Diffable`], and [`NamedSession`].
///
/// # Re-attach
///
/// After calling [`detach()`](ConfigSession::detach), the session remains
/// active on the device. Call `AristaConfigSession::new()` again with the
/// same name to re-attach — the dynamic privilege level is still registered
/// and `acquire_privilege` will be a no-op if already in the session.
///
/// Cross-program re-attach also works: Arista's `configure session {name}`
/// re-enters an existing session on the device.
pub struct AristaConfigSession<'a> {
    channel: &'a mut Channel,
    session_name: String,
    original_privilege: String,
    session_priv_name: String,
    consumed: bool,
}

impl<'a> AristaConfigSession<'a> {
    /// Create or re-attach to a named configuration session.
    ///
    /// If the session already exists on the device, this re-enters it.
    /// If the dynamic privilege level is already registered (after a detach),
    /// registration is skipped and `acquire_privilege` is a no-op.
    pub async fn new(channel: &'a mut Channel, session_name: impl Into<String>) -> Result<Self> {
        let session_name = session_name.into();

        // Validate session name (Arista allows alphanumeric, hyphens, underscores, max 63 chars)
        if session_name.is_empty() || session_name.len() > 63 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Session name must be 1-63 characters, got {}",
                    session_name.len()
                ),
            }
            .into());
        }
        if !session_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Session name contains invalid characters: '{}'. Only ASCII alphanumeric, hyphens, and underscores allowed.",
                    session_name
                ),
            }
            .into());
        }

        // Validate platform
        if channel.platform().name != PLATFORM_NAME {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "AristaConfigSession requires an Arista EOS platform, got '{}'",
                    channel.platform().name
                ),
            }
            .into());
        }

        let original_privilege = channel
            .privilege_manager()
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        let session_priv_name = format!("config_session_{}", session_name);

        // Check if dynamic level already registered (re-attach after detach)
        let already_registered = channel
            .privilege_manager()
            .get(&session_priv_name)
            .is_some();

        if !already_registered {
            debug!(
                "registering dynamic privilege level for session {:?}",
                session_priv_name
            );

            // Build prompt pattern using first 6 chars of session name (per Arista behavior)
            let first6: String = session_name.chars().take(6).collect();
            let escaped = regex::escape(&first6);
            let pattern = format!(
                r"(?m)(?-u)^[\w.\-@()/: ]+\(config\-s\-{}[\w.\-@/:+]*\)#\s?$",
                escaped
            );

            let session_priv = PrivilegeLevel::new(&session_priv_name, &pattern)
                .map_err(|e| DriverError::InvalidConfig {
                    message: format!("Failed to create session privilege level: {e}"),
                })?
                .with_parent("privilege_exec")
                .with_escalate(format!("configure session {}", session_name))
                .with_deescalate("end");

            channel
                .privilege_manager_mut()
                .register_dynamic_level(session_priv);
            channel.rebuild_prompt_pattern();
        }

        debug!(
            "entering Arista config session (from {:?})",
            original_privilege
        );

        // Enter the session (no-op if already there after re-attach)
        channel.acquire_privilege(&session_priv_name).await?;

        Ok(Self {
            channel,
            session_name,
            original_privilege,
            session_priv_name,
            consumed: false,
        })
    }

    /// Clean up the dynamic privilege level and restore original privilege.
    async fn cleanup(&mut self) -> Result<()> {
        self.channel
            .privilege_manager_mut()
            .remove_dynamic_level(&self.session_priv_name);
        self.channel.rebuild_prompt_pattern();

        // Restore original privilege if known and different from current
        if !self.original_privilege.is_empty() {
            let current = self
                .channel
                .privilege_manager()
                .current()
                .map(|l| l.name.clone())
                .unwrap_or_default();

            if current != self.original_privilege {
                self.channel
                    .acquire_privilege(&self.original_privilege)
                    .await?;
            }
        }

        Ok(())
    }
}

impl ConfigSession for AristaConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.channel.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        debug!("Arista config session: commit");

        // Commit the session changes
        self.channel.send_command("commit").await?;

        // Exit the session (back to privilege_exec)
        self.channel.send_command("end").await?;

        self.cleanup().await?;
        self.consumed = true;
        Ok(())
    }

    async fn abort(mut self) -> Result<()> {
        debug!("Arista config session: abort");

        // Abort discards changes and exits the session
        self.channel.send_command("abort").await?;

        self.cleanup().await?;
        self.consumed = true;
        Ok(())
    }

    fn detach(mut self) -> Result<()> {
        debug!("Arista config session: detach");
        self.consumed = true;
        // Leave session active, dynamic level registered
        Ok(())
    }
}

impl Diffable for AristaConfigSession<'_> {
    async fn diff(&mut self) -> Result<String> {
        debug!("Arista config session: diff");
        let response = self
            .channel
            .send_command("show session-config diffs")
            .await?;
        Ok(response.result.to_string())
    }
}

impl ConfirmableCommit for AristaConfigSession<'_> {
    async fn commit_confirmed(&mut self, timeout: Duration) -> Result<()> {
        debug!("Arista config session: commit_confirmed ({:?})", timeout);
        let total = timeout.as_secs();

        if total < 60 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Arista commit timer minimum is 1 minute, got {} seconds",
                    total
                ),
            }
            .into());
        }

        let cmd = format!(
            "commit timer {:02}:{:02}:{:02}",
            total / 3600,
            (total % 3600) / 60,
            total % 60,
        );
        self.channel.send_command(&cmd).await?;

        Ok(())
    }
}

impl NamedSession for AristaConfigSession<'_> {
    fn session_name(&self) -> &str {
        &self.session_name
    }
}

impl Drop for AristaConfigSession<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            warn!(
                "AristaConfigSession '{}' dropped without commit/abort/detach",
                self.session_name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_session_prompt_pattern() {
        // Verify the generated pattern matches expected Arista session prompts
        let session_name = "my-changes";
        let first6: String = session_name.chars().take(6).collect();
        let escaped = regex::escape(&first6);
        let pattern = format!(
            r"(?m)(?-u)^[\w.\-@()/: ]+\(config\-s\-{}[\w.\-@/:+]*\)#\s?$",
            escaped
        );

        let re = regex::bytes::Regex::new(&pattern).unwrap();

        // Should match session prompt
        assert!(re.is_match(b"switch(config-s-my-cha)#"));
        assert!(re.is_match(b"switch(config-s-my-cha)# "));
        assert!(re.is_match(b"switch(config-s-my-changes)#"));
        assert!(re.is_match(b"admin@switch(config-s-my-cha)#"));

        // Should NOT match regular config
        assert!(!re.is_match(b"switch(config)#"));
        assert!(!re.is_match(b"switch#"));
        assert!(!re.is_match(b"switch>"));
    }

    #[test]
    fn test_session_prompt_short_name() {
        // Session name shorter than 6 chars
        let session_name = "abc";
        let first6: String = session_name.chars().take(6).collect();
        let escaped = regex::escape(&first6);
        let pattern = format!(
            r"(?m)(?-u)^[\w.\-@()/: ]+\(config\-s\-{}[\w.\-@/:+]*\)#\s?$",
            escaped
        );

        let re = regex::bytes::Regex::new(&pattern).unwrap();

        assert!(re.is_match(b"switch(config-s-abc)#"));
        assert!(!re.is_match(b"switch(config-s-xyz)#"));
    }

    #[test]
    fn test_session_prompt_exact_six_chars() {
        // Session name exactly 6 chars — first 6 = whole name
        let session_name = "mytest";
        let first6: String = session_name.chars().take(6).collect();
        let escaped = regex::escape(&first6);
        let pattern = format!(
            r"(?m)(?-u)^[\w.\-@()/: ]+\(config\-s\-{}[\w.\-@/:+]*\)#\s?$",
            escaped
        );

        let re = regex::bytes::Regex::new(&pattern).unwrap();

        assert!(re.is_match(b"switch(config-s-mytest)#"));
        // Longer names that start with "mytest" also match
        assert!(re.is_match(b"switch(config-s-mytest-extra)#"));
    }

    #[test]
    fn test_commit_timer_formatting() {
        use std::time::Duration;

        // Helper to format duration the same way the impl does
        fn format_timer(timeout: Duration) -> String {
            let total = timeout.as_secs();
            format!(
                "commit timer {:02}:{:02}:{:02}",
                total / 3600,
                (total % 3600) / 60,
                total % 60,
            )
        }

        assert_eq!(
            format_timer(Duration::from_secs(60)),
            "commit timer 00:01:00"
        );
        assert_eq!(
            format_timer(Duration::from_secs(300)),
            "commit timer 00:05:00"
        );
        assert_eq!(
            format_timer(Duration::from_secs(301)),
            "commit timer 00:05:01"
        );
        assert_eq!(
            format_timer(Duration::from_secs(3600)),
            "commit timer 01:00:00"
        );
        assert_eq!(
            format_timer(Duration::from_secs(3661)),
            "commit timer 01:01:01"
        );
        assert_eq!(
            format_timer(Duration::from_secs(86400)),
            "commit timer 24:00:00"
        );
    }

    // Session name validation tests (sync, no SSH connection needed)

    fn validate_session_name(name: &str) -> std::result::Result<(), String> {
        if name.is_empty() || name.len() > 63 {
            return Err(format!(
                "Session name must be 1-63 characters, got {}",
                name.len()
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "Session name contains invalid characters: '{}'",
                name
            ));
        }
        Ok(())
    }

    #[test]
    fn test_session_name_valid() {
        assert!(validate_session_name("my-session_1").is_ok());
        assert!(validate_session_name("a").is_ok());
        assert!(validate_session_name("test-session").is_ok());
        assert!(validate_session_name("UPPER_lower_123").is_ok());
    }

    #[test]
    fn test_session_name_empty() {
        assert!(validate_session_name("").is_err());
    }

    #[test]
    fn test_session_name_too_long() {
        let long_name = "a".repeat(64);
        assert!(validate_session_name(&long_name).is_err());
        // 63 chars should be fine
        let ok_name = "a".repeat(63);
        assert!(validate_session_name(&ok_name).is_ok());
    }

    #[test]
    fn test_session_name_injection() {
        assert!(validate_session_name("test; show version").is_err());
    }

    #[test]
    fn test_session_name_newline() {
        assert!(validate_session_name("test\nset").is_err());
    }

    #[test]
    fn test_session_name_spaces() {
        assert!(validate_session_name("my session").is_err());
    }
}
