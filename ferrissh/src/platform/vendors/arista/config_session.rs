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
//! let mut session = AristaConfigSession::new(&mut driver, "my-changes").await?;
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

use log::warn;

use std::time::Duration;

use crate::driver::config_session::{ConfigSession, ConfirmableCommit, Diffable, NamedSession};
use crate::driver::response::Response;
use crate::driver::{Driver, GenericDriver};
use crate::error::{DriverError, Result};
use crate::platform::PrivilegeLevel;

use super::platform::PLATFORM_NAME;

/// Arista EOS named configuration session guard.
///
/// Holds `&mut GenericDriver` to prevent concurrent driver use.
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
    driver: &'a mut GenericDriver,
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
    pub async fn new(
        driver: &'a mut GenericDriver,
        session_name: impl Into<String>,
    ) -> Result<Self> {
        let session_name = session_name.into();

        // Validate platform
        if driver.platform().name != PLATFORM_NAME {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "AristaConfigSession requires an Arista EOS platform, got '{}'",
                    driver.platform().name
                ),
            }
            .into());
        }

        let original_privilege = driver
            .privilege_manager()
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        let session_priv_name = format!("config_session_{}", session_name);

        // Check if dynamic level already registered (re-attach after detach)
        let already_registered = driver.privilege_manager().get(&session_priv_name).is_some();

        if !already_registered {
            // Build prompt pattern using first 6 chars of session name (per Arista behavior)
            let first6: String = session_name.chars().take(6).collect();
            let escaped = regex::escape(&first6);
            let pattern = format!(
                r"(?mi)^[\w.\-@()/: ]{{1,63}}\(config\-s\-{}[\w.\-@/:+]{{0,64}}\)#\s?$",
                escaped
            );

            let session_priv = PrivilegeLevel::new(&session_priv_name, &pattern)
                .map_err(|e| DriverError::InvalidConfig {
                    message: format!("Failed to create session privilege level: {e}"),
                })?
                .with_parent("privilege_exec")
                .with_escalate(format!("configure session {}", session_name))
                .with_deescalate("end");

            driver
                .privilege_manager_mut()
                .register_dynamic_level(session_priv);
            driver.rebuild_prompt_pattern();
        }

        // Enter the session (no-op if already there after re-attach)
        driver.acquire_privilege(&session_priv_name).await?;

        Ok(Self {
            driver,
            session_name,
            original_privilege,
            session_priv_name,
            consumed: false,
        })
    }

    /// Clean up the dynamic privilege level and restore original privilege.
    async fn cleanup(&mut self) -> Result<()> {
        self.driver
            .privilege_manager_mut()
            .remove_dynamic_level(&self.session_priv_name);
        self.driver.rebuild_prompt_pattern();

        // Restore original privilege if different from current
        let current = self
            .driver
            .privilege_manager()
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        if current != self.original_privilege {
            self.driver
                .acquire_privilege(&self.original_privilege)
                .await?;
        }

        Ok(())
    }
}

impl ConfigSession for AristaConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.driver.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        self.consumed = true;

        // Commit the session changes
        self.driver.send_command("commit").await?;

        // Exit the session (back to privilege_exec)
        self.driver.send_command("end").await?;

        self.cleanup().await
    }

    async fn abort(mut self) -> Result<()> {
        self.consumed = true;

        // Abort discards changes and exits the session
        self.driver.send_command("abort").await?;

        self.cleanup().await
    }

    fn detach(mut self) -> Result<()> {
        self.consumed = true;
        // Leave session active, dynamic level registered
        Ok(())
    }
}

impl Diffable for AristaConfigSession<'_> {
    async fn diff(&mut self) -> Result<String> {
        let response = self
            .driver
            .send_command("show session-config diffs")
            .await?;
        Ok(response.result)
    }
}

impl ConfirmableCommit for AristaConfigSession<'_> {
    async fn commit_confirmed(&mut self, timeout: Duration) -> Result<()> {
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
        self.driver.send_command(&cmd).await?;

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
            r"(?mi)^[\w.\-@()/: ]{{1,63}}\(config\-s\-{}[\w.\-@/:+]{{0,64}}\)#\s?$",
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
            r"(?mi)^[\w.\-@()/: ]{{1,63}}\(config\-s\-{}[\w.\-@/:+]{{0,64}}\)#\s?$",
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
            r"(?mi)^[\w.\-@()/: ]{{1,63}}\(config\-s\-{}[\w.\-@/:+]{{0,64}}\)#\s?$",
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
}
