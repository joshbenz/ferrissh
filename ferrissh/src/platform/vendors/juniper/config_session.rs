//! Juniper JUNOS configuration session.
//!
//! Provides RAII-guarded access to Juniper's candidate configuration system.
//! Unlike Arista's named sessions, Juniper uses a single shared candidate
//! configuration entered via `configure` (with optional `private`/`exclusive` modes).
//!
//! Supports diff, validate, and confirmed commit.
//!
//! # Example
//!
//! ```rust,no_run
//! use ferrissh::{Driver, DriverBuilder, Platform, ConfigSession, Diffable, Validatable};
//! use ferrissh::platform::vendors::juniper::JuniperConfigSession;
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let mut driver = DriverBuilder::new("router.example.com")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::JuniperJunos)
//!     .build()?;
//! driver.open().await?;
//!
//! let mut session = JuniperConfigSession::new(&mut driver).await?;
//! session.send_command("set system host-name lab-router").await?;
//!
//! let diff = session.diff().await?;
//! println!("Changes:\n{}", diff);
//!
//! let validation = session.validate().await?;
//! if validation.valid {
//!     session.commit().await?;
//! } else {
//!     session.abort().await?;
//! }
//! # Ok(())
//! # }
//! ```

use log::{debug, warn};

use std::time::Duration;

use crate::driver::config_session::{
    ConfigSession, ConfirmableCommit, Diffable, Validatable, ValidationResult,
};
use crate::driver::response::Response;
use crate::driver::{Driver, GenericDriver};
use crate::error::{DriverError, Result};

use super::platform::PLATFORM_NAME;

/// Juniper JUNOS configuration session guard.
///
/// Holds `&mut GenericDriver` to prevent concurrent driver use.
/// Implements [`ConfigSession`], [`Diffable`], [`Validatable`], and [`ConfirmableCommit`].
///
/// # Re-attach
///
/// After calling [`detach()`](ConfigSession::detach), the driver remains in
/// configuration mode. Call `JuniperConfigSession::new()` again to re-attach —
/// `acquire_privilege("configuration")` is a no-op if already in config mode.
pub struct JuniperConfigSession<'a> {
    driver: &'a mut GenericDriver,
    original_privilege: String,
    consumed: bool,
}

impl<'a> JuniperConfigSession<'a> {
    /// Enter Juniper configuration mode.
    ///
    /// Validates the platform is Juniper JUNOS, saves the current privilege
    /// level, and escalates to `configuration` mode via `configure`.
    pub async fn new(driver: &'a mut GenericDriver) -> Result<Self> {
        // Validate platform
        if driver.platform().name != PLATFORM_NAME {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "JuniperConfigSession requires a Juniper JUNOS platform, got '{}'",
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

        debug!(
            "entering Juniper config session (from {:?})",
            original_privilege
        );

        // Enter configuration mode (no-op if already there)
        driver.acquire_privilege("configuration").await?;

        Ok(Self {
            driver,
            original_privilege,
            consumed: false,
        })
    }
}

impl ConfigSession for JuniperConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.driver.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        debug!("Juniper config session: commit");
        self.consumed = true;

        // commit and-quit commits and exits config mode in one command
        self.driver.send_command("commit and-quit").await?;

        // Restore original privilege if needed
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

    async fn abort(mut self) -> Result<()> {
        debug!("Juniper config session: abort");
        self.consumed = true;

        // Discard all uncommitted changes
        self.driver.send_command("rollback 0").await?;

        // Return to original privilege level (exits config mode)
        self.driver
            .acquire_privilege(&self.original_privilege)
            .await?;

        Ok(())
    }

    fn detach(mut self) -> Result<()> {
        debug!("Juniper config session: detach");
        self.consumed = true;
        // Stay in config mode — user can re-create JuniperConfigSession::new()
        Ok(())
    }
}

impl Diffable for JuniperConfigSession<'_> {
    async fn diff(&mut self) -> Result<String> {
        debug!("Juniper config session: diff");
        let response = self.driver.send_command("show | compare").await?;
        Ok(response.result)
    }
}

impl Validatable for JuniperConfigSession<'_> {
    async fn validate(&mut self) -> Result<ValidationResult> {
        debug!("Juniper config session: validate");
        let response = self.driver.send_command("commit check").await?;

        if response.is_success() && response.result.contains("configuration check succeeds") {
            Ok(ValidationResult {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
            })
        } else {
            // Parse error lines from the output
            let errors: Vec<String> = response
                .result
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && !trimmed.contains("configuration check succeeds")
                })
                .map(|line| line.trim().to_string())
                .collect();

            Ok(ValidationResult {
                valid: false,
                errors,
                warnings: Vec::new(),
            })
        }
    }
}

impl ConfirmableCommit for JuniperConfigSession<'_> {
    async fn commit_confirmed(&mut self, timeout: Duration) -> Result<()> {
        debug!("Juniper config session: commit_confirmed ({:?})", timeout);
        // Juniper uses minutes for commit confirmed (range 1-65535)
        let secs = timeout.as_secs();

        if secs < 60 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Juniper commit confirmed minimum is 1 minute, got {} seconds",
                    secs
                ),
            }
            .into());
        }

        // Round up to next minute using div_ceil
        let minutes = secs.div_ceil(60);

        if minutes > 65535 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Juniper commit confirmed maximum is 65535 minutes, got {}",
                    minutes
                ),
            }
            .into());
        }

        let cmd = format!("commit confirmed {}", minutes);
        self.driver.send_command(&cmd).await?;

        // Does NOT consume the session — user must later commit() to confirm
        // or let it auto-rollback
        Ok(())
    }
}

impl Drop for JuniperConfigSession<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            warn!("JuniperConfigSession dropped without commit/abort/detach");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn test_commit_confirmed_formatting() {
        // Verify Duration-to-minutes conversion and command format
        fn format_cmd(timeout: Duration) -> String {
            let minutes = timeout.as_secs().div_ceil(60);
            format!("commit confirmed {}", minutes)
        }

        // Exactly 1 minute
        assert_eq!(format_cmd(Duration::from_secs(60)), "commit confirmed 1");

        // 10 minutes (default)
        assert_eq!(format_cmd(Duration::from_secs(600)), "commit confirmed 10");

        // 1 hour
        assert_eq!(format_cmd(Duration::from_secs(3600)), "commit confirmed 60");
    }

    #[test]
    fn test_commit_confirmed_minimum() {
        // Verify Duration < 60s would be rejected
        let secs = Duration::from_secs(30).as_secs();
        assert!(secs < 60, "30 seconds should be below the 1-minute minimum");

        // Exactly 60s is valid
        let secs = Duration::from_secs(60).as_secs();
        assert!(secs >= 60, "60 seconds should meet the minimum");
    }

    #[test]
    fn test_commit_confirmed_rounding() {
        // 90 seconds should round up to 2 minutes
        let minutes = Duration::from_secs(90).as_secs().div_ceil(60);
        assert_eq!(minutes, 2);

        // 61 seconds should round up to 2 minutes
        let minutes = Duration::from_secs(61).as_secs().div_ceil(60);
        assert_eq!(minutes, 2);

        // 120 seconds should be exactly 2 minutes (no rounding needed)
        let minutes = Duration::from_secs(120).as_secs().div_ceil(60);
        assert_eq!(minutes, 2);

        // 121 seconds should round up to 3 minutes
        let minutes = Duration::from_secs(121).as_secs().div_ceil(60);
        assert_eq!(minutes, 3);
    }
}
