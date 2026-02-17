//! Nokia SR OS MD-CLI configuration session.
//!
//! Provides RAII-guarded access to Nokia's MD-CLI candidate configuration
//! with exclusive mode. Only works when the device is running MD-CLI — returns
//! an error if the driver detects Classic CLI mode.
//!
//! Supports diff (`compare`), validate, and confirmed commit.
//!
//! # Example
//!
//! ```rust,no_run
//! use ferrissh::{Driver, DriverBuilder, Platform, ConfigSession, Diffable, Validatable};
//! use ferrissh::platform::vendors::nokia_sros::NokiaConfigSession;
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let mut driver = DriverBuilder::new("router.example.com")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::NokiaSros)
//!     .build()?;
//! driver.open().await?;
//!
//! let mut session = NokiaConfigSession::new(&mut driver).await?;
//! session.send_command("set / system name lab-router").await?;
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

/// Nokia SR OS MD-CLI configuration session guard.
///
/// Holds `&mut GenericDriver` to prevent concurrent driver use.
/// Implements [`ConfigSession`], [`Diffable`], [`Validatable`], and [`ConfirmableCommit`].
///
/// Only works with MD-CLI mode. If the device is running Classic CLI,
/// [`new()`](NokiaConfigSession::new) returns an error.
///
/// # Re-attach
///
/// After calling [`detach()`](ConfigSession::detach), the driver remains in
/// configuration mode. Call `NokiaConfigSession::new()` again to re-attach —
/// `acquire_privilege("configuration")` is a no-op if already in config mode.
pub struct NokiaConfigSession<'a> {
    driver: &'a mut GenericDriver,
    original_privilege: String,
    consumed: bool,
}

impl<'a> NokiaConfigSession<'a> {
    /// Enter Nokia MD-CLI exclusive configuration mode.
    ///
    /// Validates the platform is Nokia SR OS and that the device is running
    /// MD-CLI (not Classic CLI). Saves the current privilege level and
    /// escalates to `configuration` mode via `edit-config exclusive`.
    pub async fn new(driver: &'a mut GenericDriver) -> Result<Self> {
        // Validate platform
        if driver.platform().name != PLATFORM_NAME {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "NokiaConfigSession requires a Nokia SR OS platform, got '{}'",
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

        // Reject Classic CLI mode
        if original_privilege.starts_with("classic_") {
            debug!(
                "Nokia config session rejected: Classic CLI mode (privilege {:?})",
                original_privilege
            );
            return Err(DriverError::InvalidConfig {
                message: "NokiaConfigSession requires MD-CLI mode. \
                    The device is running Classic CLI, which has no candidate/commit model. \
                    Use driver.acquire_privilege(\"classic_configuration\") and \
                    driver.send_command() directly for Classic CLI configuration."
                    .to_string(),
            }
            .into());
        }

        debug!(
            "entering Nokia config session (from {:?})",
            original_privilege
        );

        // Enter exclusive configuration mode (no-op if already there)
        driver.acquire_privilege("configuration").await?;

        Ok(Self {
            driver,
            original_privilege,
            consumed: false,
        })
    }
}

impl ConfigSession for NokiaConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.driver.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        debug!("Nokia config session: commit");
        self.consumed = true;

        // Commit the candidate configuration
        self.driver.send_command("commit").await?;

        // Exit config mode
        self.driver.send_command("quit-config").await?;

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
        debug!("Nokia config session: abort");
        self.consumed = true;

        // Discard all uncommitted changes (avoids quit-config confirmation prompt)
        self.driver.send_command("discard").await?;

        // Exit config mode
        self.driver.send_command("quit-config").await?;

        // Restore original privilege
        self.driver
            .acquire_privilege(&self.original_privilege)
            .await?;

        Ok(())
    }

    fn detach(mut self) -> Result<()> {
        debug!("Nokia config session: detach");
        self.consumed = true;
        // Stay in config mode — user can re-create NokiaConfigSession::new()
        Ok(())
    }
}

impl Diffable for NokiaConfigSession<'_> {
    async fn diff(&mut self) -> Result<String> {
        debug!("Nokia config session: diff");
        let response = self.driver.send_command("compare").await?;
        Ok(response.result)
    }
}

impl Validatable for NokiaConfigSession<'_> {
    async fn validate(&mut self) -> Result<ValidationResult> {
        debug!("Nokia config session: validate");
        let response = self.driver.send_command("validate").await?;

        // Nokia validate produces no output on success.
        // On failure, error messages are returned and typically trigger
        // failure patterns (MINOR:/MAJOR:).
        if response.is_success() {
            Ok(ValidationResult {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
            })
        } else {
            let errors: Vec<String> = response
                .result
                .lines()
                .filter(|line| !line.trim().is_empty())
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

impl ConfirmableCommit for NokiaConfigSession<'_> {
    async fn commit_confirmed(&mut self, timeout: Duration) -> Result<()> {
        debug!("Nokia config session: commit_confirmed ({:?})", timeout);
        // Nokia uses minutes for commit confirmed (range 1-65535, default 10)
        let secs = timeout.as_secs();

        if secs < 60 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Nokia commit confirmed minimum is 1 minute, got {} seconds",
                    secs
                ),
            }
            .into());
        }

        // Round up to next minute
        let minutes = secs.div_ceil(60);

        if minutes > 65535 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "Nokia commit confirmed maximum is 65535 minutes, got {}",
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

impl Drop for NokiaConfigSession<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            warn!("NokiaConfigSession dropped without commit/abort/detach");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn test_commit_confirmed_formatting() {
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
        let secs = Duration::from_secs(30).as_secs();
        assert!(secs < 60, "30 seconds should be below the 1-minute minimum");

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

        // 120 seconds should be exactly 2 minutes
        let minutes = Duration::from_secs(120).as_secs().div_ceil(60);
        assert_eq!(minutes, 2);

        // 121 seconds should round up to 3 minutes
        let minutes = Duration::from_secs(121).as_secs().div_ceil(60);
        assert_eq!(minutes, 3);
    }
}
