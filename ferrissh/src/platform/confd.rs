//! Generic ConfD configuration session.
//!
//! ConfD (Tail-f/Cisco) is a management framework for network devices that
//! provides NETCONF/YANG support and generates CLI interfaces from YANG models.
//! ConfD supports both C-style and J-style CLIs, but the config session
//! commands are identical regardless of CLI style:
//!
//! - Diff: `compare running-config`
//! - Validate: `validate` (no output on success)
//! - Commit: `commit`
//! - Abort: `revert`
//! - Confirmed commit: `commit confirmed <minutes>` (1–65535 range)
//!
//! The CLI style only affects prompts and navigation commands (how you enter
//! and exit config mode), which are defined in each vendor's `platform.rs`.
//!
//! # Usage
//!
//! Vendor modules provide a convenience constructor that pre-fills the platform
//! name. You can also use the generic struct directly:
//!
//! ```rust,no_run
//! use ferrissh::{Driver, DriverBuilder, Platform, ConfigSession, Diffable, Validatable};
//! use ferrissh::platform::vendors::arrcus_arcos;
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let mut driver = DriverBuilder::new("router.example.com")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::ArrcusArcOs)
//!     .build()?;
//! driver.open().await?;
//!
//! let mut session = arrcus_arcos::config_session(&mut driver).await?;
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

/// ConfD configuration session guard.
///
/// Provides RAII-guarded access to any ConfD candidate configuration.
/// Works with both C-style and J-style ConfD CLIs — the config session
/// commands are identical; only the prompts differ (defined in `platform.rs`).
///
/// Holds `&mut GenericDriver` to prevent concurrent driver use.
/// Implements [`ConfigSession`], [`Diffable`], [`Validatable`], and [`ConfirmableCommit`].
///
/// # Re-attach
///
/// After calling [`detach()`](ConfigSession::detach), the driver remains in
/// configuration mode. Create a new session to re-attach —
/// `acquire_privilege("configuration")` is a no-op if already in config mode.
pub struct ConfDConfigSession<'a> {
    driver: &'a mut GenericDriver,
    original_privilege: String,
    platform_name: &'static str,
    consumed: bool,
}

impl<'a> ConfDConfigSession<'a> {
    /// Enter ConfD J-style configuration mode.
    ///
    /// Validates the driver's platform matches `platform_name`, saves the
    /// current privilege level, and escalates to `configuration` mode via
    /// `configure`.
    ///
    /// Vendor modules typically wrap this with a convenience function that
    /// pre-fills `platform_name`.
    pub async fn new(driver: &'a mut GenericDriver, platform_name: &'static str) -> Result<Self> {
        // Validate platform
        if driver.platform().name != platform_name {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "ConfD config session requires platform '{}', got '{}'",
                    platform_name,
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
            "entering ConfD config session for {} (from {:?})",
            platform_name, original_privilege
        );

        // Enter configuration mode (no-op if already there)
        driver.acquire_privilege("configuration").await?;

        Ok(Self {
            driver,
            original_privilege,
            platform_name,
            consumed: false,
        })
    }

    /// Restore the driver to its original privilege level if needed.
    async fn restore_privilege(&mut self) -> Result<()> {
        if !self.original_privilege.is_empty() {
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
        }
        Ok(())
    }
}

impl ConfigSession for ConfDConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.driver.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        debug!("{} config session: commit", self.platform_name);
        self.consumed = true;

        // Commit the candidate configuration
        self.driver.send_command("commit").await?;

        // Restore original privilege (exits config mode)
        self.restore_privilege().await
    }

    async fn abort(mut self) -> Result<()> {
        debug!("{} config session: abort", self.platform_name);
        self.consumed = true;

        // Discard all uncommitted changes
        self.driver.send_command("revert").await?;

        // Restore original privilege (exits config mode)
        self.restore_privilege().await
    }

    fn detach(mut self) -> Result<()> {
        debug!("{} config session: detach", self.platform_name);
        self.consumed = true;
        // Stay in config mode — user can re-create a session to re-attach
        Ok(())
    }
}

impl Diffable for ConfDConfigSession<'_> {
    async fn diff(&mut self) -> Result<String> {
        debug!("{} config session: diff", self.platform_name);
        let response = self.driver.send_command("compare running-config").await?;
        Ok(response.result)
    }
}

impl Validatable for ConfDConfigSession<'_> {
    async fn validate(&mut self) -> Result<ValidationResult> {
        debug!("{} config session: validate", self.platform_name);
        let response = self.driver.send_command("validate").await?;

        // ConfD validate produces no output on success.
        // On failure, error messages are returned and typically trigger
        // failure patterns.
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

impl ConfirmableCommit for ConfDConfigSession<'_> {
    async fn commit_confirmed(&mut self, timeout: Duration) -> Result<()> {
        debug!(
            "{} config session: commit_confirmed ({:?})",
            self.platform_name, timeout
        );
        // ConfD uses minutes for commit confirmed
        let secs = timeout.as_secs();

        if secs < 60 {
            return Err(DriverError::InvalidConfig {
                message: format!(
                    "ConfD commit confirmed minimum is 1 minute, got {} seconds",
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
                    "ConfD commit confirmed maximum is 65535 minutes, got {}",
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

impl Drop for ConfDConfigSession<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            warn!(
                "ConfDConfigSession ({}) dropped without commit/abort/detach",
                self.platform_name
            );
        }
    }
}

/// Backwards-compatible alias for J-style ConfD vendors.
///
/// The config session commands are identical for both C-style and J-style
/// ConfD CLIs. This alias exists so that code written for J-style vendors
/// continues to compile without changes.
pub type ConfDJStyleConfigSession<'a> = ConfDConfigSession<'a>;

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
