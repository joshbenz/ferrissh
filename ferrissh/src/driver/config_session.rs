//! Configuration session traits and RAII guards.
//!
//! Config sessions are treated as **transactions**, not privilege levels.
//! They use Rust's ownership system for compile-time safety:
//! - The guard holds `&mut GenericDriver`, preventing concurrent driver use
//! - `commit()`/`abort()` consume the guard, ensuring single-use
//! - `detach()` releases the guard without ending the session
//!
//! # Example
//!
//! ```rust,no_run
//! use ferrissh::{Driver, DriverBuilder, Platform, ConfigSession};
//!
//! # async fn example() -> Result<(), ferrissh::Error> {
//! let mut driver = DriverBuilder::new("192.168.1.1")
//!     .username("admin")
//!     .password("secret")
//!     .platform(Platform::JuniperJunos)
//!     .build()?;
//! driver.open().await?;
//!
//! let mut session = driver.config_session().await?;
//! session.send_command("set system host-name test").await?;
//! session.commit().await?; // consumes session, returns to original privilege
//! # Ok(())
//! # }
//! ```

use std::future::Future;

use log::warn;

use super::Driver;
use super::generic::GenericDriver;
use super::response::Response;
use crate::error::{DriverError, Result};

// =============================================================================
// Core traits
// =============================================================================

/// Core configuration session trait.
///
/// Every vendor with a config mode can implement this. The key methods
/// `commit()`, `abort()`, and `detach()` consume the session by value,
/// enforcing single-use at compile time.
pub trait ConfigSession: Send {
    /// Send a command within the configuration session.
    fn send_command(&mut self, cmd: &str) -> impl Future<Output = Result<Response>> + Send;

    /// Commit the configuration and exit the session.
    ///
    /// Consumes the session — it cannot be used after this.
    fn commit(self) -> impl Future<Output = Result<()>> + Send;

    /// Abort the configuration and exit the session, discarding changes.
    ///
    /// Consumes the session — it cannot be used after this.
    fn abort(self) -> impl Future<Output = Result<()>> + Send;

    /// Detach from the session without committing or aborting.
    ///
    /// The session remains active on the device. Call the vendor's
    /// session constructor again with the same name to re-attach.
    ///
    /// Consumes the session — it cannot be used after this.
    fn detach(self) -> Result<()>;
}

/// Sessions that support viewing uncommitted changes.
pub trait Diffable: ConfigSession {
    /// Show the diff of uncommitted changes.
    fn diff(&mut self) -> impl Future<Output = Result<String>> + Send;
}

/// Sessions that support validating config before commit.
pub trait Validatable: ConfigSession {
    /// Validate the configuration without committing.
    fn validate(&mut self) -> impl Future<Output = Result<ValidationResult>> + Send;
}

/// Sessions that support confirmed commits with auto-rollback.
pub trait ConfirmableCommit: ConfigSession {
    /// Commit with automatic rollback after `timeout_minutes` if not confirmed.
    fn commit_confirmed(&mut self, timeout_minutes: u32)
    -> impl Future<Output = Result<()>> + Send;
}

/// Named configuration sessions.
pub trait NamedSession: ConfigSession {
    /// Get the session name.
    fn session_name(&self) -> &str;
}

/// Result of a configuration validation check.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the configuration is valid.
    pub valid: bool,
    /// Validation errors.
    pub errors: Vec<String>,
    /// Validation warnings.
    pub warnings: Vec<String>,
}

// =============================================================================
// GenericConfigSession — works for any vendor with config mode
// =============================================================================

/// RAII guard for a generic configuration session.
///
/// Holds `&mut GenericDriver` to prevent concurrent driver use.
/// Works for any vendor that has a privilege level with "config" in the name.
///
/// For vendor-specific features (named sessions, diff, validate),
/// use the vendor's own session type instead (e.g., `AristaConfigSession`).
pub struct GenericConfigSession<'a> {
    driver: &'a mut GenericDriver,
    original_privilege: String,
    config_privilege: String,
    consumed: bool,
}

impl<'a> GenericConfigSession<'a> {
    /// Enter a generic configuration session.
    ///
    /// Finds the configuration privilege level (any level with "config" in the name)
    /// and escalates to it.
    pub async fn new(driver: &'a mut GenericDriver) -> Result<Self> {
        let original_privilege = driver
            .privilege_manager()
            .current()
            .map(|l| l.name.clone())
            .unwrap_or_default();

        // Find the configuration privilege level
        let config_privilege = driver
            .platform()
            .privilege_levels
            .keys()
            .find(|name| name.to_lowercase().contains("config"))
            .cloned()
            .ok_or_else(|| DriverError::InvalidConfig {
                message: "No configuration privilege level found".to_string(),
            })?;

        driver.acquire_privilege(&config_privilege).await?;

        Ok(Self {
            driver,
            original_privilege,
            config_privilege,
            consumed: false,
        })
    }
}

impl ConfigSession for GenericConfigSession<'_> {
    async fn send_command(&mut self, cmd: &str) -> Result<Response> {
        self.driver.send_command(cmd).await
    }

    async fn commit(mut self) -> Result<()> {
        self.consumed = true;
        if self.original_privilege != self.config_privilege {
            self.driver
                .acquire_privilege(&self.original_privilege)
                .await?;
        }
        Ok(())
    }

    async fn abort(mut self) -> Result<()> {
        self.consumed = true;
        if self.original_privilege != self.config_privilege {
            self.driver
                .acquire_privilege(&self.original_privilege)
                .await?;
        }
        Ok(())
    }

    fn detach(mut self) -> Result<()> {
        self.consumed = true;
        Ok(())
    }
}

impl Drop for GenericConfigSession<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            warn!("GenericConfigSession dropped without explicit commit/abort/detach");
        }
    }
}
