//! Arrcus ArcOS configuration session.
//!
//! ArcOS uses ConfD C-style CLI. This module re-exports the generic
//! [`ConfDConfigSession`] and provides a convenience constructor.
//!
//! # Example
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

use crate::driver::GenericDriver;
use crate::error::Result;
use crate::platform::confd::ConfDConfigSession;

use super::platform::PLATFORM_NAME;

/// Type alias for Arrcus ArcOS configuration sessions.
///
/// ArcOS uses ConfD C-style CLI. See [`ConfDConfigSession`] for
/// full documentation of available methods.
pub type ArrcusConfigSession<'a> = ConfDConfigSession<'a>;

/// Create an Arrcus ArcOS configuration session.
///
/// Convenience wrapper around [`ConfDConfigSession::new()`] that
/// pre-fills the platform name. Equivalent to:
///
/// ```rust,ignore
/// ConfDConfigSession::new(driver, "arrcus_arcos").await
/// ```
pub async fn config_session(driver: &mut GenericDriver) -> Result<ConfDConfigSession<'_>> {
    ConfDConfigSession::new(driver, PLATFORM_NAME).await
}
