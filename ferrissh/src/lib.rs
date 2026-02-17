//! # Ferrissh
//!
//! Async SSH CLI scraper library for network device automation.
//!
//! Ferrissh provides a high-level async API for interacting with network devices
//! over SSH, similar to Python's scrapli and netmiko libraries.
//!
//! ## Features
//!
//! - Async SSH connections via russh
//! - Multi-vendor support (Linux, Juniper, with extensible platform system)
//! - Efficient pattern buffer matching (scrapli-style tail search)
//! - Privilege level management with graph-based navigation
//! - Easy vendor extensibility
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ferrissh::{DriverBuilder, Driver, Platform};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ferrissh::Error> {
//!     let mut driver = DriverBuilder::new("192.168.1.1")
//!         .username("admin")
//!         .password("secret")
//!         .platform(Platform::Linux)
//!         .build()?;
//!
//!     driver.open().await?;
//!
//!     let response = driver.send_command("uname -a").await?;
//!     println!("{}", response.result);
//!
//!     driver.close().await?;
//!     Ok(())
//! }
//! ```

pub mod channel;
pub mod driver;
pub mod error;
pub mod platform;
pub mod transport;

// Re-export main types for convenience
pub use driver::{
    ConfigSession, ConfirmableCommit, Diffable, Driver, DriverBuilder, GenericConfigSession,
    GenericDriver, InteractiveBuilder, InteractiveEvent, InteractiveResult, NamedSession, Response,
    Validatable, ValidationResult,
};
pub use error::Error;
pub use platform::{
    ConfDConfigSession, ConfDJStyleConfigSession, Platform, PlatformDefinition, PrivilegeLevel,
};
pub use transport::HostKeyVerification;
