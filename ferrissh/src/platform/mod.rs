//! Platform definitions for multi-vendor support.
//!
//! This module defines vendor-specific configurations including
//! prompt patterns, privilege levels, and device behavior.

mod definition;
mod privilege_level;
mod registry;
pub mod vendors;

pub use definition::PlatformDefinition;
pub use privilege_level::PrivilegeLevel;
pub use registry::PlatformRegistry;

use async_trait::async_trait;

use crate::driver::GenericDriver;
use crate::error::Result;

/// Trait for vendor-specific behavior.
#[async_trait]
pub trait VendorBehavior: Send + Sync {
    /// Called after connection is established.
    async fn on_open(&self, driver: &mut GenericDriver) -> Result<()>;

    /// Called before connection is closed.
    async fn on_close(&self, driver: &mut GenericDriver) -> Result<()>;

    /// Normalize command output (strip command echo, trailing prompt).
    fn normalize_output(&self, raw: &str, command: &str) -> String;

    /// Detect command failure from output.
    fn detect_failure(&self, output: &str) -> Option<String>;
}

/// Default vendor behavior implementation.
pub struct DefaultBehavior;

#[async_trait]
impl VendorBehavior for DefaultBehavior {
    async fn on_open(&self, _driver: &mut GenericDriver) -> Result<()> {
        Ok(())
    }

    async fn on_close(&self, _driver: &mut GenericDriver) -> Result<()> {
        Ok(())
    }

    fn normalize_output(&self, raw: &str, command: &str) -> String {
        // Strip command echo from the beginning
        let output = raw
            .strip_prefix(command)
            .unwrap_or(raw)
            .trim_start_matches(['\r', '\n']);

        // Strip trailing prompt (last line)
        if let Some(pos) = output.rfind('\n') {
            output[..pos].to_string()
        } else {
            output.to_string()
        }
    }

    fn detect_failure(&self, _output: &str) -> Option<String> {
        None
    }
}
