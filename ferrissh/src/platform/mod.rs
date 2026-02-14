//! Platform definitions for multi-vendor support.
//!
//! This module defines vendor-specific configurations including
//! prompt patterns, privilege levels, and device behavior.

mod definition;
mod privilege_level;
pub mod vendors;

pub use definition::PlatformDefinition;
pub use privilege_level::PrivilegeLevel;

/// Built-in platform selection.
///
/// Use this enum to select a built-in platform or provide a custom one.
///
/// # Example
///
/// ```rust
/// use ferrissh::Platform;
///
/// // Built-in platform
/// let platform = Platform::Linux;
///
/// // Custom platform
/// use ferrissh::PlatformDefinition;
/// let custom = Platform::Custom(PlatformDefinition::new("my_device"));
/// ```
#[derive(Debug, Clone)]
pub enum Platform {
    /// Standard Linux/Unix shell.
    Linux,
    /// Juniper JUNOS.
    JuniperJunos,
    /// User-provided platform definition.
    Custom(PlatformDefinition),
}

impl From<Platform> for PlatformDefinition {
    fn from(p: Platform) -> Self {
        match p {
            Platform::Linux => vendors::linux::platform(),
            Platform::JuniperJunos => vendors::juniper::platform(),
            Platform::Custom(def) => def,
        }
    }
}

/// Trait for vendor-specific output post-processing.
///
/// Most vendor differences are handled by `PlatformDefinition` data fields
/// (on_open_commands, failed_when_contains, etc.). The driver handles
/// universal output normalization (stripping command echo and trailing prompt).
///
/// This trait is only needed for vendors with genuinely unique output formats,
/// like Juniper's `[edit]` context lines. Most platforms don't need it.
pub trait VendorBehavior: Send + Sync {
    /// Post-process output after universal stripping has been applied.
    ///
    /// The input has already had the command echo and trailing prompt removed.
    /// Use this for vendor-specific cleanup (e.g., filtering `[edit]` lines).
    fn post_process_output(&self, output: &str) -> String {
        output.to_string()
    }
}
