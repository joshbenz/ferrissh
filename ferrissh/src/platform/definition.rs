//! Platform definition for vendor-specific configurations.

use std::fmt;
use std::sync::Arc;

use indexmap::IndexMap;

use super::VendorBehavior;
use super::privilege_level::PrivilegeLevel;

/// Platform definition containing all vendor-specific configuration.
///
/// This struct is designed to be serde-compatible for future YAML loading,
/// while also supporting code-defined behavior via the VendorBehavior trait.
#[derive(Clone)]
pub struct PlatformDefinition {
    /// Platform name (e.g., "linux", "cisco_iosxe", "juniper_junos").
    pub name: String,

    /// Privilege levels for this platform.
    pub privilege_levels: IndexMap<String, PrivilegeLevel>,

    /// Default privilege level after connection.
    pub default_privilege: String,

    /// Patterns that indicate command failure.
    pub failed_when_contains: Vec<String>,

    /// Commands to run when connection is established.
    pub on_open_commands: Vec<String>,

    /// Commands to run before connection is closed.
    pub on_close_commands: Vec<String>,

    /// Terminal width for PTY.
    pub terminal_width: u32,

    /// Terminal height for PTY.
    pub terminal_height: u32,

    /// Optional vendor-specific behavior (not serializable).
    pub behavior: Option<Arc<dyn VendorBehavior>>,
}

impl PlatformDefinition {
    /// Create a new platform definition with minimal required fields.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            privilege_levels: IndexMap::new(),
            default_privilege: String::new(),
            failed_when_contains: vec![],
            on_open_commands: vec![],
            on_close_commands: vec![],
            terminal_width: 511,
            terminal_height: 24,
            behavior: None,
        }
    }

    /// Add a privilege level.
    pub fn with_privilege(mut self, level: PrivilegeLevel) -> Self {
        self.privilege_levels.insert(level.name.clone(), level);
        self
    }

    /// Set the default privilege level.
    pub fn with_default_privilege(mut self, name: impl Into<String>) -> Self {
        self.default_privilege = name.into();
        self
    }

    /// Add a failure pattern.
    pub fn with_failure_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.failed_when_contains.push(pattern.into());
        self
    }

    /// Add an on_open command.
    pub fn with_on_open_command(mut self, command: impl Into<String>) -> Self {
        self.on_open_commands.push(command.into());
        self
    }

    /// Add an on_close command.
    pub fn with_on_close_command(mut self, command: impl Into<String>) -> Self {
        self.on_close_commands.push(command.into());
        self
    }

    /// Set terminal dimensions.
    pub fn with_terminal_size(mut self, width: u32, height: u32) -> Self {
        self.terminal_width = width;
        self.terminal_height = height;
        self
    }

    /// Set vendor behavior.
    pub fn with_behavior(mut self, behavior: Arc<dyn VendorBehavior>) -> Self {
        self.behavior = Some(behavior);
        self
    }

    /// Get a privilege level by name.
    pub fn get_privilege(&self, name: &str) -> Option<&PrivilegeLevel> {
        self.privilege_levels.get(name)
    }
}

impl fmt::Debug for PlatformDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformDefinition")
            .field("name", &self.name)
            .field("privilege_levels", &self.privilege_levels)
            .field("default_privilege", &self.default_privilege)
            .field("failed_when_contains", &self.failed_when_contains)
            .field("on_open_commands", &self.on_open_commands)
            .field("on_close_commands", &self.on_close_commands)
            .field("terminal_width", &self.terminal_width)
            .field("terminal_height", &self.terminal_height)
            .field(
                "behavior",
                &self.behavior.as_ref().map(|_| "<VendorBehavior>"),
            )
            .finish()
    }
}
