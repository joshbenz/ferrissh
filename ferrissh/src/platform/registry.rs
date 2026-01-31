//! Global platform registry for looking up platform definitions.

use std::collections::HashMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;

use super::definition::PlatformDefinition;
use super::vendors;
use crate::error::{PlatformError, Result};

/// Global platform registry.
static REGISTRY: Lazy<RwLock<PlatformRegistry>> = Lazy::new(|| {
    let mut registry = PlatformRegistry::new();
    registry.register_builtin_platforms();
    RwLock::new(registry)
});

/// Registry for platform definitions.
#[derive(Debug, Default)]
pub struct PlatformRegistry {
    platforms: HashMap<String, PlatformDefinition>,
}

impl PlatformRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            platforms: HashMap::new(),
        }
    }

    /// Get the global registry.
    pub fn global() -> &'static RwLock<PlatformRegistry> {
        &REGISTRY
    }

    /// Register built-in platforms.
    fn register_builtin_platforms(&mut self) {
        // Register Linux platform
        self.platforms.insert("linux".to_string(), vendors::linux::platform());
    }

    /// Register a platform definition.
    pub fn register(&mut self, platform: PlatformDefinition) -> Result<()> {
        if self.platforms.contains_key(&platform.name) {
            return Err(PlatformError::AlreadyRegistered {
                name: platform.name.clone(),
            }
            .into());
        }
        self.platforms.insert(platform.name.clone(), platform);
        Ok(())
    }

    /// Get a platform by name.
    pub fn get(&self, name: &str) -> Option<&PlatformDefinition> {
        self.platforms.get(name)
    }

    /// Check if a platform is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.platforms.contains_key(name)
    }

    /// List all registered platform names.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.platforms.keys()
    }

    /// Get a mutable reference to a platform.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PlatformDefinition> {
        self.platforms.get_mut(name)
    }
}
