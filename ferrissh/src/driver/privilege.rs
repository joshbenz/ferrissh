//! Privilege level management with graph-based navigation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use indexmap::IndexMap;
use log::trace;
use regex::bytes::Regex;

use crate::error::{DriverError, Result};
use crate::platform::PrivilegeLevel;

/// Immutable privilege data shared across all channels on a session.
///
/// Built once per session and wrapped in `Arc` so that each `Channel`
/// can reference it without cloning the level definitions or graph.
#[derive(Debug)]
pub struct PrivilegeLevelsBase {
    levels: IndexMap<String, PrivilegeLevel>,
    graph: HashMap<String, HashSet<String>>,
}

impl PrivilegeLevelsBase {
    /// Create a new base from privilege level definitions.
    pub fn new(levels: IndexMap<String, PrivilegeLevel>) -> Self {
        let graph = Self::build_graph(&levels);
        Self { levels, graph }
    }

    /// Build the bidirectional adjacency list from privilege definitions.
    pub(crate) fn build_graph(
        levels: &IndexMap<String, PrivilegeLevel>,
    ) -> HashMap<String, HashSet<String>> {
        let mut graph: HashMap<String, HashSet<String>> = HashMap::new();

        for (name, level) in levels {
            // Ensure this node exists in the graph
            graph.entry(name.clone()).or_default();

            // Add bidirectional edge to parent
            if let Some(ref parent) = level.previous_priv {
                graph
                    .entry(name.clone())
                    .or_default()
                    .insert(parent.clone());
                graph
                    .entry(parent.clone())
                    .or_default()
                    .insert(name.clone());
            }
        }

        graph
    }

    /// Get a privilege level by name.
    pub fn get(&self, name: &str) -> Option<&PrivilegeLevel> {
        self.levels.get(name)
    }

    /// Find the root privilege level name (no previous_priv).
    pub fn root_level_name(&self) -> Option<String> {
        self.levels
            .iter()
            .find(|(_, l)| l.previous_priv.is_none())
            .map(|(name, _)| name.clone())
    }
}

/// Copy-on-write overlay for dynamically registered privilege levels.
///
/// Used by vendor-specific config sessions (e.g., Arista named sessions)
/// that temporarily add privilege levels at runtime. The overlay graph
/// is rebuilt from merged (base + dynamic) levels.
#[derive(Debug)]
struct DynamicOverlay {
    levels: IndexMap<String, PrivilegeLevel>,
    graph: HashMap<String, HashSet<String>>,
}

/// Manages privilege level navigation using a graph structure.
///
/// Privilege levels form a bidirectional graph where each level connects
/// to its parent (previous_priv). This manager handles:
/// - Determining current privilege from a prompt
/// - Finding paths between privilege levels
/// - Tracking current privilege state
///
/// Holds an `Arc<PrivilegeLevelsBase>` for shared immutable data, with an
/// optional copy-on-write `DynamicOverlay` for runtime-registered levels.
#[derive(Debug)]
pub struct PrivilegeManager {
    /// Shared immutable privilege level data.
    base: Arc<PrivilegeLevelsBase>,

    /// Current privilege level name.
    current: Option<String>,

    /// Copy-on-write: None until register_dynamic_level() is called.
    dynamic: Option<DynamicOverlay>,
}

impl PrivilegeManager {
    /// Create a new privilege manager from shared privilege level data.
    ///
    /// No cloning — just increments the Arc reference count.
    pub fn new(base: Arc<PrivilegeLevelsBase>) -> Self {
        let current = base.root_level_name();

        Self {
            base,
            current,
            dynamic: None,
        }
    }

    /// Determine the current privilege level from a prompt string.
    ///
    /// Checks dynamic overlay first (if present), then base levels.
    pub fn determine_from_prompt(&self, prompt: &str) -> Result<&PrivilegeLevel> {
        let prompt_bytes = prompt.as_bytes();

        // Check dynamic levels first
        if let Some(ref overlay) = self.dynamic {
            for level in overlay.levels.values() {
                if level.not_contains.iter().any(|nc| prompt.contains(nc)) {
                    continue;
                }
                if level.pattern.is_match(prompt_bytes) {
                    trace!(
                        "prompt {:?} matched dynamic privilege level {:?}",
                        prompt, level.name
                    );
                    return Ok(level);
                }
            }
        }

        // Check base levels
        for level in self.base.levels.values() {
            if level.not_contains.iter().any(|nc| prompt.contains(nc)) {
                continue;
            }
            if level.pattern.is_match(prompt_bytes) {
                trace!(
                    "prompt {:?} matched privilege level {:?}",
                    prompt, level.name
                );
                return Ok(level);
            }
        }

        let total = self.base.levels.len() + self.dynamic.as_ref().map_or(0, |d| d.levels.len());
        trace!(
            "no privilege level matched prompt {:?} (checked {} levels)",
            prompt, total
        );
        Err(DriverError::UnknownPrivilege {
            prompt: prompt.to_string(),
        }
        .into())
    }

    /// Get the current privilege level.
    pub fn current(&self) -> Option<&PrivilegeLevel> {
        self.current.as_ref().and_then(|name| self.get(name))
    }

    /// Set the current privilege level by name.
    pub fn set_current(&mut self, name: &str) -> Result<()> {
        if self.contains_key(name) {
            self.current = Some(name.to_string());
            Ok(())
        } else {
            Err(DriverError::UnknownPrivilege {
                prompt: name.to_string(),
            }
            .into())
        }
    }

    /// Get a privilege level by name, checking dynamic overlay first.
    pub fn get(&self, name: &str) -> Option<&PrivilegeLevel> {
        if let Some(ref overlay) = self.dynamic
            && let Some(level) = overlay.levels.get(name)
        {
            return Some(level);
        }
        self.base.get(name)
    }

    /// Check if a privilege level exists (in dynamic or base).
    fn contains_key(&self, name: &str) -> bool {
        if let Some(ref overlay) = self.dynamic
            && overlay.levels.contains_key(name)
        {
            return true;
        }
        self.base.levels.contains_key(name)
    }

    /// Get the active graph (overlay if present, else base).
    fn graph(&self) -> &HashMap<String, HashSet<String>> {
        if let Some(ref overlay) = self.dynamic {
            &overlay.graph
        } else {
            &self.base.graph
        }
    }

    /// Find the shortest path from one privilege level to another.
    ///
    /// Returns a list of privilege level names to traverse, including
    /// both the start and end nodes.
    pub fn find_path(&self, from: &str, to: &str) -> Result<Vec<String>> {
        if from == to {
            return Ok(vec![from.to_string()]);
        }

        let graph = self.graph();

        // BFS to find shortest path
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(from.to_string());
        visited.insert(from.to_string());

        while let Some(current) = queue.pop_front() {
            if current == to {
                // Reconstruct path
                let mut path = vec![to.to_string()];
                let mut node = to.to_string();

                while let Some(prev) = parent.get(&node) {
                    path.push(prev.clone());
                    node = prev.clone();
                }

                path.reverse();
                trace!("find_path: {} -> {} = {:?}", from, to, path);
                return Ok(path);
            }

            if let Some(neighbors) = graph.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        parent.insert(neighbor.clone(), current.clone());
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        Err(DriverError::NoPrivilegePath {
            from: from.to_string(),
            to: to.to_string(),
        }
        .into())
    }

    /// Get the transition from one level to an adjacent level.
    ///
    /// Returns (command, needs_auth, auth_prompt) for the transition.
    pub fn get_transition(&self, from: &str, to: &str) -> Option<TransitionInfo> {
        let from_level = self.get(from)?;
        let to_level = self.get(to)?;

        // Check if we're escalating (going to a child of current)
        if to_level.previous_priv.as_deref() == Some(from) {
            // Escalating: use escalate_command from target
            return Some(TransitionInfo {
                command: to_level.escalate_command.clone()?,
                auth_prompt: to_level.escalate_prompt.clone(),
            });
        }

        // Check if we're de-escalating (going to parent)
        if from_level.previous_priv.as_deref() == Some(to) {
            // De-escalating: use deescalate_command from current
            return Some(TransitionInfo {
                command: from_level.deescalate_command.clone()?,
                auth_prompt: None,
            });
        }

        None
    }

    /// Get all privilege level names.
    pub fn level_names(&self) -> impl Iterator<Item = &String> {
        let dynamic_keys: Box<dyn Iterator<Item = &String>> =
            if let Some(ref overlay) = self.dynamic {
                Box::new(overlay.levels.keys())
            } else {
                Box::new(std::iter::empty())
            };
        dynamic_keys.chain(self.base.levels.keys())
    }

    /// Iterate over all privilege levels (dynamic overlay first, then base).
    pub fn all_levels(&self) -> impl Iterator<Item = &PrivilegeLevel> {
        let dynamic_iter: Box<dyn Iterator<Item = &PrivilegeLevel>> =
            if let Some(ref overlay) = self.dynamic {
                Box::new(overlay.levels.values())
            } else {
                Box::new(std::iter::empty())
            };
        dynamic_iter.chain(self.base.levels.values())
    }

    /// Register a dynamic privilege level at runtime.
    ///
    /// Used by vendor-specific config sessions (e.g., Arista named sessions)
    /// that need to add temporary privilege levels for session prompts.
    ///
    /// After calling this, you must also call `Channel::rebuild_prompt_pattern()`
    /// so the channel's prompt pattern list includes the new pattern.
    pub fn register_dynamic_level(&mut self, level: PrivilegeLevel) {
        let overlay = self.dynamic.get_or_insert_with(|| DynamicOverlay {
            levels: IndexMap::new(),
            graph: HashMap::new(),
        });
        let name = level.name.clone();
        overlay.levels.insert(name, level);

        // Rebuild overlay graph from merged (base + dynamic) levels
        let mut merged = self.base.levels.clone();
        merged.extend(overlay.levels.iter().map(|(k, v)| (k.clone(), v.clone())));
        overlay.graph = PrivilegeLevelsBase::build_graph(&merged);
    }

    /// Remove a dynamically registered privilege level.
    ///
    /// After calling this, you must also call `Channel::rebuild_prompt_pattern()`
    /// so the channel's prompt pattern list no longer includes the removed pattern.
    pub fn remove_dynamic_level(&mut self, name: &str) {
        if let Some(ref mut overlay) = self.dynamic {
            overlay.levels.shift_remove(name);
            if overlay.levels.is_empty() {
                self.dynamic = None;
            } else {
                // Rebuild overlay graph from merged levels
                let mut merged = self.base.levels.clone();
                merged.extend(overlay.levels.iter().map(|(k, v)| (k.clone(), v.clone())));
                overlay.graph = PrivilegeLevelsBase::build_graph(&merged);
            }
        }
    }
}

/// Information about a privilege level transition.
#[derive(Debug, Clone)]
pub struct TransitionInfo {
    /// Command to execute for the transition.
    pub command: String,

    /// Pattern to match for auth prompt. If `Some`, authentication is required.
    pub auth_prompt: Option<Regex>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_levels() -> IndexMap<String, PrivilegeLevel> {
        let user = PrivilegeLevel::new("user", r">\s*$").unwrap();

        let privileged = PrivilegeLevel::new("privileged", r"#\s*$")
            .unwrap()
            .with_parent("user")
            .with_escalate("enable")
            .with_deescalate("disable")
            .with_auth(r"[Pp]assword:\s*$")
            .unwrap()
            .with_not_contains("(config)");

        let configuration = PrivilegeLevel::new("configuration", r"\(config[^)]*\)#\s*$")
            .unwrap()
            .with_parent("privileged")
            .with_escalate("configure terminal")
            .with_deescalate("end");

        let mut levels = IndexMap::new();
        levels.insert("user".to_string(), user);
        levels.insert("privileged".to_string(), privileged);
        levels.insert("configuration".to_string(), configuration);
        levels
    }

    fn make_test_base() -> Arc<PrivilegeLevelsBase> {
        Arc::new(PrivilegeLevelsBase::new(make_test_levels()))
    }

    #[test]
    fn test_determine_privilege() {
        let manager = PrivilegeManager::new(make_test_base());

        let level = manager.determine_from_prompt("router>").unwrap();
        assert_eq!(level.name, "user");

        let level = manager.determine_from_prompt("router#").unwrap();
        assert_eq!(level.name, "privileged");

        let level = manager.determine_from_prompt("router(config)#").unwrap();
        assert_eq!(level.name, "configuration");
    }

    #[test]
    fn test_find_path() {
        let manager = PrivilegeManager::new(make_test_base());

        let path = manager.find_path("user", "configuration").unwrap();
        assert_eq!(path, vec!["user", "privileged", "configuration"]);

        let path = manager.find_path("configuration", "user").unwrap();
        assert_eq!(path, vec!["configuration", "privileged", "user"]);

        let path = manager.find_path("user", "user").unwrap();
        assert_eq!(path, vec!["user"]);
    }

    #[test]
    fn test_get_transition() {
        let manager = PrivilegeManager::new(make_test_base());

        // Escalating user -> privileged
        let trans = manager.get_transition("user", "privileged").unwrap();
        assert_eq!(trans.command, "enable");
        assert!(trans.auth_prompt.is_some());

        // De-escalating privileged -> user
        let trans = manager.get_transition("privileged", "user").unwrap();
        assert_eq!(trans.command, "disable");
        assert!(trans.auth_prompt.is_none());
    }

    #[test]
    fn test_dynamic_level_registration() {
        let mut manager = PrivilegeManager::new(make_test_base());

        // Register a dynamic config session level
        let session_level = PrivilegeLevel::new("config_session_test", r"\(config\-s\-test\)#\s*$")
            .unwrap()
            .with_parent("privileged")
            .with_escalate("configure session test")
            .with_deescalate("end");

        manager.register_dynamic_level(session_level);

        // Dynamic level should be findable
        assert!(manager.get("config_session_test").is_some());

        // Path should include dynamic level
        let path = manager.find_path("user", "config_session_test").unwrap();
        assert_eq!(path, vec!["user", "privileged", "config_session_test"]);

        // all_levels should include dynamic level
        let all: Vec<&str> = manager.all_levels().map(|l| l.name.as_str()).collect();
        assert!(all.contains(&"config_session_test"));
        assert_eq!(all.len(), 4); // 3 base + 1 dynamic

        // Remove dynamic level
        manager.remove_dynamic_level("config_session_test");
        assert!(manager.get("config_session_test").is_none());
        assert!(manager.dynamic.is_none()); // overlay cleared entirely

        // all_levels should be back to base only
        let all: Vec<&str> = manager.all_levels().map(|l| l.name.as_str()).collect();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_arc_sharing() {
        let base = make_test_base();
        let m1 = PrivilegeManager::new(base.clone());
        let m2 = PrivilegeManager::new(base.clone());

        // Both managers share the same Arc
        assert!(Arc::ptr_eq(&m1.base, &m2.base));

        // Both can independently determine privilege
        let l1 = m1.determine_from_prompt("router>").unwrap();
        let l2 = m2.determine_from_prompt("router#").unwrap();
        assert_eq!(l1.name, "user");
        assert_eq!(l2.name, "privileged");
    }
}
