//! Privilege level management with graph-based navigation.

use std::collections::{HashMap, HashSet, VecDeque};

use indexmap::IndexMap;
use regex::bytes::Regex;

use crate::error::{DriverError, Result};
use crate::platform::PrivilegeLevel;

/// Manages privilege level navigation using a graph structure.
///
/// Privilege levels form a bidirectional graph where each level connects
/// to its parent (previous_priv). This manager handles:
/// - Determining current privilege from a prompt
/// - Finding paths between privilege levels
/// - Tracking current privilege state
#[derive(Debug)]
pub struct PrivilegeManager {
    /// All defined privilege levels.
    levels: IndexMap<String, PrivilegeLevel>,

    /// Adjacency list for the privilege graph.
    graph: HashMap<String, HashSet<String>>,

    /// Current privilege level name.
    current: Option<String>,
}

impl PrivilegeManager {
    /// Create a new privilege manager from privilege level definitions.
    pub fn new(levels: IndexMap<String, PrivilegeLevel>) -> Self {
        let graph = Self::build_graph(&levels);

        // Find the root level (no previous_priv)
        let current = levels
            .iter()
            .find(|(_, l)| l.previous_priv.is_none())
            .map(|(name, _)| name.clone());

        Self {
            levels,
            graph,
            current,
        }
    }

    /// Build the bidirectional adjacency list from privilege definitions.
    fn build_graph(levels: &IndexMap<String, PrivilegeLevel>) -> HashMap<String, HashSet<String>> {
        let mut graph: HashMap<String, HashSet<String>> = HashMap::new();

        for (name, level) in levels {
            // Ensure this node exists in the graph
            graph.entry(name.clone()).or_default();

            // Add bidirectional edge to parent
            if let Some(ref parent) = level.previous_priv {
                graph.entry(name.clone()).or_default().insert(parent.clone());
                graph.entry(parent.clone()).or_default().insert(name.clone());
            }
        }

        graph
    }

    /// Determine the current privilege level from a prompt string.
    pub fn determine_from_prompt(&self, prompt: &str) -> Result<&PrivilegeLevel> {
        let prompt_bytes = prompt.as_bytes();

        for level in self.levels.values() {
            // Check not_contains patterns first
            if level
                .not_contains
                .iter()
                .any(|nc| prompt.contains(nc))
            {
                continue;
            }

            // Check if prompt matches this level's pattern
            if level.pattern.is_match(prompt_bytes) {
                return Ok(level);
            }
        }

        Err(DriverError::UnknownPrivilege {
            prompt: prompt.to_string(),
        }
        .into())
    }

    /// Get the current privilege level.
    pub fn current(&self) -> Option<&PrivilegeLevel> {
        self.current.as_ref().and_then(|name| self.levels.get(name))
    }

    /// Set the current privilege level by name.
    pub fn set_current(&mut self, name: &str) -> Result<()> {
        if self.levels.contains_key(name) {
            self.current = Some(name.to_string());
            Ok(())
        } else {
            Err(DriverError::UnknownPrivilege {
                prompt: name.to_string(),
            }
            .into())
        }
    }

    /// Get a privilege level by name.
    pub fn get(&self, name: &str) -> Option<&PrivilegeLevel> {
        self.levels.get(name)
    }

    /// Find the shortest path from one privilege level to another.
    ///
    /// Returns a list of privilege level names to traverse, including
    /// both the start and end nodes.
    pub fn find_path(&self, from: &str, to: &str) -> Result<Vec<String>> {
        if from == to {
            return Ok(vec![from.to_string()]);
        }

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
                return Ok(path);
            }

            if let Some(neighbors) = self.graph.get(&current) {
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
        let from_level = self.levels.get(from)?;
        let to_level = self.levels.get(to)?;

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
        self.levels.keys()
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

    #[test]
    fn test_determine_privilege() {
        let manager = PrivilegeManager::new(make_test_levels());

        let level = manager.determine_from_prompt("router>").unwrap();
        assert_eq!(level.name, "user");

        let level = manager.determine_from_prompt("router#").unwrap();
        assert_eq!(level.name, "privileged");

        let level = manager.determine_from_prompt("router(config)#").unwrap();
        assert_eq!(level.name, "configuration");
    }

    #[test]
    fn test_find_path() {
        let manager = PrivilegeManager::new(make_test_levels());

        let path = manager.find_path("user", "configuration").unwrap();
        assert_eq!(path, vec!["user", "privileged", "configuration"]);

        let path = manager.find_path("configuration", "user").unwrap();
        assert_eq!(path, vec!["configuration", "privileged", "user"]);

        let path = manager.find_path("user", "user").unwrap();
        assert_eq!(path, vec!["user"]);
    }

    #[test]
    fn test_get_transition() {
        let manager = PrivilegeManager::new(make_test_levels());

        // Escalating user -> privileged
        let trans = manager.get_transition("user", "privileged").unwrap();
        assert_eq!(trans.command, "enable");
        assert!(trans.auth_prompt.is_some());

        // De-escalating privileged -> user
        let trans = manager.get_transition("privileged", "user").unwrap();
        assert_eq!(trans.command, "disable");
        assert!(trans.auth_prompt.is_none());
    }
}
