//! Privilege level definition.

use regex::bytes::Regex;
// Future: serde support for YAML loading
// use serde::{Deserialize, Serialize};

/// A privilege level definition for a network device.
///
/// Privilege levels form a graph where each level can have a parent
/// (previous_priv) and commands to escalate/de-escalate between levels.
#[derive(Debug, Clone)]
pub struct PrivilegeLevel {
    /// Name of this privilege level (e.g., "exec", "privileged", "configuration").
    pub name: String,

    /// Regex pattern to match the prompt for this privilege level.
    pub pattern: Regex,

    /// Name of the parent privilege level (None for root level).
    pub previous_priv: Option<String>,

    /// Command to escalate TO this level from the parent.
    pub escalate_command: Option<String>,

    /// Command to de-escalate FROM this level to the parent.
    pub deescalate_command: Option<String>,

    /// Whether escalation requires authentication (password).
    pub escalate_auth: bool,

    /// Pattern to match the authentication prompt (if escalate_auth is true).
    pub escalate_prompt: Option<Regex>,

    /// Strings that must NOT be in the prompt for this level to match.
    /// Used for disambiguation (e.g., "#" matches both priv and config modes).
    pub not_contains: Vec<String>,
}

impl PrivilegeLevel {
    /// Create a new privilege level with minimal required fields.
    pub fn new(name: impl Into<String>, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.into(),
            pattern: Regex::new(pattern)?,
            previous_priv: None,
            escalate_command: None,
            deescalate_command: None,
            escalate_auth: false,
            escalate_prompt: None,
            not_contains: vec![],
        })
    }

    /// Set the parent privilege level.
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.previous_priv = Some(parent.into());
        self
    }

    /// Set the escalation command.
    pub fn with_escalate(mut self, command: impl Into<String>) -> Self {
        self.escalate_command = Some(command.into());
        self
    }

    /// Set the de-escalation command.
    pub fn with_deescalate(mut self, command: impl Into<String>) -> Self {
        self.deescalate_command = Some(command.into());
        self
    }

    /// Set that escalation requires authentication.
    pub fn with_auth(mut self, prompt_pattern: &str) -> Result<Self, regex::Error> {
        self.escalate_auth = true;
        self.escalate_prompt = Some(Regex::new(prompt_pattern)?);
        Ok(self)
    }

    /// Add a not_contains pattern.
    pub fn with_not_contains(mut self, pattern: impl Into<String>) -> Self {
        self.not_contains.push(pattern.into());
        self
    }

    /// Check if this privilege level matches a prompt.
    pub fn matches(&self, prompt: &str) -> bool {
        // Check not_contains first
        for nc in &self.not_contains {
            if prompt.contains(nc) {
                return false;
            }
        }

        // Check pattern
        self.pattern.is_match(prompt.as_bytes())
    }
}

impl Default for PrivilegeLevel {
    fn default() -> Self {
        Self {
            name: String::new(),
            pattern: Regex::new(r"[$#>]\s*$").unwrap(),
            previous_priv: None,
            escalate_command: None,
            deescalate_command: None,
            escalate_auth: false,
            escalate_prompt: None,
            not_contains: vec![],
        }
    }
}
