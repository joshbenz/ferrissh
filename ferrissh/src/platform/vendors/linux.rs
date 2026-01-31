//! Linux platform definition.
//!
//! This is the simplest platform, supporting standard Linux/Unix shells
//! with `$` (user) and `#` (root) prompts.

use std::sync::Arc;

use async_trait::async_trait;
use regex::bytes::Regex;

use crate::driver::GenericDriver;
use crate::error::Result;
use crate::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};

/// Create the Linux platform definition.
pub fn platform() -> PlatformDefinition {
    let mut platform = PlatformDefinition::new("linux");

    // User privilege level ($ prompt)
    let user = PrivilegeLevel {
        name: "user".to_string(),
        pattern: Regex::new(r"[$]\s*$").unwrap(),
        previous_priv: None,
        escalate_command: None,
        deescalate_command: None,
        escalate_auth: false,
        escalate_prompt: None,
        not_contains: vec![],
    };

    // Root privilege level (# prompt)
    let root = PrivilegeLevel {
        name: "root".to_string(),
        pattern: Regex::new(r"[#]\s*$").unwrap(),
        previous_priv: Some("user".to_string()),
        escalate_command: Some("sudo -i".to_string()),
        deescalate_command: Some("exit".to_string()),
        escalate_auth: true,
        escalate_prompt: Some(Regex::new(r"[Pp]assword[:\s]*$").unwrap()),
        not_contains: vec![],
    };

    platform.privilege_levels.insert("user".to_string(), user);
    platform.privilege_levels.insert("root".to_string(), root);
    platform.default_privilege = "user".to_string();

    // Set terminal width to avoid line wrapping issues
    platform.terminal_width = 511;
    platform.terminal_height = 24;

    // Use default behavior
    platform.behavior = Some(Arc::new(LinuxBehavior));

    platform
}

/// Linux-specific behavior.
pub struct LinuxBehavior;

#[async_trait]
impl VendorBehavior for LinuxBehavior {
    async fn on_open(&self, _driver: &mut GenericDriver) -> Result<()> {
        // No special initialization needed for Linux
        Ok(())
    }

    async fn on_close(&self, _driver: &mut GenericDriver) -> Result<()> {
        // No special cleanup needed for Linux
        Ok(())
    }

    fn normalize_output(&self, raw: &str, command: &str) -> String {
        // Strip command echo from the beginning
        let output = raw
            .strip_prefix(command)
            .unwrap_or(raw)
            .trim_start_matches(['\r', '\n']);

        // Strip trailing prompt (last line that matches $ or #)
        let lines: Vec<&str> = output.lines().collect();
        if lines.is_empty() {
            return String::new();
        }

        // Check if last line looks like a prompt
        let last = lines.last().unwrap();
        if last.ends_with('$') || last.ends_with('#') {
            lines[..lines.len() - 1].join("\n")
        } else {
            output.to_string()
        }
    }

    fn detect_failure(&self, output: &str) -> Option<String> {
        // Common Linux error patterns
        let error_patterns = [
            "command not found",
            "No such file or directory",
            "Permission denied",
            "Operation not permitted",
        ];

        for pattern in error_patterns {
            if output.contains(pattern) {
                return Some(pattern.to_string());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_platform() {
        let platform = platform();
        assert_eq!(platform.name, "linux");
        assert_eq!(platform.privilege_levels.len(), 2);
        assert!(platform.privilege_levels.contains_key("user"));
        assert!(platform.privilege_levels.contains_key("root"));
    }

    #[test]
    fn test_user_prompt_match() {
        let platform = platform();
        let user = platform.privilege_levels.get("user").unwrap();
        assert!(user.pattern.is_match(b"user@host:~$ "));
        assert!(user.pattern.is_match(b"$ "));
        assert!(!user.pattern.is_match(b"root@host:~# "));
    }

    #[test]
    fn test_root_prompt_match() {
        let platform = platform();
        let root = platform.privilege_levels.get("root").unwrap();
        assert!(root.pattern.is_match(b"root@host:~# "));
        assert!(root.pattern.is_match(b"# "));
        assert!(!root.pattern.is_match(b"user@host:~$ "));
    }

    #[test]
    fn test_normalize_output() {
        let behavior = LinuxBehavior;

        // Command echo removal
        let raw = "uname -a\nLinux host 5.10.0 x86_64\nuser@host:~$";
        let normalized = behavior.normalize_output(raw, "uname -a");
        assert_eq!(normalized, "Linux host 5.10.0 x86_64");

        // Without command echo
        let raw = "Linux host 5.10.0 x86_64\nuser@host:~$";
        let normalized = behavior.normalize_output(raw, "uname -a");
        assert_eq!(normalized, "Linux host 5.10.0 x86_64");
    }

    #[test]
    fn test_detect_failure() {
        let behavior = LinuxBehavior;

        assert!(behavior.detect_failure("bash: foo: command not found").is_some());
        assert!(behavior.detect_failure("cat: /etc/shadow: Permission denied").is_some());
        assert!(behavior.detect_failure("Linux host 5.10.0 x86_64").is_none());
    }
}
