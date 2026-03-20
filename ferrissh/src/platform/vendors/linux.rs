//! Linux platform definition.
//!
//! This is the simplest platform, supporting standard Linux/Unix shells
//! with `$` (user) and `#` (root) prompts.

use std::sync::LazyLock;

use regex::bytes::Regex;

use crate::platform::{PlatformDefinition, PrivilegeLevel};

static USER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[$]\s*$").unwrap());
static ROOT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[#]\s*$").unwrap());
static ROOT_AUTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[Pp]assword[:\s]*$").unwrap());

/// Create the Linux platform definition.
pub fn platform() -> PlatformDefinition {
    let user = PrivilegeLevel::from_regex("user", USER_PATTERN.clone());

    let root = PrivilegeLevel::from_regex("root", ROOT_PATTERN.clone())
        .with_parent("user")
        .with_escalate("sudo -i")
        .with_deescalate("exit")
        .with_auth_regex(ROOT_AUTH.clone());

    PlatformDefinition::new("linux")
        .with_privilege(user)
        .with_privilege(root)
        .with_default_privilege("user")
        .with_failure_pattern("command not found")
        .with_failure_pattern("No such file or directory")
        .with_failure_pattern("Permission denied")
        .with_failure_pattern("Operation not permitted")
        .with_terminal_size(511, 24)
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
    fn test_failed_when_contains() {
        let platform = platform();
        assert!(!platform.failed_when_contains.is_empty());
        assert!(
            platform
                .failed_when_contains
                .contains(&"command not found".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"Permission denied".to_string())
        );
    }
}
