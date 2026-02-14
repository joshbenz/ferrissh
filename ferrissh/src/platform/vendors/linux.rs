//! Linux platform definition.
//!
//! This is the simplest platform, supporting standard Linux/Unix shells
//! with `$` (user) and `#` (root) prompts.

use crate::platform::{PlatformDefinition, PrivilegeLevel};

/// Create the Linux platform definition.
pub fn platform() -> PlatformDefinition {
    let user = PrivilegeLevel::new("user", r"[$]\s*$").unwrap();

    let root = PrivilegeLevel::new("root", r"[#]\s*$")
        .unwrap()
        .with_parent("user")
        .with_escalate("sudo -i")
        .with_deescalate("exit")
        .with_auth(r"[Pp]assword[:\s]*$")
        .unwrap();

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
