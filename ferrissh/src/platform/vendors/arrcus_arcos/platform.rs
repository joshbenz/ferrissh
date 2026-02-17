//! Arrcus ArcOS platform definition.
//!
//! ArcOS is built on ConfD (Tail-f/Cisco) with a J-style CLI. ConfD is a
//! management framework for network devices that provides NETCONF/YANG support
//! and generates CLI interfaces from YANG models.
//!
//! The J-style CLI mode in ConfD mimics Juniper's CLI conventions:
//! - `user@host>` exec prompt, `user@host%` config prompt
//! - Candidate configuration model (commit/rollback/validate/diff)
//! - Commands like `configure`, `commit`, `revert`, `validate`, `compare running-config`
//! - Terminal settings like `set cli screen-width`, `set cli screen-length`
//!
//! Note: ConfD J-style uses `%` for config mode, NOT `#` (which is Juniper JUNOS).
//! This is confirmed from the ConfD default `prompt2 = \u@\h\M \t%`.

use crate::platform::{PlatformDefinition, PrivilegeLevel};

pub const PLATFORM_NAME: &str = "arrcus_arcos";

/// Create the Arrcus ArcOS platform definition.
pub fn platform() -> PlatformDefinition {
    // Exec (operational) mode: user@host>
    let exec = PrivilegeLevel::new("exec", r"(?mi)^[\w\-.@()/:]{1,63}>\s?$").unwrap();

    // Configuration mode: user@host%
    let configuration = PrivilegeLevel::new("configuration", r"(?mi)^[\w\-.@()/:]{1,63}%\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("configure")
        .with_deescalate("exit configuration-mode");

    PlatformDefinition::new(PLATFORM_NAME)
        .with_privilege(exec)
        .with_privilege(configuration)
        .with_default_privilege("exec")
        .with_failure_pattern("is ambiguous")
        .with_failure_pattern("No valid completions")
        .with_failure_pattern("unknown command")
        .with_failure_pattern("syntax error")
        .with_on_open_command("set cli screen-width 511")
        .with_on_open_command("set cli screen-length 0")
        .with_on_open_command("set cli complete-on-space off")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arcos_platform() {
        let p = platform();
        assert_eq!(p.name, "arrcus_arcos");
        assert_eq!(p.privilege_levels.len(), 2);
        assert_eq!(p.default_privilege, "exec");
    }

    #[test]
    fn test_exec_prompt_match() {
        let p = platform();
        let exec = p.get_privilege("exec").unwrap();

        assert!(exec.pattern.is_match(b"clab@router>"));
        assert!(exec.pattern.is_match(b"clab@router> "));
        assert!(exec.pattern.is_match(b"admin@leaf-1>"));
        assert!(exec.pattern.is_match(b"admin@leaf-1> "));
        assert!(exec.pattern.is_match(b"admin@spine.lab>"));
        assert!(exec.pattern.is_match(b"root@host>"));

        // Should NOT match config prompt
        assert!(!exec.pattern.is_match(b"clab@router%"));
        assert!(!exec.pattern.is_match(b"admin@leaf-1%"));
    }

    #[test]
    fn test_configuration_prompt_match() {
        let p = platform();
        let config = p.get_privilege("configuration").unwrap();

        assert!(config.pattern.is_match(b"clab@router%"));
        assert!(config.pattern.is_match(b"clab@router% "));
        assert!(config.pattern.is_match(b"admin@leaf-1%"));
        assert!(config.pattern.is_match(b"admin@leaf-1% "));
        assert!(config.pattern.is_match(b"admin@spine.lab%"));
        assert!(config.pattern.is_match(b"root@host%"));

        // Should NOT match exec prompt
        assert!(!config.pattern.is_match(b"clab@router>"));
        assert!(!config.pattern.is_match(b"admin@leaf-1>"));
    }

    #[test]
    fn test_privilege_graph() {
        let p = platform();
        let config = p.get_privilege("configuration").unwrap();

        assert_eq!(config.previous_priv.as_deref(), Some("exec"));
        assert_eq!(config.escalate_command.as_deref(), Some("configure"));
        assert_eq!(
            config.deescalate_command.as_deref(),
            Some("exit configuration-mode")
        );
    }

    #[test]
    fn test_failure_patterns() {
        let p = platform();
        assert!(p.failed_when_contains.contains(&"syntax error".to_string()));
        assert!(p.failed_when_contains.contains(&"unknown command".to_string()));
        assert!(p.failed_when_contains.contains(&"is ambiguous".to_string()));
        assert!(p
            .failed_when_contains
            .contains(&"No valid completions".to_string()));
    }

    #[test]
    fn test_on_open_commands() {
        let p = platform();
        assert_eq!(p.on_open_commands.len(), 3);
        assert!(p
            .on_open_commands
            .contains(&"set cli screen-width 511".to_string()));
        assert!(p
            .on_open_commands
            .contains(&"set cli screen-length 0".to_string()));
        assert!(p
            .on_open_commands
            .contains(&"set cli complete-on-space off".to_string()));
    }
}
