//! Arista EOS platform definition.
//!
//! Supports Arista devices running EOS with the following privilege levels:
//! - `exec` - User EXEC mode with `>` prompt
//! - `privilege_exec` - Privileged EXEC mode with `#` prompt
//! - `configuration` - Configuration mode with `(config*)#` prompt
//!
//! Prompt patterns are adapted from [scrapli](https://github.com/carlmontanari/scrapli).
//!
//! # Prompt Examples
//!
//! ```text
//! switch>                            # exec mode
//! switch#                            # privilege_exec mode
//! switch(config)#                    # configuration mode
//! switch(config-if-Et1)#             # config sub-mode (interface)
//! switch(config-s-my_ses)#           # named config session
//! ```
//!
//! # Privilege Graph
//!
//! ```text
//! ┌──────┐  enable     ┌────────────────┐  configure terminal  ┌───────────────┐
//! │ exec ├──────────────► privilege_exec ├──────────────────────► configuration │
//! │  >   │   disable   │       #        │        end           │  (config*)#   │
//! └──────┘◄────────────┴────────────────┘◄─────────────────────┴───────────────┘
//! ```

use crate::platform::{PlatformDefinition, PrivilegeLevel};

/// Create the Arista EOS platform definition.
///
/// Prompt patterns adapted from scrapli's EOS driver.
/// Uses `(?mi)` flags for multiline (^ matches line start) and case-insensitive matching.
pub fn platform() -> PlatformDefinition {
    // Exec mode - ">" prompt
    let exec = PrivilegeLevel::new("exec", r"(?mi)^[\w.\-@()/: ]{1,63}>\s?$").unwrap();

    // Privileged EXEC mode - "#" prompt
    // not_contains "(config" prevents matching config mode prompts
    let privilege_exec = PrivilegeLevel::new("privilege_exec", r"(?mi)^[\w.\-@()/: ]{1,63}#\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("enable")
        .with_deescalate("disable")
        .with_auth(r"(?mi)^password:\s?$")
        .unwrap()
        .with_not_contains("(config");

    // Configuration mode - "(config*)" prompt
    // not_contains "(config-s-" prevents matching named session prompts
    let configuration = PrivilegeLevel::new(
        "configuration",
        r"(?mi)^[\w.\-@()/: ]{1,63}\(config[\w.\-@/:+]{0,63}\)#\s?$",
    )
    .unwrap()
    .with_parent("privilege_exec")
    .with_escalate("configure terminal")
    .with_deescalate("end")
    .with_not_contains("(config-s-");

    PlatformDefinition::new("arista_eos")
        .with_privilege(exec)
        .with_privilege(privilege_exec)
        .with_privilege(configuration)
        .with_default_privilege("privilege_exec")
        .with_failure_pattern("% Ambiguous command")
        .with_failure_pattern("% Error")
        .with_failure_pattern("% Incomplete command")
        .with_failure_pattern("% Invalid input")
        .with_failure_pattern("% Cannot commit")
        .with_failure_pattern("% Unavailable command")
        .with_failure_pattern("% Duplicate sequence number")
        .with_on_open_command("terminal length 0")
        .with_on_open_command("terminal width 32767")
        .with_terminal_size(32767, 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arista_platform() {
        let platform = platform();
        assert_eq!(platform.name, "arista_eos");
        assert_eq!(platform.privilege_levels.len(), 3);
        assert!(platform.privilege_levels.contains_key("exec"));
        assert!(platform.privilege_levels.contains_key("privilege_exec"));
        assert!(platform.privilege_levels.contains_key("configuration"));
    }

    #[test]
    fn test_exec_prompt_match() {
        let platform = platform();
        let exec = platform.privilege_levels.get("exec").unwrap();

        assert!(exec.pattern.is_match(b"switch>"));
        assert!(exec.pattern.is_match(b"switch> "));
        assert!(exec.pattern.is_match(b"admin@switch>"));
        assert!(exec.pattern.is_match(b"switch.lab>"));

        // Should NOT match privilege_exec or config
        assert!(!exec.pattern.is_match(b"switch#"));
        assert!(!exec.pattern.is_match(b"switch(config)#"));
    }

    #[test]
    fn test_privilege_exec_prompt_match() {
        let platform = platform();
        let priv_exec = platform.privilege_levels.get("privilege_exec").unwrap();

        // Standard prompts
        assert!(priv_exec.pattern.is_match(b"switch#"));
        assert!(priv_exec.pattern.is_match(b"switch# "));
        assert!(priv_exec.pattern.is_match(b"admin@switch#"));

        // Config mode prompts also match the raw pattern (# at end)
        // but not_contains "(config" filters them via matches()
        assert!(priv_exec.matches("switch#"));
        assert!(priv_exec.matches("switch# "));
        assert!(!priv_exec.matches("switch(config)#"));
        assert!(!priv_exec.matches("switch(config-if-Et1)#"));
        assert!(!priv_exec.matches("switch(config-s-mysess)#"));

        // Should NOT match exec
        assert!(!priv_exec.pattern.is_match(b"switch>"));
    }

    #[test]
    fn test_configuration_prompt_match() {
        let platform = platform();
        let config = platform.privilege_levels.get("configuration").unwrap();

        // Standard config mode
        assert!(config.pattern.is_match(b"switch(config)#"));
        assert!(config.pattern.is_match(b"switch(config)# "));

        // Config sub-modes
        assert!(config.pattern.is_match(b"switch(config-if-Et1)#"));
        assert!(config.pattern.is_match(b"switch(config-router-bgp)#"));

        // Named session prompts also match the raw pattern
        // but not_contains "(config-s-" filters them via matches()
        assert!(config.matches("switch(config)#"));
        assert!(config.matches("switch(config-if-Et1)#"));
        assert!(!config.matches("switch(config-s-mysess)#"));

        // Should NOT match exec or privilege_exec
        assert!(!config.pattern.is_match(b"switch>"));
        assert!(!config.pattern.is_match(b"switch#"));
    }

    #[test]
    fn test_privilege_graph() {
        let platform = platform();

        // exec is root (no parent)
        let exec = platform.privilege_levels.get("exec").unwrap();
        assert!(exec.previous_priv.is_none());

        // privilege_exec's parent is exec
        let priv_exec = platform.privilege_levels.get("privilege_exec").unwrap();
        assert_eq!(priv_exec.previous_priv, Some("exec".to_string()));
        assert_eq!(priv_exec.escalate_command, Some("enable".to_string()));
        assert_eq!(priv_exec.deescalate_command, Some("disable".to_string()));
        assert!(priv_exec.escalate_prompt.is_some()); // auth required
        assert_eq!(priv_exec.not_contains, vec!["(config".to_string()]);

        // configuration's parent is privilege_exec
        let config = platform.privilege_levels.get("configuration").unwrap();
        assert_eq!(config.previous_priv, Some("privilege_exec".to_string()));
        assert_eq!(
            config.escalate_command,
            Some("configure terminal".to_string())
        );
        assert_eq!(config.deescalate_command, Some("end".to_string()));
        assert_eq!(config.not_contains, vec!["(config-s-".to_string()]);
    }

    #[test]
    fn test_failure_patterns() {
        let platform = platform();
        assert!(!platform.failed_when_contains.is_empty());
        assert!(
            platform
                .failed_when_contains
                .contains(&"% Invalid input".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"% Ambiguous command".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"% Cannot commit".to_string())
        );
    }

    #[test]
    fn test_on_open_commands() {
        let platform = platform();
        assert_eq!(platform.on_open_commands.len(), 2);
        assert!(
            platform
                .on_open_commands
                .contains(&"terminal length 0".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"terminal width 32767".to_string())
        );
    }

    #[test]
    fn test_default_privilege() {
        let platform = platform();
        assert_eq!(platform.default_privilege, "privilege_exec");
    }
}
