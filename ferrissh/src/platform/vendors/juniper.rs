//! Juniper JUNOS platform definition.
//!
//! Supports Juniper devices running JUNOS with the following privilege levels:
//! - `exec` - Operational mode with `>` prompt
//! - `configuration` - Configuration mode with `#` prompt
//! - `shell` - Unix shell mode with `%` prompt
//!
//! # Prompt Examples
//!
//! ```text
//! user@router>              # exec mode
//! user@router#              # configuration mode
//! user@router%              # shell mode
//! {master:0}[edit]          # config mode with routing-engine indicator
//! user@router>              # after "exit" from config
//! ```
//!
//! # Privilege Graph
//!
//! ```text
//! ┌──────┐  configure   ┌───────────────┐
//! │ exec ├──────────────► configuration │
//! │  >   │    exit      │      #        │
//! └──┬───┘◄─────────────┴───────────────┘
//!    │
//!    │ start shell
//!    ▼
//! ┌──────┐
//! │shell │
//! │  %   │
//! └──────┘
//!    exit
//! ```

use std::sync::Arc;

use crate::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};

/// Create the Juniper JUNOS platform definition.
pub fn platform() -> PlatformDefinition {
    // Exec (operational) mode - ">" prompt
    // Matches: user@router>, {master:0}user@router>
    let exec = PrivilegeLevel::new("exec", r"(?:\{[^}]+\})?[\w.\-@]+>\s*$").unwrap();

    // Configuration mode - "#" prompt
    // Matches: user@router#, {master:0}[edit]user@router#, [edit interfaces]user@router#
    let configuration =
        PrivilegeLevel::new("configuration", r"(?:\{[^}]+\})?(?:\[edit[^\]]*\]\s*)?[\w.\-@]+#\s*$")
            .unwrap()
            .with_parent("exec")
            .with_escalate("configure")
            .with_deescalate("exit configuration-mode");

    // Shell mode - "%" prompt
    // Matches: user@router%, root@router:RE:0%
    let shell = PrivilegeLevel::new("shell", r"[\w.\-@:]+%\s*$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("start shell")
        .with_deescalate("exit");

    PlatformDefinition::new("juniper_junos")
        .with_privilege(exec)
        .with_privilege(configuration)
        .with_privilege(shell)
        .with_default_privilege("exec")
        .with_failure_pattern("unknown command")
        .with_failure_pattern("syntax error")
        .with_failure_pattern("error:")
        .with_failure_pattern("missing argument")
        .with_failure_pattern("invalid")
        .with_on_open_command("set cli screen-length 0")
        .with_on_open_command("set cli screen-width 511")
        .with_terminal_size(511, 24)
        .with_behavior(Arc::new(JuniperBehavior))
}

/// Juniper JUNOS-specific behavior.
pub struct JuniperBehavior;

impl VendorBehavior for JuniperBehavior {
    fn post_process_output(&self, output: &str) -> String {
        // Filter out [edit] context lines that JUNOS includes in config mode
        output
            .lines()
            .filter(|line| !line.trim().starts_with("[edit"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_juniper_platform() {
        let platform = platform();
        assert_eq!(platform.name, "juniper_junos");
        assert_eq!(platform.privilege_levels.len(), 3);
        assert!(platform.privilege_levels.contains_key("exec"));
        assert!(platform.privilege_levels.contains_key("configuration"));
        assert!(platform.privilege_levels.contains_key("shell"));
    }

    #[test]
    fn test_exec_prompt_match() {
        let platform = platform();
        let exec = platform.privilege_levels.get("exec").unwrap();

        // Standard prompts
        assert!(exec.pattern.is_match(b"user@router> "));
        assert!(exec.pattern.is_match(b"admin@mx960>"));
        assert!(exec.pattern.is_match(b"root@srx300> "));

        // With routing engine indicator
        assert!(exec.pattern.is_match(b"{master:0}user@router> "));
        assert!(exec.pattern.is_match(b"{backup:1}admin@mx960>"));

        // Should NOT match config or shell
        assert!(!exec.pattern.is_match(b"user@router# "));
        assert!(!exec.pattern.is_match(b"user@router% "));
    }

    #[test]
    fn test_configuration_prompt_match() {
        let platform = platform();
        let config = platform.privilege_levels.get("configuration").unwrap();

        // Standard config prompt
        assert!(config.pattern.is_match(b"user@router# "));
        assert!(config.pattern.is_match(b"admin@mx960#"));

        // With [edit] context
        assert!(config.pattern.is_match(b"[edit]user@router# "));
        assert!(config.pattern.is_match(b"[edit interfaces]user@router#"));
        assert!(config.pattern.is_match(b"[edit protocols bgp]admin@mx960# "));

        // With routing engine indicator
        assert!(config.pattern.is_match(b"{master:0}[edit]user@router# "));
        assert!(config.pattern.is_match(b"{master:0}user@router#"));

        // Should NOT match exec or shell
        assert!(!config.pattern.is_match(b"user@router> "));
        assert!(!config.pattern.is_match(b"user@router% "));
    }

    #[test]
    fn test_shell_prompt_match() {
        let platform = platform();
        let shell = platform.privilege_levels.get("shell").unwrap();

        // Standard shell prompts
        assert!(shell.pattern.is_match(b"user@router% "));
        assert!(shell.pattern.is_match(b"root@mx960%"));

        // With RE indicator (common in shell)
        assert!(shell.pattern.is_match(b"root@router:RE:0% "));

        // Should NOT match exec or config
        assert!(!shell.pattern.is_match(b"user@router> "));
        assert!(!shell.pattern.is_match(b"user@router# "));
    }

    #[test]
    fn test_privilege_graph() {
        let platform = platform();

        // exec is root (no parent)
        let exec = platform.privilege_levels.get("exec").unwrap();
        assert!(exec.previous_priv.is_none());

        // configuration's parent is exec
        let config = platform.privilege_levels.get("configuration").unwrap();
        assert_eq!(config.previous_priv, Some("exec".to_string()));
        assert_eq!(config.escalate_command, Some("configure".to_string()));
        assert_eq!(
            config.deescalate_command,
            Some("exit configuration-mode".to_string())
        );

        // shell's parent is also exec
        let shell = platform.privilege_levels.get("shell").unwrap();
        assert_eq!(shell.previous_priv, Some("exec".to_string()));
        assert_eq!(shell.escalate_command, Some("start shell".to_string()));
        assert_eq!(shell.deescalate_command, Some("exit".to_string()));
    }

    #[test]
    fn test_post_process_output() {
        let behavior = JuniperBehavior;

        // Output without [edit] lines passes through
        let output = "Hostname: router\nModel: mx960";
        assert_eq!(behavior.post_process_output(output), output);

        // [edit] lines are filtered out
        let output = "ge-0/0/0\n[edit]\nge-0/0/1";
        assert_eq!(behavior.post_process_output(output), "ge-0/0/0\nge-0/0/1");

        // [edit interfaces] context lines are also filtered
        let output = "ge-0/0/0\n[edit interfaces]";
        assert_eq!(behavior.post_process_output(output), "ge-0/0/0");
    }


    #[test]
    fn test_on_open_commands() {
        let platform = platform();
        assert_eq!(platform.on_open_commands.len(), 2);
        assert!(platform.on_open_commands.contains(&"set cli screen-length 0".to_string()));
        assert!(platform.on_open_commands.contains(&"set cli screen-width 511".to_string()));
    }

    #[test]
    fn test_failed_when_contains() {
        let platform = platform();
        assert!(!platform.failed_when_contains.is_empty());
        assert!(platform.failed_when_contains.contains(&"syntax error".to_string()));
        assert!(platform.failed_when_contains.contains(&"unknown command".to_string()));
    }
}
