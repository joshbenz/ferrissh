//! Juniper JUNOS platform definition.
//!
//! Supports Juniper devices running JUNOS with the following privilege levels:
//! - `exec` - Operational mode with `>` prompt
//! - `configuration` - Configuration mode with `#` prompt
//! - `shell` - Unix shell mode with `%` or `$` prompt (non-root)
//! - `root_shell` - Root shell with `%` or `#` prompt
//!
//! Prompt patterns are adapted from [scrapli](https://github.com/carlmontanari/scrapli).
//!
//! # Prompt Examples
//!
//! ```text
//! user@router>              # exec mode
//! user@router#              # configuration mode
//! %                         # shell mode (vJunos-router)
//! user@router%              # shell mode
//! root@router:RE:0%         # root shell mode
//! {master:0}                # routing-engine indicator (separate line)
//! user@router>              # exec prompt on next line
//! {master:0}[edit]          # config with routing-engine indicator
//! user@router#              # config prompt on next line
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
//!    ├─ start shell ──────► ┌──────┐
//!    │                      │shell │
//!    │                      │ %/$  │
//!    │                      └──────┘
//!    │                        exit
//!    │
//!    └─ start shell user root ► ┌────────────┐
//!                               │ root_shell │
//!                               │   %/#      │
//!                               └────────────┘
//!                                   exit
//! ```

use std::sync::Arc;

use crate::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};

/// Platform name for Juniper JUNOS.
pub const PLATFORM_NAME: &str = "juniper_junos";

/// Create the Juniper JUNOS platform definition.
///
/// Prompt patterns adapted from scrapli's JunOS driver.
/// Uses `(?mi)` flags for multiline (^ matches line start) and case-insensitive matching.
pub fn platform() -> PlatformDefinition {
    // Exec (operational) mode - ">" prompt
    let exec = PrivilegeLevel::new(
        "exec",
        r"(?mi)^(\{\w+(:(\w+)?\d)?\}\n)?[\w\-@()/:\.]{1,63}>\s?$",
    )
    .unwrap();

    // Configuration mode - "#" prompt
    let configuration = PrivilegeLevel::new(
        "configuration",
        r"(?mi)^(\{\w+(:(\w+)?\d)?\}\[edit\]\n)?[\w\-@()/:\.]{1,63}#\s?$",
    )
    .unwrap()
    .with_parent("exec")
    .with_escalate("configure")
    .with_deescalate("exit configuration-mode");

    // Shell mode - "%" or "$" prompt (non-root)
    let shell = PrivilegeLevel::new("shell", r"(?mi)^.*[%$]\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("start shell")
        .with_deescalate("exit")
        .with_not_contains("root");

    // Root shell mode - root user "%" or "#" prompt
    let root_shell = PrivilegeLevel::new("root_shell", r"(?mi)^.*root@(?:\S*:?\S*\s?)?[%#]\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("start shell user root")
        .with_deescalate("exit")
        .with_auth(r"(?i)^password:\s?$")
        .unwrap();

    PlatformDefinition::new(PLATFORM_NAME)
        .with_privilege(exec)
        .with_privilege(configuration)
        .with_privilege(shell)
        .with_privilege(root_shell)
        .with_default_privilege("exec")
        .with_failure_pattern("unknown command")
        .with_failure_pattern("syntax error")
        .with_failure_pattern("error:")
        .with_failure_pattern("missing argument")
        .with_failure_pattern("invalid")
        .with_failure_pattern("is ambiguous")
        .with_failure_pattern("No valid completions")
        .with_failure_pattern("missing mandatory argument")
        .with_failure_pattern("invalid numeric value")
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
        assert_eq!(platform.privilege_levels.len(), 4);
        assert!(platform.privilege_levels.contains_key("exec"));
        assert!(platform.privilege_levels.contains_key("configuration"));
        assert!(platform.privilege_levels.contains_key("shell"));
        assert!(platform.privilege_levels.contains_key("root_shell"));
    }

    #[test]
    fn test_exec_prompt_match() {
        let platform = platform();
        let exec = platform.privilege_levels.get("exec").unwrap();

        // Standard prompts
        assert!(exec.pattern.is_match(b"user@router>"));
        assert!(exec.pattern.is_match(b"user@router> "));
        assert!(exec.pattern.is_match(b"admin@mx960>"));
        assert!(exec.pattern.is_match(b"root@srx300> "));

        // With routing engine indicator on separate line (real device behavior)
        assert!(exec.pattern.is_match(b"{master:0}\nuser@router> "));
        assert!(exec.pattern.is_match(b"{backup:1}\nadmin@mx960>"));

        // With parens, slashes, colons, dots in hostname (scrapli character class)
        assert!(exec.pattern.is_match(b"user@router.lab>"));
        assert!(exec.pattern.is_match(b"user@router/re0>"));

        // Should NOT match config or shell
        assert!(!exec.pattern.is_match(b"user@router# "));
        assert!(!exec.pattern.is_match(b"user@router% "));
    }

    #[test]
    fn test_configuration_prompt_match() {
        let platform = platform();
        let config = platform.privilege_levels.get("configuration").unwrap();

        // Standard config prompt
        assert!(config.pattern.is_match(b"user@router#"));
        assert!(config.pattern.is_match(b"user@router# "));
        assert!(config.pattern.is_match(b"admin@mx960#"));

        // With [edit] on separate line (real device behavior)
        assert!(config.pattern.is_match(b"[edit]\nuser@router# "));
        assert!(config.pattern.is_match(b"[edit interfaces]\nuser@router#"));

        // With routing engine indicator + [edit] on separate line
        assert!(config.pattern.is_match(b"{master:0}[edit]\nuser@router# "));

        // Without routing engine, just the prompt line
        assert!(config.pattern.is_match(b"admin@mx960#"));

        // Should NOT match exec or shell
        assert!(!config.pattern.is_match(b"user@router> "));
        assert!(!config.pattern.is_match(b"user@router% "));
    }

    #[test]
    fn test_shell_prompt_match() {
        let platform = platform();
        let shell = platform.privilege_levels.get("shell").unwrap();

        // Bare "%" prompt (vJunos-router)
        assert!(shell.pattern.is_match(b"% "));
        assert!(shell.pattern.is_match(b"%"));

        // Standard shell prompts (pattern matches, not_contains checked separately)
        assert!(shell.pattern.is_match(b"user@router% "));
        assert!(shell.pattern.is_match(b"user@router%"));

        // Dollar sign prompt
        assert!(shell.pattern.is_match(b"user$ "));
        assert!(shell.pattern.is_match(b"$"));

        // not_contains: "root" prevents matching root prompts via matches()
        assert!(shell.matches("user@router% "));
        assert!(shell.matches("% "));
        assert!(!shell.matches("root@router% "));
        assert!(!shell.matches("root@router:RE:0% "));

        // Should NOT match exec or config
        assert!(!shell.pattern.is_match(b"user@router> "));
    }

    #[test]
    fn test_root_shell_prompt_match() {
        let platform = platform();
        let root_shell = platform.privilege_levels.get("root_shell").unwrap();

        // Standard root shell prompts
        assert!(root_shell.pattern.is_match(b"root@router% "));
        assert!(root_shell.pattern.is_match(b"root@router%"));
        assert!(root_shell.pattern.is_match(b"root@mx960#"));

        // With RE indicator
        assert!(root_shell.pattern.is_match(b"root@router:RE:0% "));

        // Should NOT match non-root prompts
        assert!(!root_shell.pattern.is_match(b"user@router% "));
        assert!(!root_shell.pattern.is_match(b"% "));
        assert!(!root_shell.pattern.is_match(b"user@router> "));
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

        // shell's parent is exec
        let shell = platform.privilege_levels.get("shell").unwrap();
        assert_eq!(shell.previous_priv, Some("exec".to_string()));
        assert_eq!(shell.escalate_command, Some("start shell".to_string()));
        assert_eq!(shell.deescalate_command, Some("exit".to_string()));
        assert_eq!(shell.not_contains, vec!["root".to_string()]);

        // root_shell's parent is exec
        let root_shell = platform.privilege_levels.get("root_shell").unwrap();
        assert_eq!(root_shell.previous_priv, Some("exec".to_string()));
        assert_eq!(
            root_shell.escalate_command,
            Some("start shell user root".to_string())
        );
        assert_eq!(root_shell.deescalate_command, Some("exit".to_string()));
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
        assert!(
            platform
                .on_open_commands
                .contains(&"set cli screen-length 0".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"set cli screen-width 511".to_string())
        );
    }

    #[test]
    fn test_failed_when_contains() {
        let platform = platform();
        assert!(!platform.failed_when_contains.is_empty());
        assert!(
            platform
                .failed_when_contains
                .contains(&"syntax error".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"unknown command".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"is ambiguous".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"No valid completions".to_string())
        );
    }
}
