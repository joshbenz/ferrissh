//! Nokia SR OS platform definition.
//!
//! Supports Nokia routers running SR OS with **auto-detection** of the CLI engine.
//! Both MD-CLI and Classic CLI privilege levels are defined — the driver detects
//! which engine is active based on the initial prompt after SSH login.
//!
//! ## MD-CLI (Model-Driven CLI)
//!
//! Two-line prompts with `@` in the second line. Candidate/commit configuration model.
//!
//! - `exec` — Operational mode
//! - `configuration` — Exclusive config mode at root
//! - `configuration_with_path` — Exclusive config mode at deeper context
//!
//! ## Classic CLI
//!
//! Single-line prompts without `@`. Immediate-apply configuration model.
//!
//! - `classic_exec` — Operational root
//! - `classic_configuration` — Config context
//!
//! # Prompt Examples
//!
//! ```text
//! [/]                                  # MD-CLI exec (line 1)
//! A:admin@router#                      # MD-CLI exec (line 2)
//!
//! (ex)[/]                              # MD-CLI exclusive config at root (line 1)
//! A:admin@router#                      # MD-CLI config (line 2)
//!
//! *(ex)[/configure router "Base"]      # MD-CLI config with path + uncommitted (line 1)
//! A:admin@router#                      # MD-CLI config (line 2)
//!
//! A:router#                            # Classic exec
//! *A:router>config#                    # Classic config with unsaved changes
//! A:router>config>router>bgp#          # Classic config deeper context
//! ```
//!
//! # Privilege Graphs
//!
//! ```text
//! MD-CLI:
//! ┌──────┐  edit-config exclusive  ┌───────────────┐
//! │ exec ├─────────────────────────► configuration │
//! │      │       quit-config       │               │
//! └──────┘◄────────────────────────┴───────────────┘
//!    ▲
//!    │ exit all    ┌─────────────────────────────┐
//!    └─────────────┤ configuration_with_path     │
//!                  │ (navigated within config)   │
//!                  └─────────────────────────────┘
//!
//! Classic:
//! ┌──────────────┐  configure  ┌─────────────────────┐
//! │ classic_exec ├─────────────► classic_configuration│
//! │              │  exit all   │                      │
//! └──────────────┘◄────────────┴─────────────────────┘
//! ```
//!
//! Prompt patterns adapted from
//! [scrapli](https://github.com/scrapli/scrapli_community/blob/main/scrapli_community/nokia/sros/nokia_sros.py).

use crate::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};

/// Platform name for Nokia SR OS.
pub const PLATFORM_NAME: &str = "nokia_sros";

/// Create the Nokia SR OS platform definition.
///
/// Includes privilege levels for both MD-CLI and Classic CLI engines.
/// The driver auto-detects which engine is active based on the initial prompt.
///
/// Prompt patterns use `(?m)` for multiline matching (`^`/`$` match line boundaries).
pub fn platform() -> PlatformDefinition {
    // =========================================================================
    // MD-CLI privilege levels (two-line prompts with @)
    // =========================================================================

    // MD-CLI exec (operational) mode
    // Two-line prompt: context line + user@host# line
    // Pattern matches any [...]\nCPM:user@host# prompt.
    // not_contains filters out config mode prompts (which have (ex), (ro), (gl), (pr)).
    let exec = PrivilegeLevel::new(
        "exec",
        r"(?mi)^\[.*\]\r?\n\*?[abcd]:[\w._-]+@[\w\s_.-]+#\s?$",
    )
    .unwrap()
    .with_not_contains("(ex)")
    .with_not_contains("(ro)")
    .with_not_contains("(gl)")
    .with_not_contains("(pr)");

    // MD-CLI exclusive configuration mode at root level
    // First line: optional !/* indicators + (ex) or (ex:bof) + [/] or [/]
    // Second line: optional * + CPM:user@host#
    let configuration = PrivilegeLevel::new(
        "configuration",
        r"(?mi)^!?\*?\((?:ex|ex:bof)\)\[/?\]\r?\n\*?[abcd]:[\w._-]+@[\w\s_.-]+#\s?$",
    )
    .unwrap()
    .with_parent("exec")
    .with_escalate("edit-config exclusive")
    .with_deescalate("quit-config");

    // MD-CLI exclusive configuration mode with deeper path
    // Same as configuration but path has 2+ characters (e.g., [/configure router "Base"])
    let configuration_with_path = PrivilegeLevel::new(
        "configuration_with_path",
        r"(?mi)^!?\*?\((?:ex|ex:bof)\)\[(?:\S|\s){2,}\]\r?\n\*?[abcd]:[\w._-]+@[\w\s_.-]+#\s?$",
    )
    .unwrap()
    .with_parent("exec")
    .with_deescalate("exit all");

    // =========================================================================
    // Classic CLI privilege levels (single-line prompts, no @)
    // =========================================================================

    // Classic exec (operational root)
    // Pattern: optional * + CPM letter : hostname #
    // not_contains "@" prevents matching MD-CLI's second prompt line
    // not_contains ">config" prevents matching classic_configuration
    let classic_exec = PrivilegeLevel::new("classic_exec", r"(?mi)^\*?[abcd]:[\w\s_.-]+#\s?$")
        .unwrap()
        .with_not_contains("@")
        .with_not_contains(">config");

    // Classic configuration mode
    // Pattern: optional * + CPM : hostname > config [deeper>context] # or $
    // not_contains "@" prevents matching MD-CLI prompts
    let classic_configuration = PrivilegeLevel::new(
        "classic_configuration",
        r"(?mi)^\*?[abcd]:[\w\s_.-]+>config[\w>]*(#|\$)\s?$",
    )
    .unwrap()
    .with_parent("classic_exec")
    .with_escalate("configure")
    .with_deescalate("exit all")
    .with_not_contains("@");

    PlatformDefinition::new(PLATFORM_NAME)
        .with_privilege(exec)
        .with_privilege(configuration)
        .with_privilege(configuration_with_path)
        .with_privilege(classic_exec)
        .with_privilege(classic_configuration)
        .with_default_privilege("exec")
        // On-open commands for both engines (failures silently ignored)
        // MD-CLI commands:
        .with_on_open_command("environment command-completion space false")
        .with_on_open_command("environment console width 512")
        .with_on_open_command("environment more false")
        // Classic CLI paging disable (// runs in Classic engine from MD-CLI):
        .with_on_open_command("//environment no more")
        .with_on_open_command("environment no more")
        // Failure patterns (superset for both engines)
        .with_failure_pattern("MINOR:")
        .with_failure_pattern("MAJOR:")
        .with_failure_pattern("CRITICAL:")
        .with_failure_pattern("Error:")
        .with_failure_pattern("Bad Command:")
        .with_terminal_size(512, 24)
}

/// Nokia SR OS-specific behavior.
pub struct NokiaSrosBehavior;

impl VendorBehavior for NokiaSrosBehavior {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nokia_sros_platform() {
        let platform = platform();
        assert_eq!(platform.name, "nokia_sros");
        assert_eq!(platform.privilege_levels.len(), 5);
        assert!(platform.privilege_levels.contains_key("exec"));
        assert!(platform.privilege_levels.contains_key("configuration"));
        assert!(
            platform
                .privilege_levels
                .contains_key("configuration_with_path")
        );
        assert!(platform.privilege_levels.contains_key("classic_exec"));
        assert!(
            platform
                .privilege_levels
                .contains_key("classic_configuration")
        );
    }

    // =========================================================================
    // MD-CLI prompt matching
    // =========================================================================

    #[test]
    fn test_mdcli_exec_prompt_match() {
        let platform = platform();
        let exec = platform.privilege_levels.get("exec").unwrap();

        // Standard MD-CLI exec prompts (two-line)
        assert!(exec.pattern.is_match(b"[/]\nA:admin@router#"));
        assert!(exec.pattern.is_match(b"[/]\nA:admin@router# "));
        assert!(exec.pattern.is_match(b"[/]\nB:admin@router#"));

        // With \r\n line endings
        assert!(exec.pattern.is_match(b"[/]\r\nA:admin@router#"));
        assert!(exec.pattern.is_match(b"[/]\r\nA:svc-github-neo@use1.lm1#"));

        // Hyphenated username
        assert!(exec.pattern.is_match(b"[/]\nA:svc-github-neo@router#"));

        // With show context
        assert!(
            exec.pattern
                .is_match(b"[/show router interface]\nA:admin@node-2#")
        );

        // matches() filters out config mode via not_contains
        assert!(exec.matches("[/]\nA:admin@router#"));
        assert!(exec.matches("[/]\r\nA:svc-github-neo@use1.lm1#"));
        assert!(!exec.matches("(ex)[/]\nA:admin@router#"));
        assert!(!exec.matches("(ro)[/]\nA:admin@router#"));
        assert!(!exec.matches("(gl)[/]\nA:admin@router#"));
        assert!(!exec.matches("(pr)[/]\nA:admin@router#"));

        // Should NOT match Classic CLI (no [...] context line)
        assert!(!exec.pattern.is_match(b"A:router#"));
    }

    #[test]
    fn test_mdcli_configuration_prompt_match() {
        let platform = platform();
        let config = platform.privilege_levels.get("configuration").unwrap();

        // Exclusive config at root
        assert!(config.pattern.is_match(b"(ex)[/]\nA:admin@router#"));
        assert!(config.pattern.is_match(b"(ex)[/]\nA:admin@router# "));
        assert!(config.pattern.is_match(b"(ex)[/]\r\nA:admin@router#"));
        assert!(config.pattern.is_match(b"(ex)[/]\r\nA:svc-github-neo@router#"));

        // With uncommitted changes indicator
        assert!(config.pattern.is_match(b"*(ex)[/]\nA:admin@router#"));

        // With outdated baseline indicator
        assert!(config.pattern.is_match(b"!(ex)[/]\nA:admin@router#"));

        // BOF config
        assert!(config.pattern.is_match(b"(ex:bof)[/]\nA:admin@router#"));

        // Different CPM slots
        assert!(config.pattern.is_match(b"(ex)[/]\nB:admin@router#"));
        assert!(config.pattern.is_match(b"(ex)[/]\nC:admin@router#"));
        assert!(config.pattern.is_match(b"(ex)[/]\nD:admin@router#"));

        // With * on second line
        assert!(config.pattern.is_match(b"*(ex)[/]\n*A:admin@router#"));

        // Should NOT match exec mode
        assert!(!config.pattern.is_match(b"[/]\nA:admin@router#"));

        // Should NOT match config with deeper path
        assert!(
            !config
                .pattern
                .is_match(b"(ex)[/configure]\nA:admin@router#")
        );
    }

    #[test]
    fn test_mdcli_configuration_with_path_prompt_match() {
        let platform = platform();
        let config_path = platform
            .privilege_levels
            .get("configuration_with_path")
            .unwrap();

        // Config with path
        assert!(
            config_path
                .pattern
                .is_match(b"(ex)[/configure]\nA:admin@router#")
        );
        assert!(
            config_path
                .pattern
                .is_match(b"(ex)[/configure router \"Base\"]\nA:admin@router#")
        );
        assert!(
            config_path
                .pattern
                .is_match(b"(ex)[/configure router \"Base\" bgp]\nA:admin@router#")
        );

        // With uncommitted changes
        assert!(
            config_path
                .pattern
                .is_match(b"*(ex)[/configure router \"Base\"]\nA:admin@router#")
        );

        // With outdated baseline + uncommitted
        assert!(
            config_path
                .pattern
                .is_match(b"!*(ex)[/configure router \"Base\"]\nA:admin@router#")
        );

        // BOF with path
        assert!(
            config_path
                .pattern
                .is_match(b"(ex:bof)[/configure system]\nA:admin@router#")
        );

        // Should NOT match root-level config (that's the configuration level)
        assert!(!config_path.pattern.is_match(b"(ex)[/]\nA:admin@router#"));

        // Should NOT match exec
        assert!(!config_path.pattern.is_match(b"[/]\nA:admin@router#"));
    }

    // =========================================================================
    // Classic CLI prompt matching
    // =========================================================================

    #[test]
    fn test_classic_exec_prompt_match() {
        let platform = platform();
        let classic_exec = platform.privilege_levels.get("classic_exec").unwrap();

        // Standard Classic exec prompts
        assert!(classic_exec.pattern.is_match(b"A:router#"));
        assert!(classic_exec.pattern.is_match(b"A:router# "));
        assert!(classic_exec.pattern.is_match(b"B:router#"));

        // With unsaved changes indicator
        assert!(classic_exec.pattern.is_match(b"*A:router#"));

        // With dots/dashes in hostname
        assert!(classic_exec.pattern.is_match(b"A:router-1.lab#"));

        // matches() respects not_contains
        assert!(classic_exec.matches("A:router#"));
        assert!(classic_exec.matches("*A:router#"));

        // Should NOT match MD-CLI (contains @)
        assert!(!classic_exec.matches("A:admin@router#"));

        // Should NOT match Classic config (contains >config)
        assert!(!classic_exec.matches("A:router>config#"));
        assert!(!classic_exec.matches("*A:router>config>router#"));
    }

    #[test]
    fn test_classic_configuration_prompt_match() {
        let platform = platform();
        let classic_config = platform
            .privilege_levels
            .get("classic_configuration")
            .unwrap();

        // Standard Classic config prompts
        assert!(classic_config.pattern.is_match(b"A:router>config#"));
        assert!(classic_config.pattern.is_match(b"A:router>config# "));

        // With unsaved changes
        assert!(classic_config.pattern.is_match(b"*A:router>config#"));

        // Deeper config contexts
        assert!(classic_config.pattern.is_match(b"A:router>config>router#"));
        assert!(
            classic_config
                .pattern
                .is_match(b"*A:router>config>router>bgp#")
        );
        assert!(classic_config.pattern.is_match(b"A:router>config>service#"));

        // New context ($ instead of #)
        assert!(classic_config.pattern.is_match(b"A:router>config>router$"));

        // matches() respects not_contains
        assert!(classic_config.matches("A:router>config#"));
        assert!(classic_config.matches("*A:router>config>router>bgp#"));

        // Should NOT match Classic exec
        assert!(!classic_config.pattern.is_match(b"A:router#"));

        // Should NOT match MD-CLI (contains @)
        assert!(!classic_config.matches("A:admin@router>config#"));
    }

    // =========================================================================
    // Privilege graph
    // =========================================================================

    #[test]
    fn test_privilege_graph() {
        let platform = platform();

        // MD-CLI exec is root (no parent)
        let exec = platform.privilege_levels.get("exec").unwrap();
        assert!(exec.previous_priv.is_none());

        // MD-CLI configuration's parent is exec
        let config = platform.privilege_levels.get("configuration").unwrap();
        assert_eq!(config.previous_priv, Some("exec".to_string()));
        assert_eq!(
            config.escalate_command,
            Some("edit-config exclusive".to_string())
        );
        assert_eq!(config.deescalate_command, Some("quit-config".to_string()));

        // MD-CLI configuration_with_path's parent is exec, no escalate
        let config_path = platform
            .privilege_levels
            .get("configuration_with_path")
            .unwrap();
        assert_eq!(config_path.previous_priv, Some("exec".to_string()));
        assert!(config_path.escalate_command.is_none());
        assert_eq!(config_path.deescalate_command, Some("exit all".to_string()));

        // Classic exec is root (no parent) — disconnected from MD-CLI
        let classic_exec = platform.privilege_levels.get("classic_exec").unwrap();
        assert!(classic_exec.previous_priv.is_none());

        // Classic configuration's parent is classic_exec
        let classic_config = platform
            .privilege_levels
            .get("classic_configuration")
            .unwrap();
        assert_eq!(
            classic_config.previous_priv,
            Some("classic_exec".to_string())
        );
        assert_eq!(
            classic_config.escalate_command,
            Some("configure".to_string())
        );
        assert_eq!(
            classic_config.deescalate_command,
            Some("exit all".to_string())
        );
    }

    // =========================================================================
    // Prompt disambiguation
    // =========================================================================

    #[test]
    fn test_prompt_disambiguation() {
        let platform = platform();
        let exec = platform.privilege_levels.get("exec").unwrap();
        let classic_exec = platform.privilege_levels.get("classic_exec").unwrap();
        let config = platform.privilege_levels.get("configuration").unwrap();

        // MD-CLI exec raw pattern does NOT match Classic prompt (requires [...]\n)
        assert!(!exec.pattern.is_match(b"A:router#"));

        // MD-CLI exec matches() filters out config mode prompts
        assert!(exec.matches("[/]\nA:admin@router#"));
        assert!(!exec.matches("(ex)[/]\nA:admin@router#"));

        // MD-CLI config does NOT match exec (requires (ex) or (ex:bof) prefix)
        assert!(!config.pattern.is_match(b"[/]\nA:admin@router#"));

        // Classic exec raw pattern does NOT match MD-CLI second line (@ not in char class)
        assert!(!classic_exec.pattern.is_match(b"A:admin@router#"));

        // Classic exec matches() filters out config prompts via not_contains
        assert!(classic_exec.matches("A:router#"));
        assert!(!classic_exec.matches("A:router>config#"));
    }

    // =========================================================================
    // Platform configuration
    // =========================================================================

    #[test]
    fn test_on_open_commands() {
        let platform = platform();
        assert_eq!(platform.on_open_commands.len(), 5);
        assert!(
            platform
                .on_open_commands
                .contains(&"environment command-completion space false".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"environment console width 512".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"environment more false".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"//environment no more".to_string())
        );
        assert!(
            platform
                .on_open_commands
                .contains(&"environment no more".to_string())
        );
    }

    #[test]
    fn test_failure_patterns() {
        let platform = platform();
        assert!(!platform.failed_when_contains.is_empty());
        assert!(
            platform
                .failed_when_contains
                .contains(&"MINOR:".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"MAJOR:".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"CRITICAL:".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"Error:".to_string())
        );
        assert!(
            platform
                .failed_when_contains
                .contains(&"Bad Command:".to_string())
        );
    }

    #[test]
    fn test_terminal_size() {
        let platform = platform();
        assert_eq!(platform.terminal_width, 512);
        assert_eq!(platform.terminal_height, 24);
    }
}
