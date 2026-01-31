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

use async_trait::async_trait;
use regex::bytes::Regex;

use crate::driver::GenericDriver;
use crate::error::Result;
use crate::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};

/// Create the Juniper JUNOS platform definition.
pub fn platform() -> PlatformDefinition {
    let mut platform = PlatformDefinition::new("juniper_junos");

    // Exec (operational) mode - ">" prompt
    // Matches: user@router>, {master:0}user@router>
    let exec = PrivilegeLevel {
        name: "exec".to_string(),
        pattern: Regex::new(r"(?:\{[^}]+\})?[\w.\-@]+>\s*$").unwrap(),
        previous_priv: None,
        escalate_command: None,
        deescalate_command: None,
        escalate_auth: false,
        escalate_prompt: None,
        not_contains: vec![],
    };

    // Configuration mode - "#" prompt
    // Matches: user@router#, {master:0}[edit]user@router#, [edit interfaces]user@router#
    let configuration = PrivilegeLevel {
        name: "configuration".to_string(),
        pattern: Regex::new(r"(?:\{[^}]+\})?(?:\[edit[^\]]*\]\s*)?[\w.\-@]+#\s*$").unwrap(),
        previous_priv: Some("exec".to_string()),
        escalate_command: Some("configure".to_string()),
        deescalate_command: Some("exit configuration-mode".to_string()),
        escalate_auth: false,
        escalate_prompt: None,
        not_contains: vec![],
    };

    // Shell mode - "%" prompt
    // Matches: user@router%, root@router:RE:0%
    let shell = PrivilegeLevel {
        name: "shell".to_string(),
        pattern: Regex::new(r"[\w.\-@:]+%\s*$").unwrap(),
        previous_priv: Some("exec".to_string()),
        escalate_command: Some("start shell".to_string()),
        deescalate_command: Some("exit".to_string()),
        escalate_auth: false,
        escalate_prompt: None,
        not_contains: vec![],
    };

    platform.privilege_levels.insert("exec".to_string(), exec);
    platform
        .privilege_levels
        .insert("configuration".to_string(), configuration);
    platform.privilege_levels.insert("shell".to_string(), shell);
    platform.default_privilege = "exec".to_string();

    // JUNOS error patterns
    platform.failed_when_contains = vec![
        "unknown command".to_string(),
        "syntax error".to_string(),
        "error:".to_string(),
        "missing argument".to_string(),
        "invalid".to_string(),
    ];

    // On-open: disable paging and set terminal width
    platform.on_open_commands = vec![
        "set cli screen-length 0".to_string(),
        "set cli screen-width 511".to_string(),
    ];

    // Terminal size
    platform.terminal_width = 511;
    platform.terminal_height = 24;

    // Use Juniper-specific behavior
    platform.behavior = Some(Arc::new(JuniperBehavior));

    platform
}

/// Juniper JUNOS-specific behavior.
pub struct JuniperBehavior;

#[async_trait]
impl VendorBehavior for JuniperBehavior {
    async fn on_open(&self, _driver: &mut GenericDriver) -> Result<()> {
        // on_open commands handle paging and screen width
        // Additional initialization could go here
        Ok(())
    }

    async fn on_close(&self, _driver: &mut GenericDriver) -> Result<()> {
        // No special cleanup needed for Juniper
        Ok(())
    }

    fn normalize_output(&self, raw: &str, command: &str) -> String {
        // Strip command echo from the beginning
        let output = raw
            .strip_prefix(command)
            .unwrap_or(raw)
            .trim_start_matches(['\r', '\n']);

        // Strip trailing prompt patterns
        let lines: Vec<&str> = output.lines().collect();
        if lines.is_empty() {
            return String::new();
        }

        // Check if last line looks like a JUNOS prompt (ends with >, #, or %)
        let last = lines.last().unwrap().trim();
        if last.ends_with('>') || last.ends_with('#') || last.ends_with('%') {
            // Also check for [edit] patterns that might be on their own line
            let result: Vec<&str> = lines[..lines.len() - 1]
                .iter()
                .filter(|line| !line.trim().starts_with("[edit"))
                .copied()
                .collect();
            result.join("\n")
        } else {
            output.to_string()
        }
    }

    fn detect_failure(&self, output: &str) -> Option<String> {
        // JUNOS-specific error patterns
        let error_patterns = [
            ("unknown command", "unknown command"),
            ("syntax error", "syntax error"),
            ("error:", "error"),
            ("missing argument", "missing argument"),
            ("warning: ", "warning"),  // JUNOS warnings
            ("failed", "operation failed"),
            ("invalid", "invalid input"),
        ];

        // Check for lines starting with error markers (more specific)
        for line in output.lines() {
            let trimmed = line.trim().to_lowercase();

            // "^" marker indicates syntax error position in JUNOS
            if trimmed.starts_with('^') {
                return Some("syntax error".to_string());
            }

            for (pattern, msg) in &error_patterns {
                if trimmed.contains(pattern) {
                    return Some(msg.to_string());
                }
            }
        }

        None
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
    fn test_normalize_output() {
        let behavior = JuniperBehavior;

        // Command echo removal
        let raw = "show version\nHostname: router\nModel: mx960\nuser@router>";
        let normalized = behavior.normalize_output(raw, "show version");
        assert_eq!(normalized, "Hostname: router\nModel: mx960");

        // With [edit] line
        let raw = "show interfaces\nge-0/0/0\n[edit]\nuser@router#";
        let normalized = behavior.normalize_output(raw, "show interfaces");
        assert_eq!(normalized, "ge-0/0/0");
    }

    #[test]
    fn test_detect_failure() {
        let behavior = JuniperBehavior;

        // Unknown command
        assert!(behavior.detect_failure("            ^\nunknown command.").is_some());

        // Syntax error with ^ marker
        assert!(behavior.detect_failure("        ^\n").is_some());

        // Error message
        assert!(behavior.detect_failure("error: configuration check-out failed").is_some());

        // Missing argument
        assert!(behavior.detect_failure("missing argument").is_some());

        // Valid output should not be flagged
        assert!(behavior.detect_failure("Hostname: router\nModel: mx960").is_none());
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
