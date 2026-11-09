//! Ciena WaveServer platform definition.
//!
//! WaveServer (Ai / 5) exposes a noun-verb CLI (`xcvr show`, `system show host-name`)
//! with no separate configuration mode: configuration commands apply directly
//! from the root prompt.
//!
//! An incomplete command (`topology show` with nothing after it) does not fail;
//! it enters a sub-menu whose path is shown in the prompt. `quit` returns to
//! the root menu from any depth.
//!
//! - `exec` — root menu
//! - `submenu` — any sub-menu (`quit` returns to `exec`)
//!
//! # Prompt Examples
//!
//! ```text
//! dci16.sv8#                           # root, no unsaved changes
//! dci16.sv8*#                          # root, unsaved configuration changes
//! dci9.mi1(topology/show)#             # sub-menu entered by `topology show`
//! DCI-SPARE4.SV8.CORP.EQUINIX.COM$     # lower privilege class
//! ```
//!
//! Every prompt is preceded by a bare `\r` (`\r\n\rdci16.sv8*# `); ANSI
//! stripping removes it before prompt matching, so the patterns anchor on the
//! line start. Errors are reported as `SHELL PARSER FAILURE: <reason>`.
//!
//! Long output is paged with `--More--` regardless of the PTY height, so the
//! session pager is turned off on open (`system shell session set more off`
//! only affects this CLI session; it does not touch the configuration).
//!
//! Once prompt plus typed input is wider than its line editor (FQDN host names
//! inside a deep sub-menu), WaveServer redraws the whole line on every
//! keystroke (`\rPROMPT# q`, `\rPROMPT# qu`, ...); `session set window-width`
//! does not stop it. With the `\r` stripped a packet can end in a bare copy of
//! the old prompt, so the platform sets `prompt_after_newline`: a reply prompt
//! is only accepted after the newline that ends the command echo.

use std::sync::LazyLock;

use regex::bytes::Regex;

use crate::platform::{PlatformDefinition, PrivilegeLevel};

// The prompt character follows the user's privilege class: `#` for admin and
// super users, `$` (seen on spares, `DCI-SPARE4.SV8.CORP.EQUINIX.COM$`) or `>`
// for lower classes.
static EXEC_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?-u)^[\w.\-]+\*?[#$>] ?$").unwrap());
static SUBMENU_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?-u)^[\w.\-]+\*?\([\w.\-/ ]+\)[#$>] ?$").unwrap());

pub const PLATFORM_NAME: &str = "ciena_waveserver";

/// Create the Ciena WaveServer platform definition.
pub fn platform() -> PlatformDefinition {
    let exec = PrivilegeLevel::from_regex("exec", EXEC_PATTERN.clone());

    // Entered implicitly by incomplete commands; never escalated to on purpose.
    let submenu = PrivilegeLevel::from_regex("submenu", SUBMENU_PATTERN.clone())
        .with_parent("exec")
        .with_deescalate("quit");

    PlatformDefinition::new(PLATFORM_NAME)
        .with_privilege(exec)
        .with_privilege(submenu)
        .with_default_privilege("exec")
        .with_failure_pattern("SHELL PARSER FAILURE")
        .with_on_open_command("system shell session set more off")
        .with_terminal_size(511, 200)
        .with_prompt_after_newline(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waveserver_platform() {
        let p = platform();
        assert_eq!(p.name, "ciena_waveserver");
        assert_eq!(p.privilege_levels.len(), 2);
        assert_eq!(p.default_privilege, "exec");
        assert!(p.prompt_after_newline);
    }

    #[test]
    fn test_exec_prompt_match() {
        let p = platform();
        let exec = p.get_privilege("exec").unwrap();

        assert!(exec.pattern.is_match(b"dci16.sv8*# "));
        assert!(exec.pattern.is_match(b"dci16.sv8# "));
        assert!(exec.pattern.is_match(b"dci16.sv8#"));
        // as seen after ANSI stripping (`\r\n\rdci16.sv8*# ` on the wire)
        assert!(exec.pattern.is_match(b"\ndci16.sv8*# "));
        assert!(exec.pattern.is_match(b"Waveserver-5#"));
        assert!(exec.pattern.is_match(b"DCI-SPARE4.SV8.CORP.EQUINIX.COM$ "));
        assert!(exec.pattern.is_match(b"dci9.la1.corp.equinix.com# "));

        // Table borders and banner text must not look like a prompt
        assert!(!exec.pattern.is_match(b"+------+-----+-------+"));
        assert!(!exec.pattern.is_match(b"| 3/12 | Ena |Up     |"));
        assert!(!exec.pattern.is_match(b"Welcome to Waveserver CLI!"));
    }

    #[test]
    fn test_submenu_prompt_match() {
        let p = platform();
        let exec = p.get_privilege("exec").unwrap();
        let sub = p.get_privilege("submenu").unwrap();

        assert!(sub.pattern.is_match(b"dci9.mi1(topology/show)# "));
        assert!(sub.pattern.is_match(b"\ndci9.mi1*(topology/show)# "));
        assert!(sub.pattern.is_match(b"dci9.mi1(xcvr)#"));
        assert!(!exec.pattern.is_match(b"dci9.mi1(topology/show)# "));
        assert!(!sub.pattern.is_match(b"dci9.mi1# "));

        assert_eq!(sub.previous_priv.as_deref(), Some("exec"));
        assert_eq!(sub.deescalate_command.as_deref(), Some("quit"));
    }

    #[test]
    fn test_on_open_disables_session_pager() {
        let p = platform();
        assert_eq!(
            p.on_open_commands,
            vec!["system shell session set more off"]
        );
    }

    #[test]
    fn test_failure_patterns() {
        let p = platform();
        assert!(
            p.failed_when_contains
                .contains(&"SHELL PARSER FAILURE".to_string())
        );
    }
}
