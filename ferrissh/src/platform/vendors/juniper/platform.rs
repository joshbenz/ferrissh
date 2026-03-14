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

use bytes::BytesMut;

use crate::platform::{PlatformDefinition, PrivilegeLevel, StreamProcessor, VendorBehavior};

/// Platform name for Juniper JUNOS.
pub const PLATFORM_NAME: &str = "juniper_junos";

/// Create the Juniper JUNOS platform definition.
///
/// Prompt patterns adapted from scrapli's JunOS driver.
/// Uses `(?m)` flag for multiline (^ matches line start).
pub fn platform() -> PlatformDefinition {
    // Exec (operational) mode - ">" prompt
    let exec = PrivilegeLevel::new(
        "exec",
        r"(?m)(?-u)^(?:\{\w+(?:(?:\w+)?\d)?\}\n)?[\w\-@()/:\.]+>\s?$",
    )
    .unwrap();

    // Configuration mode - "#" prompt
    let configuration = PrivilegeLevel::new(
        "configuration",
        r"(?m)(?-u)^(?:\{\w+(?:(?:\w+)?\d)?\}\[edit\]\n)?[\w\-@()/:\.]+#\s?$",
    )
    .unwrap()
    .with_parent("exec")
    .with_escalate("configure")
    .with_deescalate("exit configuration-mode");

    // Shell mode - "%" or "$" prompt (non-root)
    let shell = PrivilegeLevel::new("shell", r"(?m)(?-u)^.*[%$]\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("start shell")
        .with_deescalate("exit")
        .with_not_contains("root");

    // Root shell mode - root user "%" or "#" prompt
    let root_shell = PrivilegeLevel::new("root_shell", r"(?m)(?-u)^.*root@(?:\S*:?\S*\s?)?[%#]\s?$")
        .unwrap()
        .with_parent("exec")
        .with_escalate("start shell user root")
        .with_deescalate("exit")
        .with_auth(r"(?-u)^password:\s?$")
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

struct JuniperStreamProcessor;

impl StreamProcessor for JuniperStreamProcessor {
    fn process_lines(&mut self, buf: &mut BytesMut) {
        JuniperBehavior.post_process_output(buf);
    }
}

impl VendorBehavior for JuniperBehavior {
    fn stream_processor(&self) -> Option<Box<dyn StreamProcessor>> {
        Some(Box::new(JuniperStreamProcessor))
    }

    fn post_process_output(&self, buf: &mut BytesMut) {
        // Filter out [edit] context lines that JUNOS includes in config mode.
        // In-place compaction: scan for lines starting with "[edit", skip them.
        if memchr::memmem::find(&buf[..], b"[edit").is_none() {
            return; // fast path: nothing to filter
        }

        let len = buf.len();
        let had_trailing_newline = buf.last() == Some(&b'\n');
        let mut write = 0;
        let mut offset = 0;

        while offset < len {
            // Find end of current line
            let line_end = memchr::memchr(b'\n', &buf[offset..])
                .map(|pos| offset + pos + 1)
                .unwrap_or(len);

            // Check if line starts with "[edit" (after optional whitespace)
            let skip = {
                let line = &buf[offset..line_end];
                let trimmed = trim_start_bytes(line);
                trimmed.starts_with(b"[edit")
            };

            if !skip {
                let line_len = line_end - offset;
                if write != offset {
                    // Need to compact: copy this line to write position
                    // Use copy_within to avoid borrow conflicts
                    buf.as_mut().copy_within(offset..line_end, write);
                }
                write += line_len;
            }

            offset = line_end;
        }

        // Remove trailing newline that may be left from a skipped last line
        if write > 0 && buf[write - 1] == b'\n' && !had_trailing_newline {
            write -= 1;
        }

        buf.truncate(write);
    }
}

/// Trim leading ASCII whitespace from a byte slice.
fn trim_start_bytes(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    &s[start..]
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
    fn test_post_process_no_edit_lines() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("Hostname: router\nModel: mx960");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"Hostname: router\nModel: mx960");
    }

    #[test]
    fn test_post_process_edit_line_middle() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("ge-0/0/0\n[edit]\nge-0/0/1");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"ge-0/0/0\nge-0/0/1");
    }

    #[test]
    fn test_post_process_edit_interfaces() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("ge-0/0/0\n[edit interfaces]");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"ge-0/0/0");
    }

    #[test]
    fn test_post_process_empty_buffer() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::new();
        behavior.post_process_output(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_post_process_only_edit_line() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("[edit]");
        behavior.post_process_output(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_post_process_multiple_edit_lines() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("config1\n[edit]\nconfig2\n[edit interfaces]\nconfig3");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"config1\nconfig2\nconfig3");
    }

    #[test]
    fn test_post_process_edit_at_start() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("[edit]\nge-0/0/0\nge-0/0/1");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"ge-0/0/0\nge-0/0/1");
    }

    #[test]
    fn test_post_process_edit_with_deep_path() {
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("output\n[edit protocols bgp group internal]\nmore output");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"output\nmore output");
    }

    #[test]
    fn test_post_process_bracket_not_edit() {
        // Lines with brackets but not [edit should be preserved
        let behavior = JuniperBehavior;
        let mut buf = BytesMut::from("[something else]\noutput");
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], b"[something else]\noutput");
    }

    #[test]
    fn test_post_process_preserves_content_exactly() {
        let behavior = JuniperBehavior;
        let content = "set system host-name router1\nset system domain-name example.com";
        let mut buf = BytesMut::from(content);
        behavior.post_process_output(&mut buf);
        assert_eq!(&buf[..], content.as_bytes());
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
