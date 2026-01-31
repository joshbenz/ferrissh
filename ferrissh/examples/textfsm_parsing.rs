//! TextFSM Parsing Example
//!
//! This example demonstrates using ferrissh with textfsm-rust to parse
//! CLI output into structured data.
//!
//! # Prerequisites
//!
//! - A Linux host or Juniper device accessible via SSH
//! - Valid credentials
//!
//! # Usage
//!
//! Linux:
//! ```bash
//! cargo run --example textfsm_parsing -- --host localhost --user admin --password secret --platform linux
//! ```
//!
//! Juniper:
//! ```bash
//! cargo run --example textfsm_parsing -- --host router1 --user admin --password secret --platform juniper
//! ```

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder};
use textfsm_rust::Template;

/// Holds a command and its associated TextFSM template
struct CommandTemplate {
    command: &'static str,
    template: &'static str,
    description: &'static str,
}

/// Linux commands and templates
const LINUX_COMMANDS: &[CommandTemplate] = &[
    CommandTemplate {
        command: "uname -a",
        template: include_str!("templates/linux_uname.textfsm"),
        description: "System information",
    },
    CommandTemplate {
        command: "df -h",
        template: include_str!("templates/linux_df.textfsm"),
        description: "Disk usage",
    },
    CommandTemplate {
        command: "ps aux | head -20",
        template: include_str!("templates/linux_ps.textfsm"),
        description: "Running processes (top 20)",
    },
];

/// Juniper commands and templates
const JUNIPER_COMMANDS: &[CommandTemplate] = &[
    CommandTemplate {
        command: "show version",
        template: include_str!("templates/juniper_show_version.textfsm"),
        description: "System version information",
    },
    CommandTemplate {
        command: "show interfaces terse",
        template: include_str!("templates/juniper_show_interfaces_terse.textfsm"),
        description: "Interface status summary",
    },
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh + TextFSM Parsing Example ===\n");
    println!("Connecting to {}:{} (platform: {})...", args.host, args.port, args.platform);

    // Build the driver
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(&args.platform)
        .timeout(Duration::from_secs(args.timeout));

    if let Some(password) = &args.password {
        builder = builder.password(password);
    } else if let Some(key_path) = &args.key {
        builder = builder.private_key(key_path);
    } else {
        eprintln!("Error: Must provide either --password or --key");
        std::process::exit(1);
    }

    let mut driver = builder.build().await?;

    // Connect
    driver.open().await?;
    println!("Connected!\n");

    // Select commands based on platform
    let commands: &[CommandTemplate] = match args.platform.as_str() {
        "linux" => LINUX_COMMANDS,
        "juniper" | "juniper_junos" => JUNIPER_COMMANDS,
        _ => {
            eprintln!("Unsupported platform for this example: {}", args.platform);
            eprintln!("Supported platforms: linux, juniper");
            std::process::exit(1);
        }
    };

    // Execute each command and parse with TextFSM
    for cmd_template in commands {
        println!("{}", "=".repeat(60));
        println!("Command: {}", cmd_template.command);
        println!("Description: {}", cmd_template.description);
        println!("{}", "=".repeat(60));

        // Execute the command
        let response = driver.send_command(cmd_template.command).await?;

        if response.failed {
            eprintln!("Command failed: {:?}", response.failure_message);
            continue;
        }

        println!("\n--- Raw Output ---");
        // Print first 15 lines of raw output
        let lines: Vec<&str> = response.result.lines().take(15).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 15 {
            println!("... (truncated, {} total lines)", response.result.lines().count());
        }

        // Parse with TextFSM
        println!("\n--- Parsed Data (TextFSM) ---");
        match parse_with_textfsm(&response.result, cmd_template.template) {
            Ok(parsed) => {
                if parsed.is_empty() {
                    println!("(no records parsed)");
                } else {
                    // Print as JSON for readability
                    let json = serde_json::to_string_pretty(&parsed)?;
                    // Limit output if too many records
                    if parsed.len() > 10 {
                        let limited: Vec<_> = parsed.into_iter().take(10).collect();
                        let json = serde_json::to_string_pretty(&limited)?;
                        println!("{}", json);
                        println!("... (showing 10 of {} records)", response.result.lines().count());
                    } else {
                        println!("{}", json);
                    }
                }
            }
            Err(e) => {
                eprintln!("TextFSM parsing error: {}", e);
            }
        }

        println!("\nElapsed: {:?}", response.elapsed);
        println!();
    }

    // Demonstrate accessing parsed data programmatically
    println!("{}", "=".repeat(60));
    println!("Programmatic Access Example");
    println!("{}", "=".repeat(60));

    if args.platform == "linux" {
        // Parse uname output
        let response = driver.send_command("uname -a").await?;
        if !response.failed {
            let parsed = parse_with_textfsm(&response.result, LINUX_COMMANDS[0].template)?;
            if let Some(record) = parsed.first() {
                println!("\nSystem Info:");
                println!("  Kernel:   {}", record.get("kernel").unwrap_or(&String::new()));
                println!("  Hostname: {}", record.get("hostname").unwrap_or(&String::new()));
                println!("  Release:  {}", record.get("kernelrelease").unwrap_or(&String::new()));
                println!("  Machine:  {}", record.get("machine").unwrap_or(&String::new()));
            }
        }

        // Parse df output and find high usage filesystems
        let response = driver.send_command("df -h").await?;
        if !response.failed {
            let parsed = parse_with_textfsm(&response.result, LINUX_COMMANDS[1].template)?;

            println!("\nFilesystems with >50% usage:");
            for record in &parsed {
                if let Some(use_pct) = record.get("usepercent") {
                    if let Ok(pct) = use_pct.parse::<u32>() {
                        if pct > 50 {
                            println!(
                                "  {} - {}% used ({} of {})",
                                record.get("mountedon").unwrap_or(&String::new()),
                                pct,
                                record.get("used").unwrap_or(&String::new()),
                                record.get("size").unwrap_or(&String::new()),
                            );
                        }
                    }
                }
            }
        }
    } else if args.platform == "juniper" || args.platform == "juniper_junos" {
        // Parse show interfaces terse and find down interfaces
        let response = driver.send_command("show interfaces terse").await?;
        if !response.failed {
            let parsed = parse_with_textfsm(&response.result, JUNIPER_COMMANDS[1].template)?;

            println!("\nInterfaces that are DOWN:");
            let down_interfaces: Vec<_> = parsed
                .iter()
                .filter(|r| {
                    r.get("adminstatus").map(|s| s == "down").unwrap_or(false)
                        || r.get("linkstatus").map(|s| s == "down").unwrap_or(false)
                })
                .take(10)
                .collect();

            if down_interfaces.is_empty() {
                println!("  (none)");
            } else {
                for record in down_interfaces {
                    println!(
                        "  {} - Admin: {}, Link: {}",
                        record.get("interface").unwrap_or(&String::new()),
                        record.get("adminstatus").unwrap_or(&String::new()),
                        record.get("linkstatus").unwrap_or(&String::new()),
                    );
                }
            }

            println!("\nInterfaces that are UP:");
            let up_interfaces: Vec<_> = parsed
                .iter()
                .filter(|r| {
                    r.get("adminstatus").map(|s| s == "up").unwrap_or(false)
                        && r.get("linkstatus").map(|s| s == "up").unwrap_or(false)
                })
                .take(10)
                .collect();

            for record in up_interfaces {
                println!(
                    "  {} - {}",
                    record.get("interface").unwrap_or(&String::new()),
                    record.get("local").unwrap_or(&"(no IP)".to_string()),
                );
            }
        }
    }

    // Clean up
    println!("\n--- Cleanup ---\n");
    println!("Closing connection...");
    driver.close().await?;
    println!("Done!");

    Ok(())
}

/// Parse text output using a TextFSM template
fn parse_with_textfsm(
    output: &str,
    template_str: &str,
) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error>> {
    // Compile the template
    let template = Template::parse_str(template_str)?;

    // Create parser and parse the output directly to dictionaries
    let mut parser = template.parser();
    let records = parser.parse_text_to_dicts(output)?;

    Ok(records)
}

/// Simple argument parser
struct Args {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    key: Option<PathBuf>,
    timeout: u64,
    platform: String,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut host = "localhost".to_string();
        let mut port = 22u16;
        let mut user = env::var("USER").unwrap_or_else(|_| "admin".to_string());
        let mut password = None;
        let mut key = None;
        let mut timeout = 30u64;
        let mut platform = "linux".to_string();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--host" | "-h" => {
                    i += 1;
                    if i < args.len() {
                        host = args[i].clone();
                    }
                }
                "--port" | "-p" => {
                    i += 1;
                    if i < args.len() {
                        port = args[i].parse().unwrap_or(22);
                    }
                }
                "--user" | "-u" => {
                    i += 1;
                    if i < args.len() {
                        user = args[i].clone();
                    }
                }
                "--password" | "-P" => {
                    i += 1;
                    if i < args.len() {
                        password = Some(args[i].clone());
                    }
                }
                "--key" | "-k" => {
                    i += 1;
                    if i < args.len() {
                        key = Some(PathBuf::from(&args[i]));
                    }
                }
                "--timeout" | "-t" => {
                    i += 1;
                    if i < args.len() {
                        timeout = args[i].parse().unwrap_or(30);
                    }
                }
                "--platform" => {
                    i += 1;
                    if i < args.len() {
                        platform = args[i].clone();
                    }
                }
                "--help" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }

        Self {
            host,
            port,
            user,
            password,
            key,
            timeout,
            platform,
        }
    }

    fn print_help() {
        println!(
            r#"ferrissh + TextFSM parsing example

Demonstrates using ferrissh to collect CLI output and textfsm-rust to parse
it into structured data.

USAGE:
    cargo run --example textfsm_parsing -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    --platform <PLATFORM>    Device platform: linux, juniper [default: linux]
    --help                   Print this help message

EXAMPLES:
    # Parse Linux commands
    cargo run --example textfsm_parsing -- \
        --host myserver --user admin --password secret --platform linux

    # Parse Juniper commands
    cargo run --example textfsm_parsing -- \
        --host router1 --user admin --key ~/.ssh/id_rsa --platform juniper

    # With debug logging
    RUST_LOG=debug cargo run --example textfsm_parsing -- \
        --host localhost --user admin --password secret

SUPPORTED COMMANDS:
    Linux:
      - uname -a        -> Kernel, hostname, version info
      - df -h           -> Filesystem usage
      - ps aux          -> Process list

    Juniper:
      - show version           -> JUNOS version info
      - show interfaces terse  -> Interface status
"#
        );
    }
}
