//! Arista EOS example
//!
//! This example demonstrates connecting to an Arista EOS switch and
//! running operational commands. Optionally demonstrates named config
//! sessions with diff and commit.
//!
//! # Prerequisites
//!
//! - Arista EOS switch (vEOS, cEOS, or hardware)
//! - Valid credentials with appropriate permissions
//!
//! # Usage
//!
//! ```bash
//! cargo run --example arista_eos -- --host switch1 --user admin --password secret
//! ```
//!
//! With config session demo:
//! ```bash
//! cargo run --example arista_eos -- --host switch1 --user admin --password secret --show-config
//! ```

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder, Platform};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh Arista EOS Example ===\n");
    println!("Connecting to {}:{}...", args.host, args.port);

    // Build the driver with Arista platform
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(Platform::AristaEos)
        .timeout(Duration::from_secs(args.timeout))
        .danger_disable_host_key_verification();

    if let Some(password) = &args.password {
        builder = builder.password(password);
    } else if let Some(key_path) = &args.key {
        builder = builder.private_key(key_path);
    } else {
        eprintln!("Error: Must provide either --password or --key");
        std::process::exit(1);
    }

    let mut driver = builder.build()?;

    // Connect
    driver.open().await?;
    println!("Connected!\n");

    // Check current privilege level
    if let Some(priv_level) = driver.current_privilege() {
        println!("Current privilege level: {}\n", priv_level);
    }

    // --- Operational Commands ---
    println!("--- Operational Commands ---\n");

    // Show version
    println!("Executing: show version");
    let response = driver.send_command("show version").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(10).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 10 {
            println!("... (truncated)");
        }
    } else {
        eprintln!("Command failed: {:?}", response.failure_message);
    }
    println!();

    // Show interfaces status
    println!("Executing: show interfaces status");
    let response = driver.send_command("show interfaces status").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(20).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 20 {
            println!("... (truncated)");
        }
    }
    println!();

    // Show IP route summary
    println!("Executing: show ip route summary");
    let response = driver.send_command("show ip route summary").await?;
    if response.is_success() {
        println!("{}", response.result);
    }
    println!();

    // --- Config Session Demo ---
    if args.show_config {
        println!("--- Named Config Session Demo ---\n");

        use ferrissh::{ConfigSession, Diffable};
        use ferrissh::platform::vendors::arista::AristaConfigSession;

        // Create a named session (isolated from other users)
        let mut session = AristaConfigSession::new(&mut driver, "ferrissh-demo").await?;
        println!("Entered named config session: ferrissh-demo");

        // Show any pending diffs
        let diff = session.diff().await?;
        if diff.trim().is_empty() {
            println!("No pending changes in session");
        } else {
            println!("Session diffs:\n{}", diff);
        }

        // Abort (don't make real changes in this demo)
        session.abort().await?;
        println!("Config session aborted (demo mode)");
    }

    // --- Batch Commands ---
    println!("\n--- Batch Commands ---\n");

    let commands = ["show hostname", "show uptime"];

    println!("Executing {} commands...", commands.len());
    let responses = driver.send_commands(&commands).await?;

    for (cmd, response) in commands.iter().zip(responses.iter()) {
        println!("\n> {}", cmd);
        println!("{}", "-".repeat(40));
        if !response.is_success() {
            eprintln!("Failed: {:?}", response.failure_message);
        } else {
            println!("{}", response.result);
        }
    }

    // Clean up
    println!("\n--- Cleanup ---\n");
    println!("Closing connection...");
    driver.close().await?;
    println!("Done!");

    Ok(())
}

/// Simple argument parser
struct Args {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    key: Option<PathBuf>,
    timeout: u64,
    show_config: bool,
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
        let mut show_config = false;

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
                "--show-config" | "-c" => {
                    show_config = true;
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
            show_config,
        }
    }

    fn print_help() {
        println!(
            r#"ferrissh Arista EOS example

Demonstrates connecting to Arista EOS switches and running operational commands.
Supports named configuration sessions with diff and commit.

USAGE:
    cargo run --example arista_eos -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    -c, --show-config        Demo named config session
    --help                   Print this help message

EXAMPLES:
    # Basic operational commands
    cargo run --example arista_eos -- --host switch1 --user admin --password secret

    # With config session demo
    cargo run --example arista_eos -- --host switch1 --user admin --password secret --show-config

    # Debug logging
    RUST_LOG=debug cargo run --example arista_eos -- --host switch1 --user admin --password secret
"#
        );
    }
}
