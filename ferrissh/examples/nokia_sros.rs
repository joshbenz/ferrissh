//! Nokia SR OS example
//!
//! This example demonstrates connecting to a Nokia SR OS device and
//! running operational commands. The platform auto-detects whether
//! the device is running MD-CLI or Classic CLI.
//!
//! # Prerequisites
//!
//! - Nokia SR OS device (7750, 7250, etc.)
//! - Valid credentials with appropriate permissions
//!
//! # Usage
//!
//! ```bash
//! cargo run --example nokia_sros -- --host pe1 --user admin --password admin
//! ```
//!
//! With SSH key:
//! ```bash
//! cargo run --example nokia_sros -- --host pe1 --user admin --key ~/.ssh/id_rsa
//! ```

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder, Platform};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh Nokia SR OS Example ===\n");
    println!("Connecting to {}:{}...", args.host, args.port);

    // Build the driver with Nokia platform
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(Platform::NokiaSros)
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

    // Check current privilege level (reveals MD-CLI vs Classic CLI)
    if let Some(priv_level) = driver.current_privilege() {
        println!("Current privilege level: {}\n", priv_level);
    }

    // --- Operational Commands ---
    println!("--- Operational Commands ---\n");

    // Show system information
    println!("Executing: show system information");
    let response = driver.send_command("show system information").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(15).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 15 {
            println!("... (truncated)");
        }
    } else {
        eprintln!("Command failed: {:?}", response.failure_message);
    }
    println!();

    // Show router interface
    println!("Executing: show router interface");
    let response = driver.send_command("show router interface").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(20).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 20 {
            println!("... (truncated)");
        }
    }
    println!();

    // Show port
    println!("Executing: show port");
    let response = driver.send_command("show port").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(20).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 20 {
            println!("... (truncated)");
        }
    }
    println!();

    // --- Batch Commands ---
    println!("--- Batch Commands ---\n");

    let commands = ["show system cpu", "show system memory-pools"];

    println!("Executing {} commands...", commands.len());
    let responses = driver.send_commands(&commands).await?;

    for (cmd, response) in commands.iter().zip(responses.iter()) {
        println!("\n> {}", cmd);
        println!("{}", "-".repeat(40));
        if !response.is_success() {
            eprintln!("Failed: {:?}", response.failure_message);
        } else {
            let lines: Vec<&str> = response.result.lines().take(15).collect();
            println!("{}", lines.join("\n"));
        }
    }

    // --- Config Session Demo ---
    if args.show_config {
        println!("\n--- Config Session Demo (MD-CLI) ---\n");

        use ferrissh::platform::vendors::nokia_sros::NokiaConfigSession;
        use ferrissh::{ConfigSession, Diffable, Validatable};

        match NokiaConfigSession::new(&mut driver).await {
            Ok(mut session) => {
                println!("Entered exclusive configuration mode");

                // Show any pending changes
                let diff = session.diff().await?;
                if diff.trim().is_empty() {
                    println!("No pending changes");
                } else {
                    println!("Pending changes:\n{}", diff);
                }

                // Validate current config
                let result = session.validate().await?;
                println!("Validation: {}", if result.valid { "OK" } else { "FAILED" });

                // Abort (don't make real changes in this demo)
                session.abort().await?;
                println!("Config session aborted (demo mode)");
            }
            Err(e) => {
                eprintln!("Could not create config session: {}", e);
                eprintln!("(This is expected if the device is running Classic CLI)");
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
            r#"ferrissh Nokia SR OS example

Demonstrates connecting to Nokia SR OS devices and running operational commands.
Auto-detects MD-CLI vs Classic CLI mode.

USAGE:
    cargo run --example nokia_sros -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    -c, --show-config        Demo configuration session (MD-CLI only)
    --help                   Print this help message

EXAMPLES:
    # Basic operational commands
    cargo run --example nokia_sros -- --host pe1 --user admin --password admin

    # With config session demo
    cargo run --example nokia_sros -- --host pe1 --user admin --password admin --show-config

    # Debug logging
    RUST_LOG=debug cargo run --example nokia_sros -- --host pe1 --user admin --password admin
"#
        );
    }
}
