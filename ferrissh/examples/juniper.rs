//! Juniper JUNOS example
//!
//! This example demonstrates connecting to a Juniper device running JUNOS
//! and executing common operational and configuration commands.
//!
//! # Prerequisites
//!
//! - Juniper device running JUNOS (MX, SRX, EX, QFX, etc.)
//! - Valid credentials with appropriate permissions
//!
//! # Usage
//!
//! ```bash
//! cargo run --example juniper -- --host 192.168.1.1 --user admin --password secret
//! ```
//!
//! With SSH key:
//! ```bash
//! cargo run --example juniper -- --host router.example.com --user admin --key ~/.ssh/id_rsa
//! ```

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder, Platform};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh Juniper JUNOS Example ===\n");
    println!("Connecting to {}:{}...", args.host, args.port);

    // Build the driver with Juniper platform
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(Platform::JuniperJunos)
        .timeout(Duration::from_secs(args.timeout));

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

    // Show system information
    println!("Executing: show version");
    let response = driver.send_command("show version").await?;
    if !response.is_success() {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        // Print first 10 lines to keep output manageable
        let lines: Vec<&str> = response.result.lines().take(10).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 10 {
            println!("... (truncated)");
        }
    }
    println!();

    // Show chassis hardware
    println!("Executing: show chassis hardware");
    let response = driver.send_command("show chassis hardware").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(15).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 15 {
            println!("... (truncated)");
        }
    }
    println!();

    // Show interfaces terse
    println!("Executing: show interfaces terse");
    let response = driver.send_command("show interfaces terse").await?;
    if response.is_success() {
        let lines: Vec<&str> = response.result.lines().take(20).collect();
        println!("{}", lines.join("\n"));
        if response.result.lines().count() > 20 {
            println!("... (truncated)");
        }
    }
    println!();

    // --- Configuration Mode Demo ---
    if args.show_config {
        println!("--- Configuration Mode Demo ---\n");

        // Use send_config to automatically enter and exit config mode
        println!("Entering configuration mode...");
        let responses = driver
            .send_config(&[
                "show | compare",  // Show any uncommitted changes
            ])
            .await?;

        for response in &responses {
            if !response.is_success() {
                eprintln!("Config command failed: {:?}", response.failure_message);
            } else {
                println!("Uncommitted changes:\n{}", response.result);
            }
        }

        // Back in operational mode
        if let Some(priv_level) = driver.current_privilege() {
            println!("Back to privilege level: {}", priv_level);
        }
        println!();
    }

    // --- Multiple Commands ---
    println!("--- Batch Commands ---\n");

    let commands = [
        "show system uptime",
        "show system users",
    ];

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
            r#"ferrissh Juniper JUNOS example

Demonstrates connecting to Juniper devices and running JUNOS commands.

USAGE:
    cargo run --example juniper -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    -c, --show-config        Demo configuration mode (enters config)
    --help                   Print this help message

EXAMPLES:
    # Basic operational commands
    cargo run --example juniper -- --host router1 --user admin --password secret

    # With configuration mode demo
    cargo run --example juniper -- --host router1 --user admin --key ~/.ssh/id_rsa --show-config

    # Debug logging
    RUST_LOG=debug cargo run --example juniper -- --host router1 --user admin --password secret
"#
        );
    }
}
