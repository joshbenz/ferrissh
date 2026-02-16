//! Interactive command example
//!
//! This example demonstrates how to use `send_interactive` for commands
//! that require user input or confirmation.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example interactive -- --host localhost --user your_username --password your_password
//! ```
//!
//! This example will:
//! 1. Connect to the host
//! 2. Demonstrate using InteractiveBuilder to create command sequences
//! 3. Show how to handle commands that require input

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder, InteractiveBuilder, InteractiveEvent, Platform};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh Interactive Command Example ===\n");

    // Build the driver
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(Platform::Linux)
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

    println!("Connecting to {}:{}...", args.host, args.port);
    driver.open().await?;
    println!("Connected!\n");

    // Example 1: Simple interactive using InteractiveEvent directly
    println!("--- Example 1: Using InteractiveEvent directly ---");
    println!("Sending 'echo hello' and waiting for prompt...\n");

    let events = vec![InteractiveEvent::new("echo hello", r"[$#]\s*$")?];

    let result = driver.send_interactive(&events).await?;

    println!("Result:");
    println!("  Steps: {}", result.steps.len());
    println!("  Total time: {:?}", result.elapsed);
    println!("  Failed: {}", !result.is_success());
    if let Some(output) = result.final_output() {
        println!("  Output: {}", output.trim());
    }
    println!();

    // Example 2: Using InteractiveBuilder for multi-step interactions
    println!("--- Example 2: Using InteractiveBuilder ---");
    println!("Creating a file, then reading it back...\n");

    let events = InteractiveBuilder::new()
        .send("echo 'Hello from ferrissh!' > /tmp/ferrissh_test.txt")
        .expect(r"[$#]\s*$")?
        .send("cat /tmp/ferrissh_test.txt")
        .expect(r"[$#]\s*$")?
        .send("rm /tmp/ferrissh_test.txt")
        .expect(r"[$#]\s*$")?
        .build();

    let result = driver.send_interactive(&events).await?;

    println!("Result:");
    for (i, step) in result.steps.iter().enumerate() {
        println!("  Step {}: '{}' -> {:?}", i + 1, step.input, step.elapsed);
        if !step.output.trim().is_empty() {
            println!("    Output: {}", step.output.trim());
        }
    }
    println!("  Total time: {:?}", result.elapsed);
    println!();

    // Example 3: Simulating a prompt that asks for confirmation
    println!("--- Example 3: Command with 'yes' confirmation ---");
    println!("Using 'read' to simulate waiting for input...\n");

    // This creates a command that outputs a prompt and waits for 'y'
    // Note: This is a simulation since most Linux commands don't need confirmation
    let events = InteractiveBuilder::new()
        .send("echo 'Continue? [y/n]' && read answer && echo \"You said: $answer\"")
        .expect(r"\[y/n\]")?
        .send("y")
        .expect(r"[$#]\s*$")?
        .with_timeout(Duration::from_secs(5))
        .build();

    let result = driver.send_interactive(&events).await?;

    println!("Result:");
    println!(
        "  Final output: {:?}",
        result.final_output().map(|s| s.trim())
    );
    println!("  Failed: {}", !result.is_success());
    println!();

    // Example 4: Show current privilege level
    println!("--- Example 4: Checking privilege level ---");
    if let Some(priv_level) = driver.current_privilege() {
        println!("Current privilege level: {}", priv_level);
    }
    println!();

    // Clean up
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
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut host = "localhost".to_string();
        let mut port = 22u16;
        let mut user = env::var("USER").unwrap_or_else(|_| "root".to_string());
        let mut password = None;
        let mut key = None;
        let mut timeout = 30u64;

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
        }
    }

    fn print_help() {
        println!(
            r#"ferrissh interactive example

Demonstrates send_interactive for commands requiring user input.

USAGE:
    cargo run --example interactive -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    --help                   Print this help message
"#
        );
    }
}
