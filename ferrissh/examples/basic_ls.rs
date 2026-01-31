//! Basic example: Connect to localhost and run `ls`
//!
//! This example demonstrates the basic usage of ferrissh to connect
//! to a Linux host and execute a command.
//!
//! # Prerequisites
//!
//! - SSH server running on localhost (port 22)
//! - Valid credentials (username/password or SSH key)
//!
//! # Usage
//!
//! With password authentication:
//! ```bash
//! cargo run --example basic_ls -- --host localhost --user your_username --password your_password
//! ```
//!
//! With SSH key authentication:
//! ```bash
//! cargo run --example basic_ls -- --host localhost --user your_username --key ~/.ssh/id_rsa
//! ```

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (set RUST_LOG=debug for verbose output)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let args = Args::parse();

    println!("Connecting to {}:{}...", args.host, args.port);

    // Build the driver
    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform("linux")
        .timeout(Duration::from_secs(args.timeout));

    // Set authentication method
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
    println!("Opening connection...");
    driver.open().await?;
    println!("Connected!");

    // Run the ls command
    println!("\nExecuting: ls -la");
    println!("{}", "-".repeat(50));

    let response = driver.send_command("ls -la").await?;

    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        println!("{}", response.result);
    }

    println!("{}", "-".repeat(50));
    println!("Command completed in {:?}", response.elapsed);

    // Run a few more commands to demonstrate
    println!("\nExecuting: pwd");
    let response = driver.send_command("pwd").await?;
    println!("Current directory: {}", response.result.trim());

    println!("\nExecuting: whoami");
    let response = driver.send_command("whoami").await?;
    println!("Running as: {}", response.result.trim());

    println!("\nExecuting: uname -a");
    let response = driver.send_command("uname -a").await?;
    println!("System: {}", response.result.trim());

    // Close the connection
    println!("\nClosing connection...");
    driver.close().await?;
    println!("Done!");

    Ok(())
}

/// Simple argument parser (avoiding external dependencies)
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
                _ => {
                    eprintln!("Unknown argument: {}", args[i]);
                }
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
            r#"ferrissh basic_ls example

USAGE:
    cargo run --example basic_ls -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    --help                   Print this help message

EXAMPLES:
    # Connect with password
    cargo run --example basic_ls -- --host localhost --user admin --password secret

    # Connect with SSH key
    cargo run --example basic_ls -- --host 192.168.1.1 --user root --key ~/.ssh/id_rsa

    # Connect to non-standard port
    cargo run --example basic_ls -- --host myserver --port 2222 --user admin --key ~/.ssh/id_rsa
"#
        );
    }
}
