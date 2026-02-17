//! Streaming output example: real-time command output via `send_command_stream`.
//!
//! This example demonstrates streaming output from a long-running command
//! without buffering the entire response in memory.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example streaming -- --host localhost --user admin --password secret
//! ```

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder, Platform};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("Connecting to {}:{}...", args.host, args.port);

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

    driver.open().await?;
    println!("Connected!\n");

    // Stream a command's output in real time
    let command = args.command.as_deref().unwrap_or("ls -la /");
    println!("Streaming: {}", command);
    println!("{}", "-".repeat(50));

    let mut stream = driver.send_command_stream(command).await?;
    let mut total_bytes = 0usize;

    while let Some(chunk) = stream.next_chunk().await? {
        total_bytes += chunk.len();
        let text = String::from_utf8_lossy(&chunk);
        print!("{}", text);
        io::stdout().flush()?;
    }

    let response = stream.into_response()?;
    println!("\n{}", "-".repeat(50));
    println!(
        "Streamed {} bytes in {:?} (success: {})",
        total_bytes,
        response.elapsed,
        response.is_success()
    );
    println!("Prompt: {:?}", response.prompt);

    driver.close().await?;
    println!("Done!");

    Ok(())
}

struct Args {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    key: Option<PathBuf>,
    timeout: u64,
    command: Option<String>,
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
        let mut command = None;

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
                "--command" | "-c" => {
                    i += 1;
                    if i < args.len() {
                        command = Some(args[i].clone());
                    }
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
            command,
        }
    }
}
