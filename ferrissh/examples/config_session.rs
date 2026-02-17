//! Config Session example
//!
//! Demonstrates RAII-guarded config sessions with diff, validate, commit,
//! and abort across multiple vendors. Shows the extension trait pattern
//! (Diffable, Validatable, ConfirmableCommit, NamedSession).
//!
//! # Usage
//!
//! ```bash
//! # Juniper config session
//! cargo run --example config_session -- --host router1 --user admin --password secret --platform juniper
//!
//! # Arista EOS named session
//! cargo run --example config_session -- --host switch1 --user admin --password secret --platform arista
//!
//! # Nokia SR OS (MD-CLI)
//! cargo run --example config_session -- --host pe1 --user admin --password admin --platform nokia
//! ```

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{ConfigSession, Diffable, Driver, DriverBuilder, Platform, Validatable};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    println!("=== Ferrissh Config Session Example ===\n");
    println!(
        "Connecting to {}:{} (platform: {})...",
        args.host, args.port, args.platform
    );

    // Build the driver
    let platform = match args.platform.as_str() {
        "juniper" | "juniper_junos" => Platform::JuniperJunos,
        "arista" | "arista_eos" => Platform::AristaEos,
        "nokia" | "nokia_sros" => Platform::NokiaSros,
        "arrcus" | "arrcus_arcos" => Platform::ArrcusArcOs,
        other => {
            eprintln!("Unknown platform: {other}");
            eprintln!("Supported: juniper, arista, nokia, arrcus");
            std::process::exit(1);
        }
    };

    let mut builder = DriverBuilder::new(&args.host)
        .port(args.port)
        .username(&args.user)
        .platform(platform)
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

    if let Some(priv_level) = driver.current_privilege() {
        println!("Current privilege level: {}\n", priv_level);
    }

    match args.platform.as_str() {
        "juniper" | "juniper_junos" => demo_juniper(&mut driver).await?,
        "arista" | "arista_eos" => demo_arista(&mut driver).await?,
        "nokia" | "nokia_sros" => demo_nokia(&mut driver).await?,
        "arrcus" | "arrcus_arcos" => demo_arrcus(&mut driver).await?,
        _ => unreachable!(),
    }

    println!("\nClosing connection...");
    driver.close().await?;
    println!("Done!");

    Ok(())
}

async fn demo_juniper(
    driver: &mut ferrissh::GenericDriver,
) -> Result<(), Box<dyn std::error::Error>> {
    use ferrissh::platform::vendors::juniper::JuniperConfigSession;

    println!("--- Juniper Config Session ---\n");

    // Create session (enters configure mode)
    let mut session = JuniperConfigSession::new(driver).await?;
    println!("Entered configuration mode");

    // Check for pending changes
    let diff = session.diff().await?;
    if diff.trim().is_empty() {
        println!("No pending changes");
    } else {
        println!("Pending changes:\n{}", diff);
    }

    // Validate current config
    let result = session.validate().await?;
    println!(
        "Validation: {}",
        if result.valid {
            "OK".to_string()
        } else {
            format!("FAILED: {:?}", result.errors)
        }
    );

    // Abort without making changes
    session.abort().await?;
    println!("Session aborted (demo mode)");

    if let Some(priv_level) = driver.current_privilege() {
        println!("Back to privilege level: {}", priv_level);
    }

    Ok(())
}

async fn demo_arista(
    driver: &mut ferrissh::GenericDriver,
) -> Result<(), Box<dyn std::error::Error>> {
    use ferrissh::platform::vendors::arista::AristaConfigSession;

    println!("--- Arista Named Config Session ---\n");

    // Create a named session (isolated candidate config)
    let mut session = AristaConfigSession::new(driver, "ferrissh-demo").await?;
    println!("Entered named config session: ferrissh-demo");

    // Show session diffs
    let diff = session.diff().await?;
    if diff.trim().is_empty() {
        println!("No pending changes in session");
    } else {
        println!("Session diffs:\n{}", diff);
    }

    // Abort without making changes
    session.abort().await?;
    println!("Session aborted (demo mode)");

    Ok(())
}

async fn demo_nokia(
    driver: &mut ferrissh::GenericDriver,
) -> Result<(), Box<dyn std::error::Error>> {
    use ferrissh::platform::vendors::nokia_sros::NokiaConfigSession;

    println!("--- Nokia SR OS Config Session (MD-CLI) ---\n");

    match NokiaConfigSession::new(driver).await {
        Ok(mut session) => {
            println!("Entered exclusive configuration mode");

            let diff = session.diff().await?;
            if diff.trim().is_empty() {
                println!("No pending changes");
            } else {
                println!("Pending changes:\n{}", diff);
            }

            let result = session.validate().await?;
            println!(
                "Validation: {}",
                if result.valid {
                    "OK".to_string()
                } else {
                    format!("FAILED: {:?}", result.errors)
                }
            );

            session.abort().await?;
            println!("Session aborted (demo mode)");
        }
        Err(e) => {
            eprintln!("Could not create config session: {}", e);
            eprintln!("(Expected if device is running Classic CLI)");
        }
    }

    Ok(())
}

async fn demo_arrcus(
    driver: &mut ferrissh::GenericDriver,
) -> Result<(), Box<dyn std::error::Error>> {
    use ferrissh::platform::vendors::arrcus_arcos;

    println!("--- Arrcus ArcOS Config Session (ConfD) ---\n");

    // Uses the generic ConfD config session
    let mut session = arrcus_arcos::config_session(driver).await?;
    println!("Entered ConfD configuration mode");

    let diff = session.diff().await?;
    if diff.trim().is_empty() {
        println!("No pending changes");
    } else {
        println!("Pending changes:\n{}", diff);
    }

    let result = session.validate().await?;
    println!(
        "Validation: {}",
        if result.valid {
            "OK".to_string()
        } else {
            format!("FAILED: {:?}", result.errors)
        }
    );

    session.abort().await?;
    println!("Session aborted (demo mode)");

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
        let mut platform = "juniper".to_string();

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
            r#"ferrissh config session example

Demonstrates RAII-guarded config sessions with diff, validate, commit, and abort.
Shows the extension trait pattern across multiple vendors.

USAGE:
    cargo run --example config_session -- [OPTIONS]

OPTIONS:
    -h, --host <HOST>        Target host [default: localhost]
    -p, --port <PORT>        SSH port [default: 22]
    -u, --user <USER>        Username [default: $USER]
    -P, --password <PASS>    Password for authentication
    -k, --key <PATH>         Path to SSH private key
    -t, --timeout <SECS>     Connection timeout [default: 30]
    --platform <PLATFORM>    Device platform: juniper, arista, nokia, arrcus [default: juniper]
    --help                   Print this help message

EXAMPLES:
    # Juniper config session (diff + validate + abort)
    cargo run --example config_session -- --host router1 --user admin --password secret --platform juniper

    # Arista named config session
    cargo run --example config_session -- --host switch1 --user admin --password secret --platform arista

    # Nokia SR OS (MD-CLI exclusive mode)
    cargo run --example config_session -- --host pe1 --user admin --password admin --platform nokia

    # Arrcus ArcOS (ConfD)
    cargo run --example config_session -- --host arrcus1 --user admin --password secret --platform arrcus
"#
        );
    }
}
