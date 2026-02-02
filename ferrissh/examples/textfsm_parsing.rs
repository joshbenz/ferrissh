//! TextFSM Parsing Example
//!
//! This example demonstrates using ferrissh with textfsm-rust to parse
//! CLI output into strongly-typed Rust structs using serde deserialization.
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

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ferrissh::{Driver, DriverBuilder};
use serde::{Deserialize, Serialize};
use textfsm_rust::Template;

// =============================================================================
// Linux Structs
// =============================================================================

/// Parsed output from `uname -a`
#[derive(Debug, Deserialize, Serialize)]
struct UnameInfo {
    kernel: String,
    hostname: String,
    #[serde(rename = "kernelrelease")]
    kernel_release: String,
    #[serde(rename = "kernelversion")]
    kernel_version: String,
    machine: String,
    os: String,
}

/// Parsed output from `df -h`
#[derive(Debug, Deserialize, Serialize)]
struct DiskUsage {
    filesystem: String,
    size: String,
    used: String,
    available: String,
    #[serde(rename = "usepercent")]
    use_percent: String,
    #[serde(rename = "mountedon")]
    mounted_on: String,
}

impl DiskUsage {
    /// Get usage percentage as a number
    fn use_percent_num(&self) -> Option<u32> {
        self.use_percent.parse().ok()
    }
}

/// Parsed output from `ps aux`
#[derive(Debug, Deserialize, Serialize)]
struct ProcessInfo {
    user: String,
    pid: String,
    cpu: String,
    mem: String,
    vsz: String,
    rss: String,
    tty: String,
    stat: String,
    start: String,
    time: String,
    command: String,
}

impl ProcessInfo {
    /// Get CPU usage as a number
    fn cpu_percent(&self) -> Option<f32> {
        self.cpu.parse().ok()
    }

    /// Get memory usage as a number
    fn mem_percent(&self) -> Option<f32> {
        self.mem.parse().ok()
    }
}

// =============================================================================
// Juniper Structs
// =============================================================================

/// Parsed output from `show version`
#[derive(Debug, Deserialize, Serialize)]
struct JuniperVersion {
    hostname: Option<String>,
    model: Option<String>,
    #[serde(rename = "junosversion")]
    junos_version: Option<String>,
    kernel: String,
}

/// Parsed output from `show interfaces terse`
#[derive(Debug, Deserialize, Serialize)]
struct JuniperInterface {
    interface: String,
    #[serde(rename = "adminstatus")]
    admin_status: Option<String>,
    #[serde(rename = "linkstatus")]
    link_status: Option<String>,
    proto: Option<String>,
    local: Option<String>,
    remote: Option<String>,
}

impl JuniperInterface {
    fn is_up(&self) -> bool {
        self.admin_status.as_deref() == Some("up")
            && self.link_status.as_deref() == Some("up")
    }

    fn is_down(&self) -> bool {
        self.admin_status.as_deref() == Some("down")
            || self.link_status.as_deref() == Some("down")
    }
}

// =============================================================================
// Templates
// =============================================================================

const LINUX_UNAME_TEMPLATE: &str = include_str!("templates/linux_uname.textfsm");
const LINUX_DF_TEMPLATE: &str = include_str!("templates/linux_df.textfsm");
const LINUX_PS_TEMPLATE: &str = include_str!("templates/linux_ps.textfsm");
const JUNIPER_VERSION_TEMPLATE: &str = include_str!("templates/juniper_show_version.textfsm");
const JUNIPER_INTERFACES_TEMPLATE: &str = include_str!("templates/juniper_show_interfaces_terse.textfsm");

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

    match args.platform.as_str() {
        "linux" => run_linux_examples(&mut driver).await?,
        "juniper" | "juniper_junos" => run_juniper_examples(&mut driver).await?,
        _ => {
            eprintln!("Unsupported platform: {}", args.platform);
            eprintln!("Supported platforms: linux, juniper");
            std::process::exit(1);
        }
    }

    // Clean up
    println!("\n--- Cleanup ---\n");
    println!("Closing connection...");
    driver.close().await?;
    println!("Done!");

    Ok(())
}

async fn run_linux_examples(driver: &mut impl Driver) -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // Example 1: Parse uname -a into UnameInfo struct
    // =========================================================================
    println!("{}", "=".repeat(60));
    println!("Command: uname -a");
    println!("Parsing into: UnameInfo struct");
    println!("{}", "=".repeat(60));

    let response = driver.send_command("uname -a").await?;
    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        println!("\nRaw output: {}", response.result.trim());

        let template = Template::parse_str(LINUX_UNAME_TEMPLATE)?;
        let mut parser = template.parser();
        let results: Vec<UnameInfo> = parser.parse_text_into(&response.result)?;

        if let Some(info) = results.first() {
            println!("\nParsed UnameInfo struct:");
            println!("  Kernel:         {}", info.kernel);
            println!("  Hostname:       {}", info.hostname);
            println!("  Kernel Release: {}", info.kernel_release);
            println!("  Kernel Version: {}", info.kernel_version);
            println!("  Machine:        {}", info.machine);
            println!("  OS:             {}", info.os);
        }
    }
    println!();

    // =========================================================================
    // Example 2: Parse df -h into Vec<DiskUsage>
    // =========================================================================
    println!("{}", "=".repeat(60));
    println!("Command: df -h");
    println!("Parsing into: Vec<DiskUsage>");
    println!("{}", "=".repeat(60));

    let response = driver.send_command("df -h").await?;
    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        println!("\nRaw output (first 10 lines):");
        for line in response.result.lines().take(10) {
            println!("  {}", line);
        }

        let template = Template::parse_str(LINUX_DF_TEMPLATE)?;
        let mut parser = template.parser();
        let disks: Vec<DiskUsage> = parser.parse_text_into(&response.result)?;

        println!("\nParsed {} DiskUsage records", disks.len());

        // Show filesystems with high usage using typed access
        println!("\nFilesystems with >50% usage:");
        let high_usage: Vec<_> = disks
            .iter()
            .filter(|d| d.use_percent_num().map(|p| p > 50).unwrap_or(false))
            .collect();

        if high_usage.is_empty() {
            println!("  (none)");
        } else {
            for disk in high_usage {
                println!(
                    "  {} - {}% used ({} of {}) mounted on {}",
                    disk.filesystem,
                    disk.use_percent,
                    disk.used,
                    disk.size,
                    disk.mounted_on
                );
            }
        }

        // Print as JSON to show the full structure
        println!("\nFirst 3 records as JSON:");
        let sample: Vec<_> = disks.into_iter().take(3).collect();
        println!("{}", serde_json::to_string_pretty(&sample)?);
    }
    println!();

    // =========================================================================
    // Example 3: Parse ps aux into Vec<ProcessInfo>
    // =========================================================================
    println!("{}", "=".repeat(60));
    println!("Command: ps aux | head -20");
    println!("Parsing into: Vec<ProcessInfo>");
    println!("{}", "=".repeat(60));

    let response = driver.send_command("ps aux | head -20").await?;
    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        let template = Template::parse_str(LINUX_PS_TEMPLATE)?;
        let mut parser = template.parser();
        let processes: Vec<ProcessInfo> = parser.parse_text_into(&response.result)?;

        println!("\nParsed {} ProcessInfo records", processes.len());

        // Find top CPU consumers using typed methods
        println!("\nTop 5 CPU consumers:");
        let mut sorted: Vec<_> = processes.iter().collect();
        sorted.sort_by(|a, b| {
            b.cpu_percent()
                .unwrap_or(0.0)
                .partial_cmp(&a.cpu_percent().unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for proc in sorted.iter().take(5) {
            println!(
                "  PID {:>6} | CPU {:>5}% | MEM {:>5}% | {}",
                proc.pid,
                proc.cpu,
                proc.mem,
                if proc.command.len() > 40 {
                    format!("{}...", &proc.command[..40])
                } else {
                    proc.command.clone()
                }
            );
        }

        // Print one full record as JSON
        if let Some(first) = processes.first() {
            println!("\nExample ProcessInfo as JSON:");
            println!("{}", serde_json::to_string_pretty(&first)?);
        }
    }

    Ok(())
}

async fn run_juniper_examples(driver: &mut impl Driver) -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // Example 1: Parse show version into JuniperVersion
    // =========================================================================
    println!("{}", "=".repeat(60));
    println!("Command: show version");
    println!("Parsing into: Vec<JuniperVersion>");
    println!("{}", "=".repeat(60));

    let response = driver.send_command("show version").await?;
    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        println!("\nRaw output (first 15 lines):");
        for line in response.result.lines().take(15) {
            println!("  {}", line);
        }

        let template = Template::parse_str(JUNIPER_VERSION_TEMPLATE)?;
        let mut parser = template.parser();
        let versions: Vec<JuniperVersion> = parser.parse_text_into(&response.result)?;

        println!("\nParsed {} JuniperVersion records", versions.len());

        for (i, ver) in versions.iter().enumerate() {
            println!("\nRecord {}:", i + 1);
            if let Some(h) = &ver.hostname {
                println!("  Hostname:      {}", h);
            }
            if let Some(m) = &ver.model {
                println!("  Model:         {}", m);
            }
            if let Some(v) = &ver.junos_version {
                println!("  JUNOS Version: {}", v);
            }
            println!("  Kernel:        {}", ver.kernel);
        }
    }
    println!();

    // =========================================================================
    // Example 2: Parse show interfaces terse into Vec<JuniperInterface>
    // =========================================================================
    println!("{}", "=".repeat(60));
    println!("Command: show interfaces terse");
    println!("Parsing into: Vec<JuniperInterface>");
    println!("{}", "=".repeat(60));

    let response = driver.send_command("show interfaces terse").await?;
    if response.failed {
        eprintln!("Command failed: {:?}", response.failure_message);
    } else {
        let template = Template::parse_str(JUNIPER_INTERFACES_TEMPLATE)?;
        let mut parser = template.parser();
        let interfaces: Vec<JuniperInterface> = parser.parse_text_into(&response.result)?;

        println!("\nParsed {} JuniperInterface records", interfaces.len());

        // Use typed methods to filter interfaces
        let up_interfaces: Vec<_> = interfaces.iter().filter(|i| i.is_up()).collect();
        let down_interfaces: Vec<_> = interfaces.iter().filter(|i| i.is_down()).collect();

        println!("\nInterfaces that are UP ({}):", up_interfaces.len());
        for iface in up_interfaces.iter().take(10) {
            let ip = iface.local.as_deref().unwrap_or("(no IP)");
            println!("  {} - {}", iface.interface, ip);
        }
        if up_interfaces.len() > 10 {
            println!("  ... and {} more", up_interfaces.len() - 10);
        }

        println!("\nInterfaces that are DOWN ({}):", down_interfaces.len());
        for iface in down_interfaces.iter().take(10) {
            println!(
                "  {} - Admin: {}, Link: {}",
                iface.interface,
                iface.admin_status.as_deref().unwrap_or("?"),
                iface.link_status.as_deref().unwrap_or("?")
            );
        }
        if down_interfaces.len() > 10 {
            println!("  ... and {} more", down_interfaces.len() - 10);
        }

        // Print sample as JSON
        println!("\nFirst 3 interfaces as JSON:");
        let sample: Vec<_> = interfaces.into_iter().take(3).collect();
        println!("{}", serde_json::to_string_pretty(&sample)?);
    }

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
it into strongly-typed Rust structs via serde deserialization.

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

PARSED STRUCTS:
    Linux:
      - UnameInfo:       uname -a output (kernel, hostname, release, etc.)
      - DiskUsage:       df -h output (filesystem, size, used, available, %)
      - ProcessInfo:     ps aux output (user, pid, cpu, mem, command, etc.)

    Juniper:
      - JuniperVersion:    show version (hostname, model, junos_version, kernel)
      - JuniperInterface:  show interfaces terse (interface, admin/link status, IP)
"#
        );
    }
}
