# ferrissh

An async SSH CLI scraper library for network device automation in Rust.

[![Crates.io](https://img.shields.io/crates/v/ferrissh.svg)](https://crates.io/crates/ferrissh)
[![Documentation](https://docs.rs/ferrissh/badge.svg)](https://docs.rs/ferrissh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Warning:** This library is experimental and under active development. The API is subject to change without notice. Use in production at your own risk.

Ferrissh provides a high-level async API for interacting with network devices over SSH, similar to Python's [scrapli](https://github.com/carlmontanari/scrapli) and [netmiko](https://github.com/ktbyers/netmiko) libraries.

## Features

- **Async/Await** - Built on Tokio and russh for efficient async SSH connections
- **Multi-Vendor Support** - Linux, Juniper JUNOS, with more coming
- **Privilege Management** - Automatic navigation between privilege levels
- **Interactive Commands** - Handle prompts requiring user input (confirmations, passwords)
- **Configuration Mode** - Automatic privilege escalation for config commands
- **Pattern Matching** - Efficient tail-search buffer matching (scrapli-style optimization)
- **Output Normalization** - Clean output with command echo and prompt stripping
- **Error Detection** - Vendor-specific failure pattern detection
- **Easy Extensibility** - Add custom platforms with minimal code

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ferrissh = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use ferrissh::{Driver, DriverBuilder};

#[tokio::main]
async fn main() -> Result<(), ferrissh::Error> {
    // Connect to a Linux host
    let mut driver = DriverBuilder::new("192.168.1.1")
        .username("admin")
        .password("secret")
        .platform("linux")
        .build()
        .await?;

    driver.open().await?;

    // Send a command
    let response = driver.send_command("uname -a").await?;
    println!("{}", response.result);

    driver.close().await?;
    Ok(())
}
```

## Supported Platforms

| Platform | Name | Privilege Levels |
|----------|------|------------------|
| Linux/Unix | `linux` | user (`$`), root (`#`) |
| Juniper JUNOS | `juniper` | exec (`>`), configuration (`#`), shell (`%`) |



## Usage Examples

### Basic Commands

```rust
use ferrissh::{Driver, DriverBuilder};

let mut driver = DriverBuilder::new("router.example.com")
    .username("admin")
    .password("secret")
    .platform("juniper")
    .build()
    .await?;

driver.open().await?;

// Single command
let response = driver.send_command("show version").await?;
println!("{}", response.result);

// Multiple commands
let responses = driver.send_commands(&[
    "show interfaces terse",
    "show route summary",
    "show bgp summary",
]).await?;

for response in responses {
    println!("{}", response.result);
}

driver.close().await?;
```

### SSH Key Authentication

```rust
use std::path::PathBuf;

let driver = DriverBuilder::new("192.168.1.1")
    .username("admin")
    .private_key(PathBuf::from("~/.ssh/id_rsa"))
    .platform("linux")
    .build()
    .await?;
```

### Configuration Mode

Automatically enter and exit configuration mode:

```rust
// send_config handles privilege escalation automatically
let responses = driver.send_config(&[
    "set interfaces ge-0/0/0 description 'Uplink'",
    "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
]).await?;

// Check for errors
for response in &responses {
    if response.failed {
        eprintln!("Error: {:?}", response.failure_message);
    }
}
```

### Interactive Commands

Handle commands that require confirmation or input:

```rust
use ferrissh::{InteractiveBuilder, InteractiveEvent};

// Using the builder (fluent API)
let events = InteractiveBuilder::new()
    .send("reload")
    .expect(r"Proceed with reload\? \[confirm\]")
    .send("y")
    .expect(r"#")
    .build();

let result = driver.send_interactive(events).await?;

if result.failed {
    eprintln!("Interactive command failed!");
}

// With hidden input (passwords)
let events = InteractiveBuilder::new()
    .send("enable")
    .expect(r"[Pp]assword:")
    .send_hidden("secret_password")  // Won't appear in logs
    .expect(r"#")
    .build();
```

### Privilege Level Management

```rust
// Check current privilege
if let Some(level) = driver.current_privilege() {
    println!("Current level: {}", level);
}

// Navigate to a specific privilege level
driver.acquire_privilege("configuration").await?;

// Do configuration work...
driver.send_command("set system host-name new-router").await?;

// Return to operational mode
driver.acquire_privilege("exec").await?;
```

### Custom Timeouts

```rust
use std::time::Duration;

let driver = DriverBuilder::new("slow-device.example.com")
    .username("admin")
    .password("secret")
    .platform("juniper")
    .timeout(Duration::from_secs(60))  // 60 second timeout
    .build()
    .await?;
```

### Error Handling

```rust
let response = driver.send_command("show interfces").await?;  // Typo

if response.failed {
    println!("Command failed!");
    println!("Error: {:?}", response.failure_message);
    println!("Raw output: {}", response.raw_result);
} else {
    println!("Success: {}", response.result);
}
```

## Response Structure

```rust
pub struct Response {
    pub command: String,           // The command that was sent
    pub result: String,            // Normalized output
    pub raw_result: String,        // Raw output before normalization
    pub prompt: String,            // The prompt after command completed
    pub elapsed: Duration,         // Time taken for command
    pub failed: bool,              // Whether the command failed
    pub failure_message: Option<String>,  // Error message if failed
}
```

## Parsing Output with TextFSM

For structured data extraction from CLI output, ferrissh works well with [textfsm-rust](https://crates.io/crates/textfsm-rust) - a Rust implementation of Google's TextFSM.

```rust
use ferrissh::{Driver, DriverBuilder};
use textfsm_rust::Template;

// Define a TextFSM template for parsing `df -h` output
const DF_TEMPLATE: &str = r#"
Value Filesystem (\S+)
Value Size (\S+)
Value Used (\S+)
Value Available (\S+)
Value UsePercent (\d+)
Value MountedOn (\S+)

Start
  ^Filesystem -> Continue
  ^${Filesystem}\s+${Size}\s+${Used}\s+${Available}\s+${UsePercent}%\s+${MountedOn} -> Record
"#;

// Run command and parse output
let response = driver.send_command("df -h").await?;
let template = Template::parse_str(DF_TEMPLATE)?;
let mut parser = template.parser();
let records = parser.parse_text_to_dicts(&response.result)?;

// Access structured data
for record in records {
    if let Some(pct) = record.get("usepercent") {
        if pct.parse::<u32>().unwrap_or(0) > 80 {
            println!("Warning: {} is {}% full",
                record.get("mountedon").unwrap_or(&String::new()), pct);
        }
    }
}
```

See the [textfsm_parsing example](ferrissh/examples/textfsm_parsing.rs) for a complete demonstration with templates for Linux and Juniper commands.

## Adding Custom Platforms

```rust
use ferrissh::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};
use std::sync::Arc;

// Define privilege levels
let exec = PrivilegeLevel::new("exec", r"[\w@]+>\s*$")?;
let config = PrivilegeLevel::new("config", r"[\w@]+#\s*$")?
    .with_parent("exec")
    .with_escalate("configure")
    .with_deescalate("exit");

// Create platform
let platform = PlatformDefinition::new("my_vendor")
    .with_privilege(exec)
    .with_privilege(config)
    .with_default_privilege("exec")
    .with_failure_pattern("error:")
    .with_on_open_command("terminal length 0")
    .with_behavior(Arc::new(MyVendorBehavior));

// Use with driver
let driver = DriverBuilder::new("device.example.com")
    .custom_platform(platform)
    .username("admin")
    .password("secret")
    .build()
    .await?;
```

## Running the Examples

The `ferrissh/examples/` directory contains several examples demonstrating different features. All examples support both password and SSH key authentication.

### Common Options

| Option | Description |
|--------|-------------|
| `--host <HOST>` | Target hostname or IP (default: localhost) |
| `--port <PORT>` | SSH port (default: 22) |
| `--user <USER>` | Username (default: $USER) |
| `--password <PASS>` | Password authentication |
| `--key <PATH>` | Path to SSH private key |
| `--timeout <SECS>` | Connection timeout (default: 30) |
| `--help` | Show help message |

### basic_ls - Linux Commands

Basic example connecting to a Linux host and running commands.

```bash
# With password
cargo run --example basic_ls -- --host 192.168.1.10 --user admin --password secret

# With SSH key
cargo run --example basic_ls -- --host myserver --user admin --key ~/.ssh/id_ed25519
```

### juniper - Juniper JUNOS

Demonstrates connecting to Juniper devices and running operational/configuration commands.

```bash
# Basic operational commands
cargo run --example juniper -- --host router1 --user admin --password secret

# Include configuration mode demo
cargo run --example juniper -- --host router1 --user admin --key ~/.ssh/id_rsa --show-config
```

### interactive - Interactive Commands

Shows how to handle commands that require user input or confirmation prompts.

```bash
cargo run --example interactive -- --host localhost --user admin --password secret
```

### textfsm_parsing - Structured Output Parsing

Demonstrates using [textfsm-rust](https://crates.io/crates/textfsm-rust) to parse CLI output into structured data. Includes templates for common Linux and Juniper commands.

```bash
# Parse Linux commands (uname, df, ps)
cargo run --example textfsm_parsing -- \
    --host localhost --user admin --key ~/.ssh/id_ed25519 --platform linux

# Parse Juniper commands (show version, show interfaces terse)
cargo run --example textfsm_parsing -- \
    --host router1 --user admin --password secret --platform juniper
```

**Sample output:**
```
--- Parsed Data (TextFSM) ---
[
  {
    "filesystem": "/dev/nvme1n1p4",
    "size": "853G",
    "used": "278G",
    "available": "532G",
    "usepercent": "35",
    "mountedon": "/"
  }
]

Filesystems with >50% usage:
  /sys/firmware/efi/efivars - 52% used (64K of 128K)
```

### Debug Logging

Enable debug logging to see detailed SSH and parsing information:

```bash
RUST_LOG=debug cargo run --example basic_ls -- --host localhost --user admin --key ~/.ssh/id_rsa
```

Log levels: `error`, `warn`, `info`, `debug`, `trace`

## Dependencies

| Crate | Purpose |
|-------|---------|
| `russh` | SSH client library |
| `russh-keys` | SSH key handling |
| `tokio` | Async runtime |
| `async-trait` | Async trait support |
| `regex` | Pattern matching |
| `bytes` | Efficient byte buffers |
| `thiserror` | Error handling |
| `log` | Logging facade |
| `strip-ansi-escapes` | ANSI escape code removal |


## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [scrapli](https://github.com/carlmontanari/scrapli) - Inspiration for API design and pattern buffer optimization
- [netmiko](https://github.com/ktbyers/netmiko) - Pioneer in network device automation
- [russh](https://github.com/warp-tech/russh) - Excellent async SSH library for Rust
