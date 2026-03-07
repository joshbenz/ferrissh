# ferrissh

An async SSH CLI scraper library for network device automation in Rust.

[![Crates.io](https://img.shields.io/crates/v/ferrissh.svg)](https://crates.io/crates/ferrissh)
[![Documentation](https://docs.rs/ferrissh/badge.svg)](https://docs.rs/ferrissh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Warning:** This library is EXTREMELY experimental and under active development. The API is subject to change without notice. Use in production at your own risk.

Ferrissh provides a high-level async API for interacting with network devices over SSH, heavily inspired by Python's [scrapli](https://github.com/carlmontanari/scrapli) and [netmiko](https://github.com/ktbyers/netmiko) libraries.

## Features

- **Async/Await** - Built on Tokio and russh for efficient async SSH connections
- **Multi-Vendor Support** - Linux, Juniper JUNOS, Arista EOS, Nokia SR OS, Arrcus ArcOS
- **Privilege Management** - Automatic navigation between privilege levels
- **Config Sessions** - RAII-guarded config sessions with commit, abort, diff, validate, and confirmed commit
- **ConfD Support** - Generic ConfD config session shared by both C-style and J-style CLI vendors
- **Interactive Commands** - Handle prompts requiring user input (confirmations, passwords)
- **Configuration Mode** - Automatic privilege escalation for config commands
- **Credential Protection** - Passwords and passphrases wrapped in `SecretString` (via `secrecy`), redacted from Debug output
- **Multi-Channel** - Multiple independent PTY shells on a single SSH connection via `Session` + `Channel`
- **Streaming Output** - `send_command_stream()` yields normalized output chunks as they arrive, with `futures::Stream` adapter. Ideal for large outputs (BGP tables, full configs)
- **Zero-Copy Responses** - `Payload` type backed by reference-counted `Bytes` with in-place buffer normalization. Cheap clones.
- **Pattern Matching** - Efficient tail-search buffer matching (scrapli-style optimization)
- **Data-Driven Platforms** - Platforms are pure data (prompts, privilege graphs, failure patterns) with optional extension traits for configuration sessions

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ferrissh = "0.4"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use ferrissh::{Driver, DriverBuilder, Platform};

#[tokio::main]
async fn main() -> Result<(), ferrissh::Error> {
    // Connect to a Linux host
    let mut driver = DriverBuilder::new("192.168.1.1")
        .username("admin")
        .password("secret")
        .platform(Platform::Linux)
        .build()?;

    driver.open().await?;

    // Send a command
    let response = driver.send_command("uname -a").await?;
    println!("{}", response.result);

    driver.close().await?;
    Ok(())
}
```

## Built in Platforms

| Platform | Enum Variant | Privilege Levels | Config Session |
|----------|-------------|------------------|----------------|
| Linux/Unix | `Platform::Linux` | user (`$`), root (`#`) | - |
| Juniper JUNOS | `Platform::JuniperJunos` | exec (`>`), configuration (`#`), shell (`%`) | `JuniperConfigSession` |
| Arista EOS | `Platform::AristaEos` | exec (`>`), privileged (`#`), configuration (`(config)#`) | `AristaConfigSession` |
| Nokia SR OS | `Platform::NokiaSros` | exec (`#`), configuration (`(ex)[]#`), MD-CLI and Classic CLI | `NokiaSrosConfigSession` |
| Arrcus ArcOS | `Platform::ArrcusArcOs` | exec (`#`), configuration (`(config)#`), ConfD C-style CLI | `ConfDConfigSession` |

### Config Session Management

Config sessions are **RAII-guarded transactions** that hold `&mut Channel`, preventing concurrent use at compile time. The `commit()` and `abort()` methods consume the session by value, enforcing single-use.

Ferrissh uses **extension traits** to express what each vendor's config session supports:

| Trait | Description | Vendors |
|-------|-------------|---------|
| `ConfigSession` | Core trait: `send_command`, `commit`, `abort`, `detach` | All |
| `Diffable` | View uncommitted changes (`diff()`) | Juniper, Arista, Nokia, ConfD |
| `Validatable` | Validate config before commit (`validate()`) | Juniper, Arista, Nokia, ConfD |
| `ConfirmableCommit` | Auto-rollback commit (`commit_confirmed(timeout)`) | Juniper, Arista, ConfD |
| `NamedSession` | Named/isolated config sessions (`session_name()`) | Arista |

Each vendor implements only the traits it supports — the type system prevents calling features the vendor doesn't have.

### ConfD Support

Ferrissh includes a generic `ConfDConfigSession` that works with any vendor using Tail-f/Cisco ConfD as their management framework. The config session commands (`commit`, `revert`, `validate`, `compare running-config`, `commit confirmed`) are identical for both C-style and J-style ConfD CLIs — only the prompts and navigation commands differ, which are defined in each vendor's platform definition.

Arrcus ArcOS uses this generic ConfD session directly. Future ConfD-based vendors can reuse it with just a platform definition — no new config session code needed.

## Usage Examples

### Basic Commands

```rust
use ferrissh::{Driver, DriverBuilder, Platform};

let mut driver = DriverBuilder::new("router.example.com")
    .username("admin")
    .password("secret")
    .platform(Platform::JuniperJunos)
    .build()?;

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

### Streaming Output

Process large outputs incrementally instead of buffering the entire response:

```rust
use ferrissh::Driver;

// Stream a large routing table
let mut stream = driver.send_command_stream("show route").await?;
while let Some(chunk) = stream.next_chunk().await? {
    print!("{}", String::from_utf8_lossy(&chunk));
}

// Completion metadata (prompt, elapsed time, failure patterns)
let completion = stream.completion().unwrap();
println!("Completed in {:?}", completion.elapsed);
```

Or use the `futures::Stream` adapter with `StreamExt`:

```rust
use futures_util::StreamExt;

let stream = driver.send_command_stream("show running-config").await?;
let mut pinned = Box::pin(stream.into_stream());
while let Some(chunk) = pinned.next().await {
    let bytes = chunk?;
    process_chunk(&bytes);
}
```

### SSH Key Authentication

```rust
use std::path::PathBuf;

let driver = DriverBuilder::new("192.168.1.1")
    .username("admin")
    .private_key(PathBuf::from("~/.ssh/id_rsa"))
    .platform(Platform::Linux)
    .build()?;
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
    if !response.is_success() {
        eprintln!("Error: {:?}", response.failure_message);
    }
}
```

### Config Sessions (RAII-guarded)

Config sessions provide RAII-guarded access to device configuration with
commit, abort, diff, validate, and confirmed commit support:

```rust
use ferrissh::{ConfigSession, Diffable, Validatable, Driver};
use ferrissh::platform::vendors::juniper::JuniperConfigSession;

let mut driver = connect_juniper().await;

// Create a config session (enters config mode)
let mut session = JuniperConfigSession::new(driver.channel().unwrap()).await?;

// Make changes
session.send_command("set interfaces lo0 description 'test'").await?;

// Review pending changes
let diff = session.diff().await?;
println!("Changes:\n{}", diff);

// Validate before committing
let result = session.validate().await?;
if result.valid {
    session.commit().await?;  // Commits and exits config mode
} else {
    session.abort().await?;   // Discards changes and exits config mode
}
```

### Multi-Channel (Multiple Shells on One Connection)

Open multiple independent PTY shells on a single authenticated SSH connection:

```rust
use ferrissh::{Driver, DriverBuilder, Platform};

let mut driver = DriverBuilder::new("192.168.1.1")
    .username("admin")
    .password("secret")
    .platform(Platform::Linux)
    .build()?;

driver.open().await?;

// Open a second channel on the same SSH connection
let mut ch2 = driver.open_channel().await?;

// Each channel has its own shell, privilege state, and prompt detection
let (r1, r2) = tokio::try_join!(
    driver.send_command("hostname"),
    ch2.send_command("whoami"),
)?;

ch2.close().await?;
driver.close().await?;
```

For full control, use `SessionBuilder` to create a session and open channels directly:

```rust
use ferrissh::{SessionBuilder, Platform};

let session = SessionBuilder::new("192.168.1.1")
    .username("admin")
    .password("secret")
    .platform(Platform::Linux)
    .connect().await?;

let mut ch1 = session.open_channel().await?;
let mut ch2 = session.open_channel().await?;

let (r1, r2) = tokio::try_join!(
    ch1.send_command("uname -a"),
    ch2.send_command("uptime"),
)?;

ch1.close().await?;
ch2.close().await?;
session.close().await?;
```

### Interactive Commands

Handle commands that require confirmation or input:

```rust
use ferrissh::{InteractiveBuilder, InteractiveEvent};

// Using the builder (fluent API)
let events = InteractiveBuilder::new()
    .send("reload")
    .expect(r"Proceed with reload\? \[confirm\]")?
    .send("y")
    .expect(r"#")?
    .build();

let result = driver.send_interactive(&events).await?;

if !result.is_success() {
    eprintln!("Interactive command failed!");
}

// With hidden input (passwords)
let events = InteractiveBuilder::new()
    .send("enable")
    .expect(r"[Pp]assword:")?
    .send_hidden("secret_password")  // Won't appear in logs
    .expect(r"#")?
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


## Parsing Output with TextFSM

For structured data extraction from CLI output, ferrissh works well with [textfsm-rust](https://crates.io/crates/textfsm-rust) - a Rust implementation of Google's TextFSM.

### As dictionaries

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

### Into typed structs (serde)

With the `serde` feature enabled, parse directly into strongly-typed Rust structs:

```toml
[dependencies]
textfsm-rust = { version = "0.3", features = ["serde"] }
```

```rust
use serde::Deserialize;
use textfsm_rust::Template;

#[derive(Debug, Deserialize)]
struct DiskUsage {
    filesystem: String,
    size: String,
    used: String,
    available: String,
    usepercent: String,
    mountedon: String,
}

let template = Template::parse_str(DF_TEMPLATE)?;
let mut parser = template.parser();
let disks: Vec<DiskUsage> = parser.parse_text_into(&response.result)?;

for disk in &disks {
    println!("{} is {}% full", disk.mountedon, disk.usepercent);
}
```

See the [textfsm_parsing example](ferrissh/examples/textfsm_parsing.rs) for a complete demonstration with templates for Linux and Juniper commands.

### Response Payload (Zero-Copy)

Command responses use the `Payload` type — a zero-copy wrapper around reference-counted `Bytes`. It implements `Deref<Target = str>`, so it works anywhere a `&str` is expected:

```rust
let response = driver.send_command("show version").await?;

// All &str methods work via deref coercion
println!("{}", response.result);              // Display
assert!(response.result.contains("JUNOS"));   // str::contains
for line in response.result.lines() {         // str::lines
    println!("  {}", line);
}
let trimmed: &str = response.result.trim();   // str::trim

// Cloning is cheap (reference count increment, no data copy)
let cloned = response.result.clone();

// Convert to owned String when needed
let owned: String = response.result.into_string();
```

The in-place normalization pipeline (linefeed normalization, echo stripping, prompt removal) operates directly on the buffer with SIMD-accelerated byte search via `memchr`, avoiding intermediate `String` allocations.

### Adding a Custom Platform

```rust
use ferrissh::platform::{PlatformDefinition, PrivilegeLevel, VendorBehavior};
use std::sync::Arc;

// Define privilege levels with prompt patterns
let exec = PrivilegeLevel::new("exec", r"[\w@]+>\s*$")?;
let config = PrivilegeLevel::new("config", r"[\w@]+#\s*$")?
    .with_parent("exec")
    .with_escalate("configure")
    .with_deescalate("exit");

// Create platform definition — pure data, no driver code needed
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
    .build()?;
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

### nokia_sros - Nokia SR OS

Demonstrates connecting to Nokia SR OS devices with auto-detection of MD-CLI vs Classic CLI.

```bash
cargo run --example nokia_sros -- --host pe1 --user admin --password admin
```

### arista_eos - Arista EOS

Demonstrates connecting to Arista EOS switches and running operational commands.

```bash
cargo run --example arista_eos -- --host switch1 --user admin --password secret
```

### config_session - Config Sessions

Demonstrates RAII-guarded config sessions with diff, validate, commit, and abort.

```bash
# Juniper config session
cargo run --example config_session -- --host router1 --user admin --password secret --platform juniper

# Nokia SR OS config session
cargo run --example config_session -- --host pe1 --user admin --password admin --platform nokia
```

### multi_channel - Multiple Shells on One Connection

Demonstrates opening multiple PTY channels on a single SSH connection, both from a driver and from a session directly.

```bash
SSH_HOST=myserver SSH_USER=admin SSH_PASS=secret cargo run --example multi_channel
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

## Security

- **Credential protection** - Passwords and key passphrases are stored as `SecretString` (from the `secrecy` crate), which zeroizes memory on drop. `Debug` formatting on `AuthMethod` and `SshConfig` redacts all secrets.
- **Input validation** - Arista config session names are validated against injection (alphanumeric, hyphens, underscores only, max 63 chars). Builder inputs (host, port) are validated before connection.
- **RAII safety** - Config session guards only mark themselves as consumed after all operations succeed, ensuring `Drop` warnings fire on partial failures.

## Planned Features

### Platform Support

- [x] Juniper JUNOS
- [x] Nokia SR OS
- [x] Arista EOS
- [x] Arrcus ArcOS

### Config Sessions

- [x] RAII-guarded config sessions (commit/abort/detach)
- [x] Diff support
- [x] Validate support
- [x] Confirmed commit support
- [x] Generic ConfD config session (shared by C-style and J-style vendors)

### Connection Management

- [x] SSH keepalive configuration
- [x] Connection health checks (`is_alive()`)
- [x] Multi-channel support (multiple PTY shells per connection)

### Macros & Compile-Time Safety

- [ ] Proc macro for defining custom platforms declaratively
- [ ] Compile-time privilege graph validation
- [ ] Compile-time regex verification for prompt patterns

### Transport

- [ ] Feature-gated `async_ssh2_lite` backend

### API

- [x] Streaming output API (`send_command_stream()`, `futures::Stream` adapter)

## Dependencies

| Crate | Purpose |
|-------|---------|
| `russh` | SSH client library |
| `ssh-key` | SSH key handling |
| `tokio` | Async runtime |
| `bytes` | Zero-copy buffer management (`BytesMut`/`Bytes`) |
| `memchr` | SIMD-accelerated byte search for in-place normalization |
| `regex` | Pattern matching |
| `thiserror` | Error handling |
| `log` | Logging facade |
| `secrecy` | Credential protection (`SecretString` with zeroize) |
| `serde` | Serialization/deserialization |
| `indexmap` | Deterministic-order maps |
| `vte` | ANSI escape sequence stripping (reusable parser, zero-alloc) |
| `futures-core` / `futures-util` | `Stream` trait and adapters for streaming API |


## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Acknowledgments

The architecture and design of ferrissh is heavily influenced by [scrapli](https://github.com/carlmontanari/scrapli) — the data-driven platform definitions, privilege level graph, and pattern buffer optimization are all concepts from scrapli. If you're working in Python, check it out.

- [scrapli](https://github.com/carlmontanari/scrapli) - The primary inspiration for ferrissh's architecture
- [netmiko](https://github.com/ktbyers/netmiko) - Pioneer in network device automation
- [russh](https://github.com/warp-tech/russh) - Async SSH library for Rust
