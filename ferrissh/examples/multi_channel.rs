//! Multi-channel example: multiple PTY shells on a single SSH connection.
//!
//! Demonstrates two approaches:
//! 1. Starting from a `GenericDriver` and opening additional channels
//! 2. Starting from a `Session` directly for full control

use ferrissh::{Driver, DriverBuilder, Platform, SessionBuilder};

#[tokio::main]
async fn main() -> Result<(), ferrissh::Error> {
    env_logger::init();

    let host = std::env::var("SSH_HOST").unwrap_or_else(|_| "localhost".into());
    let user = std::env::var("SSH_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("SSH_PASS").unwrap_or_else(|_| "admin".into());

    // === Approach 1: Start from a driver, open additional channels ===

    println!("=== Approach 1: Driver + extra channel ===\n");

    let mut driver = DriverBuilder::new(&host)
        .username(&user)
        .password(&pass)
        .platform(Platform::Linux)
        .danger_disable_host_key_verification()
        .build()?;

    driver.open().await?;

    // Open a second channel on the same SSH connection
    let mut ch2 = driver.open_channel().await?;

    // Send different commands on each channel concurrently
    let r1 = driver.send_command("hostname").await?;
    let r2 = ch2.send_command("whoami").await?;

    println!("Channel 1 (hostname): {}", r1.result);
    println!("Channel 2 (whoami):   {}", r2.result);

    ch2.close().await?;
    driver.close().await?;

    // === Approach 2: Start from a session directly ===

    println!("\n=== Approach 2: Session + channels ===\n");

    let session = SessionBuilder::new(&host)
        .username(&user)
        .password(&pass)
        .platform(Platform::Linux)
        .danger_disable_host_key_verification()
        .connect()
        .await?;

    let mut ch1 = session.open_channel().await?;
    let mut ch2 = session.open_channel().await?;

    let r1 = ch1.send_command("uname -a").await?;
    let r2 = ch2.send_command("uptime").await?;

    println!("Channel 1 (uname):  {}", r1.result);
    println!("Channel 2 (uptime): {}", r2.result);

    ch1.close().await?;
    ch2.close().await?;
    session.close().await?;

    println!("\nDone!");
    Ok(())
}
