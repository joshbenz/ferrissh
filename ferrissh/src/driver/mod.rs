//! High-level driver for device interaction.
//!
//! The driver layer provides the main API for sending commands
//! and managing privilege levels on network devices.

mod builder;
mod generic;
mod privilege;
mod response;

pub use builder::DriverBuilder;
pub use generic::GenericDriver;
pub use privilege::PrivilegeManager;
pub use response::Response;

use async_trait::async_trait;

use crate::error::Result;

/// Trait for device drivers.
#[async_trait]
pub trait Driver: Send + Sync {
    /// Open the connection to the device.
    async fn open(&mut self) -> Result<()>;

    /// Close the connection.
    async fn close(&mut self) -> Result<()>;

    /// Send a command and wait for the prompt.
    async fn send_command(&mut self, command: &str) -> Result<Response>;

    /// Send multiple commands sequentially.
    async fn send_commands(&mut self, commands: &[&str]) -> Result<Vec<Response>>;

    /// Acquire a specific privilege level.
    async fn acquire_privilege(&mut self, privilege: &str) -> Result<()>;

    /// Check if the driver is connected.
    fn is_open(&self) -> bool;
}
