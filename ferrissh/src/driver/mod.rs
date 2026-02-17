//! High-level driver for device interaction.
//!
//! The driver layer provides the main API for sending commands
//! and managing privilege levels on network devices.

mod builder;
pub mod config_session;
mod generic;
mod interactive;
mod privilege;
pub(crate) mod response;
mod stream;

pub use builder::DriverBuilder;
pub use config_session::{
    ConfigSession, ConfirmableCommit, Diffable, GenericConfigSession, NamedSession, Validatable,
    ValidationResult,
};
pub use generic::GenericDriver;
pub use interactive::{InteractiveBuilder, InteractiveEvent, InteractiveResult, InteractiveStep};
pub use privilege::PrivilegeManager;
pub use response::Response;
pub use stream::CommandStream;

use std::future::Future;

use crate::error::Result;

/// Trait for device drivers.
pub trait Driver: Send + Sync {
    /// Open the connection to the device.
    fn open(&mut self) -> impl Future<Output = Result<()>> + Send;

    /// Close the connection.
    fn close(&mut self) -> impl Future<Output = Result<()>> + Send;

    /// Send a command and wait for the prompt.
    fn send_command(&mut self, command: &str) -> impl Future<Output = Result<Response>> + Send;

    /// Send multiple commands sequentially.
    fn send_commands(
        &mut self,
        commands: &[&str],
    ) -> impl Future<Output = Result<Vec<Response>>> + Send {
        async move {
            let mut responses = Vec::with_capacity(commands.len());
            for cmd in commands {
                responses.push(self.send_command(cmd).await?);
            }
            Ok(responses)
        }
    }

    /// Send an interactive command sequence.
    ///
    /// This handles commands that require additional input or confirmation,
    /// such as `reload`, `copy`, or `delete` commands.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use ferrissh::driver::{Driver, InteractiveEvent};
    ///
    /// # async fn example(driver: &mut impl Driver) -> Result<(), ferrissh::Error> {
    /// // Handle a reload command
    /// let events = vec![
    ///     InteractiveEvent::new("reload", r"Proceed.*\[confirm\]").unwrap(),
    ///     InteractiveEvent::new("y", r"#").unwrap(),
    /// ];
    /// let result = driver.send_interactive(&events).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn send_interactive(
        &mut self,
        events: &[InteractiveEvent],
    ) -> impl Future<Output = Result<InteractiveResult>> + Send;

    /// Send commands in configuration mode.
    ///
    /// This method:
    /// 1. Acquires the configuration privilege level
    /// 2. Sends all the provided commands
    /// 3. Returns to the previous privilege level
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use ferrissh::driver::Driver;
    ///
    /// # async fn example(driver: &mut impl Driver) -> Result<(), ferrissh::Error> {
    /// let responses = driver.send_config(&[
    ///     "interface GigabitEthernet0/1",
    ///     "description Uplink to Core",
    ///     "no shutdown",
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn send_config(
        &mut self,
        commands: &[&str],
    ) -> impl Future<Output = Result<Vec<Response>>> + Send;

    /// Acquire a specific privilege level.
    fn acquire_privilege(&mut self, privilege: &str) -> impl Future<Output = Result<()>> + Send;

    /// Check if the driver is connected.
    fn is_open(&self) -> bool;

    /// Check if the underlying SSH session is still alive.
    ///
    /// Returns `true` if the connection is open and the SSH session's
    /// background task is still running. Returns `false` if:
    /// - The driver is not connected (`open()` not called)
    /// - The SSH keepalive timeout was exceeded (peer unresponsive)
    /// - The server sent a disconnect
    /// - An I/O error killed the session
    ///
    /// Use this to check connection health before sending commands,
    /// especially after idle periods.
    ///
    /// ```rust,no_run
    /// # use ferrissh::driver::Driver;
    /// # async fn example(driver: &mut impl Driver) -> Result<(), ferrissh::Error> {
    /// if !driver.is_alive() {
    ///     println!("Connection lost, reconnecting...");
    ///     driver.close().await.ok();
    ///     driver.open().await?;
    /// }
    /// let response = driver.send_command("show version").await?;
    /// # Ok(())
    /// # }
    /// ```
    fn is_alive(&self) -> bool;

    /// Get the current privilege level name.
    fn current_privilege(&self) -> Option<&str>;
}
