//! High-level driver for device interaction.
//!
//! The driver layer provides the main API for sending commands
//! and managing privilege levels on network devices.

mod builder;
pub mod channel;
pub mod config_session;
mod generic;
mod interactive;
pub mod payload;
mod privilege;
pub(crate) mod response;
pub mod stream;

pub use builder::DriverBuilder;
pub use channel::{Channel, ChannelState};
pub use config_session::{
    ConfigSession, ConfirmableCommit, Diffable, GenericConfigSession, NamedSession, Validatable,
    ValidationResult,
};
pub use generic::GenericDriver;
// SessionState is defined in this module and re-exported here
pub use interactive::{InteractiveBuilder, InteractiveEvent, InteractiveResult, InteractiveStep};
pub use payload::Payload;
pub use privilege::{PrivilegeLevelsBase, PrivilegeManager};
pub use response::Response;
pub use stream::{CommandStream, StreamCompletion};

use std::future::Future;

use crate::error::Result;

/// The state of a driver's SSH session.
///
/// ```text
/// Disconnected ──open()──> Ready
/// Ready ──close()──> Closing ──cleanup──> Disconnected
/// Ready ──connection error──> Dead ──close()──> Disconnected
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Not connected.
    Disconnected,
    /// Connected and ready for commands.
    Ready,
    /// Graceful close in progress.
    Closing,
    /// Connection died (transport error or server disconnect).
    /// Call `close()` to transition back to `Disconnected`.
    Dead,
}

/// Trait for device drivers.
pub trait Driver: Send + Sync {
    /// Open the connection to the device.
    fn open(&mut self) -> impl Future<Output = Result<()>> + Send;

    /// Close the connection.
    fn close(&mut self) -> impl Future<Output = Result<()>> + Send;

    /// Send a command and wait for the prompt.
    fn send_command(&mut self, command: &str) -> impl Future<Output = Result<Response>> + Send;

    /// Send a command and return a streaming iterator over output chunks.
    ///
    /// Unlike [`send_command()`](Self::send_command), this returns a
    /// [`CommandStream`] that yields normalized output incrementally.
    fn send_command_stream<'a>(
        &'a mut self,
        command: &str,
    ) -> impl Future<Output = Result<CommandStream<'a>>> + Send;

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

    /// Get the current session state.
    fn state(&self) -> SessionState;
}
