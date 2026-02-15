//! Error types for ferrissh.

use std::io;
use thiserror::Error;

/// Main error type for ferrissh operations.
#[derive(Error, Debug)]
pub enum Error {
    /// SSH transport-level errors
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// Channel operation errors
    #[error("Channel error: {0}")]
    Channel(#[from] ChannelError),

    /// Driver-level errors
    #[error("Driver error: {0}")]
    Driver(#[from] DriverError),

    /// Platform/vendor errors
    #[error("Platform error: {0}")]
    Platform(#[from] PlatformError),
}

/// Transport layer errors (SSH connection, authentication).
#[derive(Error, Debug)]
pub enum TransportError {
    /// Failed to connect to host
    #[error("Connection failed to {host}:{port}: {source}")]
    ConnectionFailed {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },

    /// SSH handshake or protocol error
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    /// Authentication failed
    #[error("Authentication failed for user '{user}'")]
    AuthenticationFailed { user: String },

    /// SSH key error
    #[error("SSH key error: {0}")]
    Key(String),

    /// Connection was closed unexpectedly
    #[error("Connection disconnected")]
    Disconnected,

    /// Operation timed out
    #[error("Operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Host key not found in known_hosts (strict mode)
    #[error("Host key for {host}:{port} not found in known_hosts")]
    HostKeyUnknown { host: String, port: u16 },

    /// Host key changed from what's recorded in known_hosts
    #[error(
        "Host key for {host}:{port} has CHANGED (known_hosts line {line}). This could indicate a man-in-the-middle attack."
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        line: usize,
    },

    /// Error accessing or parsing known_hosts file
    #[error("Known hosts error: {0}")]
    KnownHosts(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Channel layer errors (pattern matching, PTY operations).
#[derive(Error, Debug)]
pub enum ChannelError {
    /// Failed to open PTY channel
    #[error("Failed to open PTY channel")]
    PtyOpenFailed,

    /// Failed to request shell
    #[error("Failed to request shell")]
    ShellRequestFailed,

    /// Pattern matching timed out
    #[error("Pattern not found within {0:?}")]
    PatternTimeout(std::time::Duration),

    /// Channel closed unexpectedly
    #[error("Channel closed")]
    Closed,

    /// SSH protocol error on the channel
    #[error("Channel SSH error: {0}")]
    Ssh(russh::Error),

    /// Invalid regex pattern
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(#[from] regex::Error),
}

/// Driver layer errors (command execution, privilege escalation).
#[derive(Error, Debug)]
pub enum DriverError {
    /// Driver not connected
    #[error("Driver not connected - call open() first")]
    NotConnected,

    /// Driver already connected
    #[error("Driver already connected")]
    AlreadyConnected,

    /// Command execution failed
    #[error("Command failed: {message}")]
    CommandFailed { message: String },

    /// Failed to acquire target privilege level
    #[error("Failed to acquire privilege level '{target}'")]
    PrivilegeAcquisitionFailed { target: String },

    /// Invalid configuration in the driver builder
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    /// Unknown privilege level detected
    #[error("Unknown privilege level from prompt: '{prompt}'")]
    UnknownPrivilege { prompt: String },

    /// No path found between privilege levels
    #[error("No path from privilege '{from}' to '{to}'")]
    NoPrivilegePath { from: String, to: String },
}

/// Platform/vendor definition errors.
#[derive(Error, Debug)]
pub enum PlatformError {
    /// Invalid platform definition
    #[error("Invalid platform definition: {message}")]
    InvalidDefinition { message: String },
}

/// Result type alias using ferrissh's Error.
pub type Result<T> = std::result::Result<T, Error>;
