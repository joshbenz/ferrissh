//! SSH transport layer wrapping russh.
//!
//! This module provides the low-level SSH connection management,
//! handling connection setup, authentication, and channel creation.

pub mod config;
mod ssh;

pub use config::{AuthMethod, HostKeyVerification, SshConfig};
pub use ssh::SshTransport;
