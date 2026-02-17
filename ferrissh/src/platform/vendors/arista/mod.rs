//! Arista EOS platform support.

pub mod config_session;
mod platform;

pub use config_session::AristaConfigSession;
pub use platform::platform;
