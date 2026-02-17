//! Juniper JUNOS platform support.

pub mod config_session;
mod platform;

pub use config_session::JuniperConfigSession;
pub use platform::{platform, JuniperBehavior, PLATFORM_NAME};
