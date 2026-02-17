//! Nokia SR OS platform support.

pub mod config_session;
mod platform;

pub use config_session::NokiaConfigSession;
pub use platform::{NokiaSrosBehavior, PLATFORM_NAME, platform};
