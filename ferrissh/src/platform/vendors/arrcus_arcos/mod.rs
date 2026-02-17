//! Arrcus ArcOS platform support.

pub mod config_session;
mod platform;

pub use config_session::{ArrcusConfigSession, config_session};
pub use platform::platform;
