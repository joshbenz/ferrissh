//! Arrcus ArcOS platform support.

pub mod config_session;
mod platform;

pub use config_session::{config_session, ArrcusConfigSession};
pub use platform::platform;
