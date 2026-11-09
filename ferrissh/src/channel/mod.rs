//! Channel layer for pattern matching and PTY operations.
//!
//! This module handles the interactive session management,
//! including pattern-based prompt detection and ANSI stripping.

mod buffer;
mod patterns;
mod pty;

pub use buffer::PatternBuffer;
pub use patterns::PromptMatcher;
pub(crate) use patterns::{find_trailing, tail_start};
pub use pty::{PtyChannel, PtyConfig};
