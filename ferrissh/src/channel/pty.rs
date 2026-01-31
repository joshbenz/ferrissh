//! PTY channel abstraction for interactive sessions.

use std::time::Duration;

use regex::bytes::Regex;

use super::buffer::PatternBuffer;

/// Configuration for PTY channel behavior.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Default timeout for operations.
    pub timeout: Duration,

    /// Search depth for pattern matching.
    pub search_depth: usize,

    /// Terminal width.
    pub terminal_width: u32,

    /// Terminal height.
    pub terminal_height: u32,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            search_depth: 1000,
            terminal_width: 511,
            terminal_height: 24,
        }
    }
}

/// High-level PTY channel for interactive device sessions.
///
/// This wraps the lower-level transport and provides pattern-based
/// read operations with timeout handling.
pub struct PtyChannel {
    /// Configuration for this channel.
    config: PtyConfig,

    /// Pattern buffer for accumulating output.
    buffer: PatternBuffer,

    /// Whether the channel is open.
    is_open: bool,
}

impl PtyChannel {
    /// Create a new PTY channel with the given configuration.
    pub fn new(config: PtyConfig) -> Self {
        Self {
            buffer: PatternBuffer::new(config.search_depth),
            config,
            is_open: false,
        }
    }

    /// Create a PTY channel with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PtyConfig::default())
    }

    /// Mark the channel as open.
    pub fn set_open(&mut self, open: bool) {
        self.is_open = open;
    }

    /// Check if the channel is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Get a mutable reference to the buffer.
    pub fn buffer_mut(&mut self) -> &mut PatternBuffer {
        &mut self.buffer
    }

    /// Get a reference to the buffer.
    pub fn buffer(&self) -> &PatternBuffer {
        &self.buffer
    }

    /// Get the default timeout.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Set the default timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.config.timeout = timeout;
    }

    /// Get the configuration.
    pub fn config(&self) -> &PtyConfig {
        &self.config
    }

    /// Clear the internal buffer.
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }

    /// Take the buffer contents.
    pub fn take_buffer(&mut self) -> Vec<u8> {
        self.buffer.take()
    }

    /// Extend the buffer with data.
    pub fn extend_buffer(&mut self, data: &[u8]) {
        self.buffer.extend(data);
    }

    /// Check if a pattern is found in the buffer tail.
    pub fn pattern_found(&self, pattern: &Regex) -> bool {
        self.buffer.tail_contains(pattern)
    }
}

/// Result of a read operation.
#[derive(Debug)]
pub struct ReadResult {
    /// The data that was read.
    pub data: Vec<u8>,

    /// Whether the pattern was matched.
    pub pattern_matched: bool,
}

impl ReadResult {
    /// Get the data as a string (lossy UTF-8).
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }
}
