//! PTY channel abstraction for interactive sessions.

use std::time::Duration;

use bytes::BytesMut;
use regex::bytes::Regex;
use russh::Channel;
use russh::ChannelMsg;
use russh::client::Msg;

use log::trace;

use super::buffer::PatternBuffer;
use crate::error::{ChannelError, Result};

/// Configuration for PTY channel behavior.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Search depth for pattern matching.
    pub search_depth: usize,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self { search_depth: 1000 }
    }
}

/// High-level PTY channel for interactive device sessions.
///
/// This wraps a russh channel and provides pattern-based
/// read operations with timeout handling.
pub struct PtyChannel {
    /// The underlying russh channel.
    channel: Channel<Msg>,

    /// Pattern buffer for accumulating output.
    buffer: PatternBuffer,
}

impl PtyChannel {
    /// Create a new PTY channel wrapping a russh channel.
    pub fn new(channel: Channel<Msg>, config: PtyConfig) -> Self {
        Self {
            channel,
            buffer: PatternBuffer::new(config.search_depth),
        }
    }

    /// Send data to the channel.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.channel.data(data).await.map_err(ChannelError::Ssh)?;
        Ok(())
    }

    /// Send a command (with newline).
    pub async fn send(&mut self, command: &str) -> Result<()> {
        let mut data = Vec::with_capacity(command.len() + 1);
        data.extend_from_slice(command.as_bytes());
        data.push(b'\n');
        trace!("sending {} bytes", data.len());
        self.write(&data).await
    }

    /// Read until pattern matches (with timeout).
    pub async fn read_until_pattern(
        &mut self,
        pattern: &Regex,
        timeout: Duration,
    ) -> Result<BytesMut> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(ChannelError::PatternTimeout(timeout).into());
                }
                msg = self.channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            self.buffer.extend(&data);
                            if self.buffer.search_tail(pattern).is_some() {
                                trace!("prompt pattern matched after {} bytes", self.buffer.as_slice().len());
                                return Ok(self.buffer.take());
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            // stderr - also add to buffer
                            self.buffer.extend(&data);
                        }
                        Some(ChannelMsg::Eof) => {
                            return Err(ChannelError::Eof.into());
                        }
                        None => {
                            return Err(ChannelError::Disconnected.into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Read until any of the given patterns matches (with timeout).
    ///
    /// Like [`PtyChannel::read_until_pattern`] but checks multiple individual patterns
    /// instead of one combined regex, avoiding combined-NFA memory overhead.
    pub async fn read_until_any_pattern(
        &mut self,
        patterns: &[Regex],
        timeout: Duration,
    ) -> Result<BytesMut> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(ChannelError::PatternTimeout(timeout).into());
                }
                msg = self.channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            self.buffer.extend(&data);
                            if self.buffer.search_tail_any(patterns).is_some() {
                                trace!("prompt pattern matched after {} bytes", self.buffer.as_slice().len());
                                return Ok(self.buffer.take());
                            }
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            // stderr - also add to buffer
                            self.buffer.extend(&data);
                        }
                        Some(ChannelMsg::Eof) => {
                            return Err(ChannelError::Eof.into());
                        }
                        None => {
                            return Err(ChannelError::Disconnected.into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Read one batch of SSH data without waiting for a prompt pattern.
    ///
    /// Returns ANSI-stripped data after receiving the first `Data` message.
    /// Accumulates `ExtendedData` (stderr) but keeps waiting for stdout.
    /// This is the low-level primitive used by [`CommandStream`](crate::driver::stream::CommandStream).
    pub async fn read_chunk(&mut self, timeout: Duration) -> Result<BytesMut> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(ChannelError::PatternTimeout(timeout).into());
                }
                msg = self.channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            self.buffer.extend(&data);
                            return Ok(self.buffer.take());
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            self.buffer.extend(&data);
                        }
                        Some(ChannelMsg::Eof) => {
                            return Err(ChannelError::Eof.into());
                        }
                        None => {
                            return Err(ChannelError::Disconnected.into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Get current buffer contents without clearing.
    pub fn peek_buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    /// Clear the buffer.
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
    }

    /// Take the buffer contents.
    pub fn take_buffer(&mut self) -> BytesMut {
        self.buffer.take()
    }

    /// Get the search depth setting.
    pub fn search_depth(&self) -> usize {
        self.buffer.search_depth()
    }
}
