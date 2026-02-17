//! Streaming command output with a sliding-window prompt detector.
//!
//! For long-running commands, `CommandStream` delivers output in real time
//! without accumulating the entire response in memory.  A `BytesMut` sliding
//! window of `search_depth` bytes is used for prompt detection — memory usage
//! is O(search_depth), not O(output_size).

use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};
use log::{debug, trace, warn};
use regex::bytes::Regex;

use super::response::Response;
use crate::channel::PtyChannel;
use crate::error::{DriverError, Result};
use crate::platform::PlatformDefinition;
use super::privilege::PrivilegeManager;

/// Real-time streaming handle for a single command's output.
///
/// Created by [`GenericDriver::send_command_stream`](super::GenericDriver::send_command_stream).
/// Call [`next_chunk`](Self::next_chunk) in a loop to receive output as it
/// arrives, then [`into_response`](Self::into_response) to finalize.
///
/// # Example
///
/// ```rust,no_run
/// # use ferrissh::{Driver, DriverBuilder, Platform};
/// # async fn example(driver: &mut ferrissh::GenericDriver) -> Result<(), ferrissh::Error> {
/// let mut stream = driver.send_command_stream("show tech-support").await?;
/// while let Some(chunk) = stream.next_chunk().await? {
///     print!("{}", String::from_utf8_lossy(&chunk));
/// }
/// let response = stream.into_response()?;
/// assert!(response.is_success());
/// # Ok(())
/// # }
/// ```
pub struct CommandStream<'a> {
    channel: &'a mut PtyChannel,
    platform: &'a PlatformDefinition,
    privilege_manager: &'a mut PrivilegeManager,
    command: String,
    prompt_pattern: Regex,
    deadline: tokio::time::Instant,
    timeout: Duration,
    finished: bool,
    start: Instant,
    window: BytesMut,
    search_depth: usize,
    failed: bool,
    failure_message: Option<String>,
    prompt: String,
}

impl<'a> CommandStream<'a> {
    /// Create a new command stream.
    ///
    /// The command should already have been sent to the channel before
    /// creating this stream.
    pub(crate) fn new(
        channel: &'a mut PtyChannel,
        platform: &'a PlatformDefinition,
        privilege_manager: &'a mut PrivilegeManager,
        command: String,
        prompt_pattern: Regex,
        timeout: Duration,
    ) -> Self {
        let search_depth = channel.search_depth();
        Self {
            channel,
            platform,
            privilege_manager,
            command,
            prompt_pattern,
            deadline: tokio::time::Instant::now() + timeout,
            timeout,
            finished: false,
            start: Instant::now(),
            window: BytesMut::with_capacity(search_depth * 2),
            search_depth,
            failed: false,
            failure_message: None,
            prompt: String::new(),
        }
    }

    /// Get the next chunk of output, or `None` when the prompt is detected.
    ///
    /// Each call blocks until the device sends data or the prompt is matched.
    /// Returns `Ok(None)` once the trailing prompt has been detected (the
    /// stream is finished).
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.finished {
            return Ok(None);
        }

        let chunk = self
            .channel
            .read_raw_chunk(self.deadline, self.timeout)
            .await?;

        // Append to sliding window
        self.window.extend_from_slice(&chunk);

        // Check for prompt match in the window (before trimming)
        if let Some(m) = self.prompt_pattern.find(&self.window) {
            self.finished = true;

            // Extract the prompt text
            let prompt_bytes = &self.window[m.start()..m.end()];
            self.prompt = String::from_utf8_lossy(prompt_bytes).trim().to_string();

            // The prompt match is within the window. We need to figure out how
            // much of the *current chunk* is pre-prompt output vs prompt text.
            //
            // window layout:  [old bytes | current chunk]
            //                             ^-- chunk_start_in_window
            //
            // The match starts at `m.start()` within the window.
            let chunk_start_in_window = self.window.len() - chunk.len();

            if m.start() >= chunk_start_in_window {
                // The prompt starts inside the current chunk.
                let pre_prompt_len = m.start() - chunk_start_in_window;
                if pre_prompt_len > 0 {
                    let pre_prompt = chunk[..pre_prompt_len].to_vec();
                    self.check_failure(&pre_prompt);
                    return Ok(Some(pre_prompt));
                }
                // Prompt starts at the very beginning of the chunk — nothing to return.
                return Ok(None);
            }
            // The prompt match started in old window bytes (spans across chunks).
            // No usable output in this chunk.
            return Ok(None);
        }

        // Trim window to keep only the last `search_depth` bytes.
        // BytesMut::advance() is an O(1) pointer bump.
        if self.window.len() > self.search_depth {
            let excess = self.window.len() - self.search_depth;
            self.window.advance(excess);
        }

        // Check this chunk for failure patterns
        self.check_failure(&chunk);

        trace!(
            "stream chunk: {} bytes, window: {} bytes",
            chunk.len(),
            self.window.len()
        );

        Ok(Some(chunk))
    }

    /// Check a chunk for failure patterns and record the first match.
    fn check_failure(&mut self, chunk: &[u8]) {
        if self.failed {
            return;
        }
        let text = String::from_utf8_lossy(chunk);
        for pattern in &self.platform.failed_when_contains {
            if text.contains(pattern) {
                self.failed = true;
                self.failure_message = Some(pattern.clone());
                debug!("stream: failure pattern matched: {:?}", pattern);
                return;
            }
        }
    }

    /// Consume the stream and build a [`Response`].
    ///
    /// The `result` and `raw_result` fields are **empty** because output was
    /// already consumed via [`next_chunk`](Self::next_chunk). The `prompt`,
    /// `elapsed`, and `is_success()` fields are populated normally.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream was not finished (prompt not yet detected).
    pub fn into_response(mut self) -> Result<Response> {
        if !self.finished {
            return Err(DriverError::CommandFailed {
                message: "stream not finished — prompt not yet detected".into(),
            }
            .into());
        }

        let elapsed = self.start.elapsed();

        // Update privilege level from the detected prompt
        if let Ok(level) = self.privilege_manager.determine_from_prompt(&self.prompt) {
            let level_name = level.name.clone();
            let _ = self.privilege_manager.set_current(&level_name);
        }

        debug!(
            "stream: completed in {:?}, prompt={:?}, success={}",
            elapsed,
            self.prompt,
            !self.failed
        );

        // Take owned values before building the response
        let command = std::mem::take(&mut self.command);
        let prompt = std::mem::take(&mut self.prompt);
        let failure_message = self.failure_message.take();

        if self.failed {
            Ok(Response::failed(
                command,
                String::new(),
                String::new(),
                prompt,
                elapsed,
                failure_message.unwrap_or_default(),
            ))
        } else {
            Ok(Response::new(
                command,
                String::new(),
                String::new(),
                prompt,
                elapsed,
            ))
        }
    }

    /// Whether the stream has finished (prompt detected).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// The command that was sent.
    pub fn command(&self) -> &str {
        &self.command
    }
}

impl Drop for CommandStream<'_> {
    fn drop(&mut self) {
        if !self.finished {
            warn!(
                "CommandStream for {:?} dropped before prompt was detected",
                self.command
            );
        }
    }
}
