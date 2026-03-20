//! Streaming command execution for incremental output processing.
//!
//! [`CommandStream`] yields normalized output chunks as they arrive from the
//! device, while still performing prompt detection and vendor post-processing.
//! This is useful for large outputs (full BGP tables, `show running-config`)
//! where callers want to process data incrementally rather than waiting for
//! the complete response.
//!
//! # Usage
//!
//! ```rust,no_run
//! # use ferrissh::{DriverBuilder, Driver, Platform};
//! # async fn example(driver: &mut impl Driver) -> Result<(), ferrissh::Error> {
//! let mut stream = driver.send_command_stream("show route").await?;
//! while let Some(chunk) = stream.next_chunk().await? {
//!     print!("{}", String::from_utf8_lossy(&chunk));
//! }
//! let completion = stream.completion().unwrap();
//! println!("Prompt: {}", completion.prompt);
//! # Ok(())
//! # }
//! ```

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use regex::bytes::Regex;

use super::channel::Channel;
use crate::error::Result;
use crate::platform::StreamProcessor;

/// Metadata available after a [`CommandStream`] finishes (prompt detected).
#[derive(Debug, Clone)]
pub struct StreamCompletion {
    /// The prompt string that terminated the stream.
    pub prompt: String,
    /// Total wall-clock time from command send to prompt detection.
    pub elapsed: Duration,
    /// First failure pattern detected during streaming, if any.
    pub failure_pattern: Option<String>,
}

/// Configuration snapshot used to construct a [`CommandStream`].
pub(crate) struct StreamConfig {
    pub prompt_patterns: Vec<Regex>,
    pub search_depth: usize,
    pub timeout: Duration,
    pub normalize: bool,
    pub processor: Option<Box<dyn StreamProcessor>>,
    pub failed_when_contains: Vec<String>,
}

/// Incremental stream of normalized output chunks from a single command.
///
/// Created by [`Channel::send_command_stream()`] or
/// [`GenericDriver::send_command_stream()`](super::GenericDriver).
///
/// The stream borrows the channel mutably, preventing concurrent use
/// (same exclusivity pattern as [`GenericConfigSession`](super::GenericConfigSession)).
pub struct CommandStream<'a> {
    /// The channel we're streaming from.
    channel: &'a mut Channel,
    /// Accumulated ANSI-stripped, UN-normalized data.
    holdback: BytesMut,
    /// Whether we still need to strip the command echo.
    first_chunk: bool,
    /// The command that was sent (for echo stripping).
    command: String,
    /// Whether to normalize line endings.
    normalize: bool,
    /// Optional vendor-specific stream processor.
    processor: Option<Box<dyn StreamProcessor>>,
    /// Failure patterns to check.
    failed_when_contains: Vec<String>,
    /// How many bytes from the end to hold back for prompt detection.
    search_depth: usize,
    /// Individual prompt patterns (avoids combined-NFA memory overhead).
    prompt_patterns: Vec<Regex>,
    /// Timeout for each read operation.
    timeout: Duration,
    /// When the command was sent.
    start: Instant,
    /// Whether the stream has finished (prompt detected or error).
    done: bool,
    /// Completion metadata (populated when prompt is found).
    completion: Option<StreamCompletion>,
    /// First failure pattern detected during streaming.
    found_failure: Option<String>,
    /// Tail of previous emission for cross-boundary failure detection.
    overlap_tail: BytesMut,
}

/// Number of bytes to keep from the end of each emitted chunk for
/// cross-boundary failure pattern detection.
const FAILURE_OVERLAP_BYTES: usize = 64;

impl<'a> CommandStream<'a> {
    /// Create a new `CommandStream`.
    ///
    /// Called internally by [`Channel::send_command_stream()`].
    pub(crate) fn new(
        channel: &'a mut Channel,
        command: &str,
        config: StreamConfig,
        start: Instant,
    ) -> Self {
        Self {
            channel,
            holdback: BytesMut::with_capacity(4096),
            first_chunk: true,
            command: command.to_owned(),
            normalize: config.normalize,
            processor: config.processor,
            failed_when_contains: config.failed_when_contains,
            search_depth: config.search_depth,
            prompt_patterns: config.prompt_patterns,
            timeout: config.timeout,
            start,
            done: false,
            completion: None,
            found_failure: None,
            overlap_tail: BytesMut::with_capacity(FAILURE_OVERLAP_BYTES),
        }
    }

    /// Get the next chunk of normalized output.
    ///
    /// Returns `Ok(Some(chunk))` for each chunk of output data,
    /// `Ok(None)` when the stream is complete (prompt detected),
    /// or `Err` on timeout/disconnect.
    ///
    /// After `Ok(None)` is returned, call [`completion()`](Self::completion)
    /// to get the prompt, elapsed time, and failure information.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }

        loop {
            // 1. Read ANSI-stripped data from PTY
            let raw = match self.channel.pty().read_chunk(self.timeout).await {
                Ok(chunk) => chunk,
                Err(err) => {
                    self.done = true;
                    self.channel.handle_error(&err);
                    self.channel.mark_command_complete();
                    return Err(err);
                }
            };
            self.holdback.extend_from_slice(&raw);

            // 2. Strip echo on first data (handles \r before \n in raw data).
            //    Only attempt once we have at least one \n in the holdback,
            //    since the echo line may arrive across multiple SSH Data messages.
            if self.first_chunk && memchr::memchr(b'\n', &self.holdback).is_some() {
                strip_echo_streaming(&mut self.holdback, &self.command);
                // Trim leading \n bytes
                let leading = self.holdback.iter().take_while(|&&b| b == b'\n').count();
                if leading > 0 {
                    let _ = self.holdback.split_to(leading);
                }
                self.first_chunk = false;
            }

            // 3. Check tail for prompt pattern (on un-normalized data)
            let tail_start = self.holdback.len().saturating_sub(self.search_depth);
            let tail = &self.holdback[tail_start..];
            let prompt_match = self.prompt_patterns.iter().find_map(|p| p.find(tail));
            if let Some(m) = prompt_match {
                // PROMPT FOUND — finalize
                //
                // The regex may match only part of the prompt line (e.g., `$ ` at the end
                // of `[user@host ~]$ `). We need to find the start of the LINE containing
                // the match so the entire prompt decoration is excluded from output.
                let match_abs_pos = tail_start + m.start();
                let prompt_line_start =
                    match memchr::memrchr(b'\n', &self.holdback[..match_abs_pos]) {
                        Some(nl_pos) => nl_pos + 1,
                        None => 0, // prompt is on the first (or only) line
                    };

                let prompt = String::from_utf8_lossy(&self.holdback[prompt_line_start..])
                    .trim()
                    .to_string();
                let mut output = self.holdback.split_to(prompt_line_start);

                // Strip trailing \n that separated output from the prompt line
                super::channel::strip_trailing_prompt_in_place(&mut output);

                // Normalize and vendor-process
                if self.normalize {
                    super::channel::normalize_linefeeds_in_place(&mut output);
                }
                if let Some(ref mut proc) = self.processor {
                    proc.process_lines(&mut output);
                }

                // Check failure patterns (with overlap)
                if self.found_failure.is_none() {
                    self.found_failure = self.check_failure_patterns(&output);
                }

                // Update channel privilege state
                self.channel.update_privilege_from_prompt(&prompt);

                self.completion = Some(StreamCompletion {
                    prompt,
                    elapsed: self.start.elapsed(),
                    failure_pattern: self.found_failure.clone(),
                });
                self.done = true;
                self.channel.mark_command_complete();

                return if output.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(output.freeze()))
                };
            }

            // 4. NO PROMPT — emit safe prefix (only complete lines)
            if self.holdback.len() <= self.search_depth {
                continue; // not enough data to safely emit
            }

            let safe_end = self.holdback.len() - self.search_depth;

            // Only emit complete lines (find last \n in safe region)
            let last_nl = memchr::memrchr(b'\n', &self.holdback[..safe_end]);
            let Some(last_nl) = last_nl else {
                continue; // no complete line yet
            };

            let emit_end = last_nl + 1;
            let mut chunk = self.holdback.split_to(emit_end);

            // Normalize and process the emittable chunk
            if self.normalize {
                super::channel::normalize_linefeeds_in_place(&mut chunk);
            }
            if let Some(ref mut proc) = self.processor {
                proc.process_lines(&mut chunk);
            }

            // Failure check with overlap window
            if self.found_failure.is_none() {
                self.found_failure = self.check_failure_patterns(&chunk);
            }
            self.update_overlap_tail(&chunk);

            return Ok(Some(chunk.freeze()));
        }
    }

    /// Convert this stream into a [`Stream`].
    ///
    /// Note: this consumes `self`, so [`completion()`](Self::completion)
    /// is not accessible afterward. Use the [`next_chunk()`](Self::next_chunk)
    /// loop directly if you need completion metadata.
    pub fn into_stream(self) -> impl Stream<Item = Result<Bytes>> + 'a {
        futures_util::stream::unfold(self, |mut stream| async move {
            match stream.next_chunk().await {
                Ok(Some(chunk)) => Some((Ok(chunk), stream)),
                Ok(None) => None,
                Err(e) => Some((Err(e), stream)),
            }
        })
    }

    /// Get the completion metadata after the stream finishes.
    ///
    /// Returns `None` if the stream hasn't finished yet.
    pub fn completion(&self) -> Option<&StreamCompletion> {
        self.completion.as_ref()
    }

    /// Check whether the stream has finished.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Drain the stream to completion, discarding remaining output.
    ///
    /// Use this to abandon processing while keeping the channel usable
    /// for subsequent commands. Without calling this (or draining via
    /// [`next_chunk()`](Self::next_chunk)), the channel will reject
    /// further commands with [`DriverError::StreamNotDrained`](crate::error::DriverError::StreamNotDrained).
    pub async fn cancel(&mut self) -> Result<()> {
        while self.next_chunk().await?.is_some() {}
        Ok(())
    }

    /// Check failure patterns against a chunk, prepending the overlap tail
    /// to catch patterns that span chunk boundaries.
    fn check_failure_patterns(&self, chunk: &[u8]) -> Option<String> {
        if self.failed_when_contains.is_empty() {
            return None;
        }

        // Build search window: overlap_tail + chunk
        if self.overlap_tail.is_empty() {
            // No overlap — search chunk directly
            for pattern in &self.failed_when_contains {
                if memchr::memmem::find(chunk, pattern.as_bytes()).is_some() {
                    return Some(pattern.clone());
                }
            }
        } else {
            // Prepend overlap tail for cross-boundary detection
            let mut search_window = BytesMut::with_capacity(self.overlap_tail.len() + chunk.len());
            search_window.extend_from_slice(&self.overlap_tail);
            search_window.extend_from_slice(chunk);
            for pattern in &self.failed_when_contains {
                if memchr::memmem::find(&search_window, pattern.as_bytes()).is_some() {
                    return Some(pattern.clone());
                }
            }
        }

        None
    }

    /// Update the overlap tail with the end of the just-emitted chunk.
    fn update_overlap_tail(&mut self, emitted: &[u8]) {
        self.overlap_tail.clear();
        let start = emitted.len().saturating_sub(FAILURE_OVERLAP_BYTES);
        self.overlap_tail.extend_from_slice(&emitted[start..]);
    }
}
/// Strip command echo from un-normalized data (handles `\r` before `\n`).
fn strip_echo_streaming(buf: &mut BytesMut, command: &str) {
    if let Some(nl_pos) = memchr::memchr(b'\n', buf) {
        let first_line = &buf[..nl_pos];
        let trimmed = if first_line.last() == Some(&b'\r') {
            &first_line[..first_line.len() - 1]
        } else {
            first_line
        };
        if trimmed == command.as_bytes() {
            let _ = buf.split_to(nl_pos + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // strip_echo_streaming — exhaustive
    // =========================================================================

    #[test]
    fn test_strip_echo_streaming_lf() {
        let mut buf = BytesMut::from("show version\noutput here");
        strip_echo_streaming(&mut buf, "show version");
        assert_eq!(&buf[..], b"output here");
    }

    #[test]
    fn test_strip_echo_streaming_crlf() {
        let mut buf = BytesMut::from("show version\r\noutput here");
        strip_echo_streaming(&mut buf, "show version");
        assert_eq!(&buf[..], b"output here");
    }

    #[test]
    fn test_strip_echo_streaming_no_match() {
        let mut buf = BytesMut::from("different command\noutput");
        strip_echo_streaming(&mut buf, "show version");
        assert_eq!(&buf[..], b"different command\noutput");
    }

    #[test]
    fn test_strip_echo_streaming_no_newline() {
        let mut buf = BytesMut::from("show version");
        strip_echo_streaming(&mut buf, "show version");
        // No newline found, so nothing stripped
        assert_eq!(&buf[..], b"show version");
    }

    #[test]
    fn test_strip_echo_streaming_empty_buf() {
        let mut buf = BytesMut::new();
        strip_echo_streaming(&mut buf, "show version");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_strip_echo_streaming_partial_match() {
        // Command is a prefix of the first line — should NOT strip
        let mut buf = BytesMut::from("show version | no-more\noutput");
        strip_echo_streaming(&mut buf, "show version");
        assert_eq!(&buf[..], b"show version | no-more\noutput");
    }

    #[test]
    fn test_strip_echo_streaming_empty_command() {
        // Empty command should never match the first line
        let mut buf = BytesMut::from("output\nprompt");
        strip_echo_streaming(&mut buf, "");
        // First line "output" != "", so nothing stripped
        assert_eq!(&buf[..], b"output\nprompt");
    }

    #[test]
    fn test_strip_echo_streaming_command_only_lf() {
        // Buffer is just the command followed by \n
        let mut buf = BytesMut::from("ls\n");
        strip_echo_streaming(&mut buf, "ls");
        assert_eq!(&buf[..], b"");
    }

    #[test]
    fn test_strip_echo_streaming_command_only_crlf() {
        let mut buf = BytesMut::from("ls\r\n");
        strip_echo_streaming(&mut buf, "ls");
        assert_eq!(&buf[..], b"");
    }

    #[test]
    fn test_strip_echo_streaming_preserves_remaining_data() {
        let mut buf = BytesMut::from("pwd\r\n/home/user\r\nrouter>");
        strip_echo_streaming(&mut buf, "pwd");
        assert_eq!(&buf[..], b"/home/user\r\nrouter>");
    }

    #[test]
    fn test_strip_echo_streaming_multiline_output() {
        let mut buf = BytesMut::from("uname -a\nLinux host 6.1.0\nmore info\nprompt");
        strip_echo_streaming(&mut buf, "uname -a");
        assert_eq!(&buf[..], b"Linux host 6.1.0\nmore info\nprompt");
    }

    #[test]
    fn test_strip_echo_streaming_binary_safe() {
        // Ensure we handle non-utf8 bytes gracefully
        let mut buf = BytesMut::from(&b"cmd\n\xff\xfe output"[..]);
        strip_echo_streaming(&mut buf, "cmd");
        assert_eq!(&buf[..], b"\xff\xfe output");
    }

    #[test]
    fn test_strip_echo_streaming_first_line_longer_than_command() {
        let mut buf = BytesMut::from("show\noutput");
        strip_echo_streaming(&mut buf, "show version");
        // "show" != "show version", so nothing stripped
        assert_eq!(&buf[..], b"show\noutput");
    }

    // =========================================================================
    // Failure pattern detection — FailureTester mirrors CommandStream logic
    // =========================================================================

    /// Helper that mirrors CommandStream's check_failure_patterns / update_overlap_tail
    /// so we can test the algorithm without needing a real SSH channel.
    struct FailureTester {
        failed_when_contains: Vec<String>,
        overlap_tail: BytesMut,
    }

    impl FailureTester {
        fn new(patterns: &[&str]) -> Self {
            Self {
                failed_when_contains: patterns.iter().map(|s| s.to_string()).collect(),
                overlap_tail: BytesMut::new(),
            }
        }

        /// Same algorithm as CommandStream::check_failure_patterns
        fn check(&self, chunk: &[u8]) -> Option<String> {
            if self.failed_when_contains.is_empty() {
                return None;
            }
            if self.overlap_tail.is_empty() {
                for pattern in &self.failed_when_contains {
                    if memchr::memmem::find(chunk, pattern.as_bytes()).is_some() {
                        return Some(pattern.clone());
                    }
                }
            } else {
                let mut search_window =
                    BytesMut::with_capacity(self.overlap_tail.len() + chunk.len());
                search_window.extend_from_slice(&self.overlap_tail);
                search_window.extend_from_slice(chunk);
                for pattern in &self.failed_when_contains {
                    if memchr::memmem::find(&search_window, pattern.as_bytes()).is_some() {
                        return Some(pattern.clone());
                    }
                }
            }
            None
        }

        /// Same algorithm as CommandStream::update_overlap_tail
        fn update_overlap(&mut self, emitted: &[u8]) {
            self.overlap_tail.clear();
            let start = emitted.len().saturating_sub(FAILURE_OVERLAP_BYTES);
            self.overlap_tail.extend_from_slice(&emitted[start..]);
        }
    }

    #[test]
    fn test_failure_pattern_single_chunk() {
        let tester = FailureTester::new(&["syntax error", "unknown command"]);
        assert_eq!(
            tester.check(b"% syntax error: bad input"),
            Some("syntax error".to_string())
        );
    }

    #[test]
    fn test_failure_pattern_absent() {
        let tester = FailureTester::new(&["syntax error", "unknown command"]);
        assert_eq!(
            tester.check(b"ge-0/0/0  up  up\nge-0/0/1  up  down\n"),
            None
        );
    }

    #[test]
    fn test_failure_pattern_cross_boundary() {
        let mut tester = FailureTester::new(&["syntax error"]);
        let chunk1 = b"some output\nsyntax ";
        assert_eq!(tester.check(chunk1), None);
        tester.update_overlap(chunk1);

        let chunk2 = b"error: bad input\nmore output";
        assert_eq!(tester.check(chunk2), Some("syntax error".to_string()));
    }

    #[test]
    fn test_failure_pattern_first_wins() {
        let tester = FailureTester::new(&["error:", "invalid"]);
        assert_eq!(
            tester.check(b"error: invalid command"),
            Some("error:".to_string())
        );
    }

    #[test]
    fn test_failure_pattern_empty_patterns() {
        let tester = FailureTester::new(&[]);
        assert_eq!(tester.check(b"anything"), None);
    }

    #[test]
    fn test_failure_pattern_second_pattern_matches() {
        let tester = FailureTester::new(&["syntax error", "unknown command"]);
        assert_eq!(
            tester.check(b"% unknown command: foo"),
            Some("unknown command".to_string())
        );
    }

    #[test]
    fn test_failure_pattern_exact_match() {
        let tester = FailureTester::new(&["error"]);
        assert_eq!(tester.check(b"error"), Some("error".to_string()));
    }

    #[test]
    fn test_failure_pattern_no_false_positive_substring() {
        // "error" should not match "errors" when that is the pattern
        let tester = FailureTester::new(&["errors"]);
        assert_eq!(tester.check(b"error"), None);
    }

    #[test]
    fn test_failure_pattern_case_sensitive() {
        let tester = FailureTester::new(&["Error"]);
        assert_eq!(tester.check(b"error"), None);
        assert_eq!(tester.check(b"Error"), Some("Error".to_string()));
    }

    // =========================================================================
    // update_overlap_tail
    // =========================================================================

    #[test]
    fn test_overlap_tail_short_emission() {
        let mut tester = FailureTester::new(&[]);
        // Emission shorter than FAILURE_OVERLAP_BYTES
        let emitted = b"short data";
        tester.update_overlap(emitted);
        assert_eq!(&tester.overlap_tail[..], b"short data");
    }

    #[test]
    fn test_overlap_tail_exact_size() {
        let mut tester = FailureTester::new(&[]);
        let emitted = vec![b'x'; FAILURE_OVERLAP_BYTES];
        tester.update_overlap(&emitted);
        assert_eq!(tester.overlap_tail.len(), FAILURE_OVERLAP_BYTES);
        assert_eq!(&tester.overlap_tail[..], &emitted[..]);
    }

    #[test]
    fn test_overlap_tail_truncates_long_emission() {
        let mut tester = FailureTester::new(&[]);
        let emitted = vec![b'a'; FAILURE_OVERLAP_BYTES * 3];
        tester.update_overlap(&emitted);
        assert_eq!(tester.overlap_tail.len(), FAILURE_OVERLAP_BYTES);
        // Should be the LAST FAILURE_OVERLAP_BYTES bytes
        let expected_start = emitted.len() - FAILURE_OVERLAP_BYTES;
        assert_eq!(&tester.overlap_tail[..], &emitted[expected_start..]);
    }

    #[test]
    fn test_overlap_tail_empty_emission() {
        let mut tester = FailureTester::new(&[]);
        tester.overlap_tail.extend_from_slice(b"old data");
        tester.update_overlap(b"");
        assert!(tester.overlap_tail.is_empty());
    }

    #[test]
    fn test_overlap_tail_replaces_previous() {
        let mut tester = FailureTester::new(&[]);
        tester.update_overlap(b"first chunk data");
        assert_eq!(&tester.overlap_tail[..], b"first chunk data");
        tester.update_overlap(b"second chunk data");
        assert_eq!(&tester.overlap_tail[..], b"second chunk data");
    }

    // =========================================================================
    // Cross-boundary failure detection with overlap — multi-step scenarios
    // =========================================================================

    #[test]
    fn test_cross_boundary_pattern_at_exact_boundary() {
        let mut tester = FailureTester::new(&["boundary"]);
        // "bound" in the tail, "ary" in next chunk
        let chunk1 = b"data data bound";
        assert_eq!(tester.check(chunk1), None);
        tester.update_overlap(chunk1);

        let chunk2 = b"ary more data";
        assert_eq!(tester.check(chunk2), Some("boundary".to_string()));
    }

    #[test]
    fn test_three_chunks_failure_in_third() {
        let mut tester = FailureTester::new(&["failure_msg"]);

        let chunk1 = b"chunk one data here\n";
        assert_eq!(tester.check(chunk1), None);
        tester.update_overlap(chunk1);

        let chunk2 = b"chunk two normal output\n";
        assert_eq!(tester.check(chunk2), None);
        tester.update_overlap(chunk2);

        let chunk3 = b"here is a failure_msg in this line\n";
        assert_eq!(tester.check(chunk3), Some("failure_msg".to_string()));
    }

    #[test]
    fn test_overlap_does_not_re_detect_old_pattern() {
        // The overlap tail may contain the pattern from a previous detection.
        // But since the real CommandStream uses found_failure to track first-wins,
        // we test the raw overlap behavior: if the pattern is entirely in the tail
        // and not newly appearing, it would still match.
        let mut tester = FailureTester::new(&["error"]);
        let chunk1 = b"contains error here";
        assert_eq!(tester.check(chunk1), Some("error".to_string()));
        tester.update_overlap(chunk1);

        // Even a benign second chunk will "match" because the overlap still has "error"
        let chunk2 = b"safe data";
        // This is expected behavior — CommandStream guards with found_failure first-wins
        assert_eq!(tester.check(chunk2), Some("error".to_string()));
    }

    // =========================================================================
    // StreamCompletion
    // =========================================================================

    #[test]
    fn test_stream_completion_debug() {
        let c = StreamCompletion {
            prompt: "router>".to_string(),
            elapsed: Duration::from_millis(42),
            failure_pattern: None,
        };
        let dbg = format!("{:?}", c);
        assert!(dbg.contains("router>"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn test_stream_completion_clone() {
        let c = StreamCompletion {
            prompt: "router#".to_string(),
            elapsed: Duration::from_secs(1),
            failure_pattern: Some("syntax error".to_string()),
        };
        let c2 = c.clone();
        assert_eq!(c2.prompt, "router#");
        assert_eq!(c2.failure_pattern, Some("syntax error".to_string()));
    }

    #[test]
    fn test_stream_completion_no_failure() {
        let c = StreamCompletion {
            prompt: "user@host:~$".to_string(),
            elapsed: Duration::from_millis(100),
            failure_pattern: None,
        };
        assert!(c.failure_pattern.is_none());
    }

    // =========================================================================
    // FAILURE_OVERLAP_BYTES constant
    // =========================================================================

    #[test]
    fn test_failure_overlap_bytes_is_64() {
        assert_eq!(FAILURE_OVERLAP_BYTES, 64);
    }
}
