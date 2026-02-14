//! Response type for command execution results.

use std::time::Duration;

/// Response from a command execution.
#[derive(Debug, Clone)]
pub struct Response {
    /// The command that was executed.
    pub command: String,

    /// The command output (normalized - command echo and trailing prompt removed).
    pub result: String,

    /// The raw output before normalization.
    pub raw_result: String,

    /// The prompt that was matched at the end.
    pub prompt: String,

    /// Time taken to execute the command.
    pub elapsed: Duration,

    /// Failure message if the command failed (based on failure patterns).
    pub failure_message: Option<String>,
}

impl Response {
    /// Create a new successful response.
    pub fn new(
        command: impl Into<String>,
        result: impl Into<String>,
        raw_result: impl Into<String>,
        prompt: impl Into<String>,
        elapsed: Duration,
    ) -> Self {
        Self {
            command: command.into(),
            result: result.into(),
            raw_result: raw_result.into(),
            prompt: prompt.into(),
            elapsed,
            failure_message: None,
        }
    }

    /// Create a failed response.
    pub fn failed(
        command: impl Into<String>,
        result: impl Into<String>,
        raw_result: impl Into<String>,
        prompt: impl Into<String>,
        elapsed: Duration,
        failure_message: impl Into<String>,
    ) -> Self {
        Self {
            command: command.into(),
            result: result.into(),
            raw_result: raw_result.into(),
            prompt: prompt.into(),
            elapsed,
            failure_message: Some(failure_message.into()),
        }
    }

    /// Check if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.failure_message.is_none()
    }

    /// Get the result lines as an iterator.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.result.lines()
    }

    /// Check if the result contains a substring.
    pub fn contains(&self, pattern: &str) -> bool {
        self.result.contains(pattern)
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.result)
    }
}
