//! Interactive command support for handling prompts that require user input.
//!
//! Many network device commands require confirmation or additional input:
//! - `reload` asks "Proceed with reload? [confirm]"
//! - `copy running-config startup-config` asks for confirmation
//! - `delete flash:file` asks "Delete filename [confirm]?"
//!
//! The `send_interactive` method handles these by sending a sequence of
//! inputs, each waiting for a specific pattern before proceeding.

use std::time::Duration;

use regex::bytes::Regex;

/// An event in an interactive command sequence.
///
/// Each event consists of:
/// - `input`: The text to send (command or response like "y" or "n")
/// - `pattern`: The pattern to wait for after sending the input
/// - `hidden`: Whether the input should be hidden in logs (for passwords)
///
/// # Example
///
/// ```rust
/// use ferrissh::driver::InteractiveEvent;
///
/// // Handle a reload command that asks for confirmation
/// let events = vec![
///     InteractiveEvent::new("reload", r"Proceed.*\[confirm\]").unwrap(),
///     InteractiveEvent::new("y", r"#").unwrap(),
/// ];
/// ```
#[derive(Debug, Clone)]
pub struct InteractiveEvent {
    /// The input to send (command or response).
    pub input: String,

    /// Pattern to wait for after sending input.
    pub pattern: Regex,

    /// Whether this input should be hidden in logs (e.g., passwords).
    pub hidden: bool,

    /// Optional timeout override for this specific event.
    pub timeout: Option<Duration>,
}

impl InteractiveEvent {
    /// Create a new interactive event.
    ///
    /// # Arguments
    ///
    /// * `input` - The text to send
    /// * `pattern` - Regex pattern to wait for after sending
    pub fn new(input: impl Into<String>, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            input: input.into(),
            pattern: Regex::new(pattern)?,
            hidden: false,
            timeout: None,
        })
    }

    /// Create an event for hidden input (like passwords).
    ///
    /// The input will not be logged.
    pub fn hidden(input: impl Into<String>, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            input: input.into(),
            pattern: Regex::new(pattern)?,
            hidden: true,
            timeout: None,
        })
    }

    /// Set a custom timeout for this event.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Mark this event's input as hidden (for logging).
    pub fn with_hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }
}

/// Result of an interactive command sequence.
#[derive(Debug, Clone)]
pub struct InteractiveResult {
    /// Results from each step in the sequence.
    pub steps: Vec<InteractiveStep>,

    /// Total time for the entire sequence.
    pub elapsed: Duration,
}

impl InteractiveResult {
    /// Create a new interactive result.
    pub fn new(steps: Vec<InteractiveStep>, elapsed: Duration) -> Self {
        Self { steps, elapsed }
    }

    /// Check if any step failed.
    pub fn is_success(&self) -> bool {
        self.steps.iter().all(|s| s.is_success())
    }

    /// Get the final output (from the last step).
    pub fn final_output(&self) -> Option<&str> {
        self.steps.last().map(|s| s.output.as_str())
    }

    /// Get all outputs concatenated.
    pub fn full_output(&self) -> String {
        self.steps.iter().map(|s| s.output.as_str()).collect()
    }
}

/// Result of a single step in an interactive sequence.
#[derive(Debug, Clone)]
pub struct InteractiveStep {
    /// The input that was sent (masked if hidden).
    pub input: String,

    /// The output received after sending input.
    pub output: String,

    /// The raw output before normalization.
    pub raw_output: String,

    /// Time taken for this step.
    pub elapsed: Duration,

    /// Failure message if the step failed.
    pub failure_message: Option<String>,
}

impl InteractiveStep {
    /// Create a successful step.
    pub fn success(
        input: impl Into<String>,
        output: impl Into<String>,
        raw_output: impl Into<String>,
        elapsed: Duration,
    ) -> Self {
        Self {
            input: input.into(),
            output: output.into(),
            raw_output: raw_output.into(),
            elapsed,
            failure_message: None,
        }
    }

    /// Create a failed step.
    pub fn failed(
        input: impl Into<String>,
        output: impl Into<String>,
        raw_output: impl Into<String>,
        elapsed: Duration,
        message: impl Into<String>,
    ) -> Self {
        Self {
            input: input.into(),
            output: output.into(),
            raw_output: raw_output.into(),
            elapsed,
            failure_message: Some(message.into()),
        }
    }

    /// Check if this step succeeded.
    pub fn is_success(&self) -> bool {
        self.failure_message.is_none()
    }
}

/// Builder for creating interactive command sequences.
///
/// # Example
///
/// ```rust
/// use ferrissh::driver::InteractiveBuilder;
/// use std::time::Duration;
///
/// let events = InteractiveBuilder::new()
///     .send("copy running-config startup-config")
///     .expect(r"Destination filename").unwrap()
///     .send("")  // Accept default filename
///     .expect(r"#").unwrap()
///     .with_timeout(Duration::from_secs(60))
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct InteractiveBuilder {
    events: Vec<InteractiveEvent>,
    default_timeout: Option<Duration>,
}

impl InteractiveBuilder {
    /// Create a new interactive builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an input to send.
    ///
    /// Must be followed by `expect()` to specify what to wait for.
    pub fn send(self, input: impl Into<String>) -> InteractiveBuilderWithInput {
        InteractiveBuilderWithInput {
            builder: self,
            input: input.into(),
            hidden: false,
            timeout: None,
        }
    }

    /// Add a hidden input (like a password).
    pub fn send_hidden(self, input: impl Into<String>) -> InteractiveBuilderWithInput {
        InteractiveBuilderWithInput {
            builder: self,
            input: input.into(),
            hidden: true,
            timeout: None,
        }
    }

    /// Set the default timeout for all events.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = Some(timeout);
        self
    }

    /// Build the list of interactive events.
    pub fn build(self) -> Vec<InteractiveEvent> {
        self.events
    }
}

/// Intermediate state for the builder after `send()` is called.
#[derive(Debug)]
pub struct InteractiveBuilderWithInput {
    builder: InteractiveBuilder,
    input: String,
    hidden: bool,
    timeout: Option<Duration>,
}

impl InteractiveBuilderWithInput {
    /// Specify the pattern to wait for after sending the input.
    pub fn expect(mut self, pattern: &str) -> Result<InteractiveBuilder, regex::Error> {
        let mut event = if self.hidden {
            InteractiveEvent::hidden(&self.input, pattern)?
        } else {
            InteractiveEvent::new(&self.input, pattern)?
        };

        if let Some(timeout) = self.timeout.or(self.builder.default_timeout) {
            event = event.with_timeout(timeout);
        }

        self.builder.events.push(event);
        Ok(self.builder)
    }

    /// Set a custom timeout for this specific event.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interactive_event_new() {
        let event = InteractiveEvent::new("reload", r"confirm").unwrap();
        assert_eq!(event.input, "reload");
        assert!(!event.hidden);
        assert!(event.timeout.is_none());
    }

    #[test]
    fn test_interactive_event_hidden() {
        let event = InteractiveEvent::hidden("secret123", r"#").unwrap();
        assert_eq!(event.input, "secret123");
        assert!(event.hidden);
    }

    #[test]
    fn test_interactive_event_invalid_pattern() {
        let result = InteractiveEvent::new("cmd", r"[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_interactive_builder() {
        let events = InteractiveBuilder::new()
            .send("reload")
            .expect(r"confirm")
            .unwrap()
            .send("y")
            .expect(r"#")
            .unwrap()
            .build();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].input, "reload");
        assert_eq!(events[1].input, "y");
    }

    #[test]
    fn test_interactive_builder_with_hidden() {
        let events = InteractiveBuilder::new()
            .send("enable")
            .expect(r"[Pp]assword")
            .unwrap()
            .send_hidden("secret")
            .expect(r"#")
            .unwrap()
            .build();

        assert_eq!(events.len(), 2);
        assert!(!events[0].hidden);
        assert!(events[1].hidden);
    }

    #[test]
    fn test_interactive_result() {
        let steps = vec![
            InteractiveStep::success("cmd1", "output1", "raw1", Duration::from_millis(100)),
            InteractiveStep::success("cmd2", "output2", "raw2", Duration::from_millis(200)),
        ];
        let result = InteractiveResult::new(steps, Duration::from_millis(300));

        assert!(result.is_success());
        assert_eq!(result.final_output(), Some("output2"));
        assert_eq!(result.full_output(), "output1output2");
    }
}
