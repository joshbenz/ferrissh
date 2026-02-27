//! Response type for command execution results.

use std::time::Duration;

use super::payload::Payload;

/// Response from a command execution.
#[derive(Debug, Clone)]
pub struct Response {
    /// The command that was executed.
    pub command: String,

    /// The command output (normalized - command echo and trailing prompt removed).
    pub result: Payload,

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
        result: Payload,
        prompt: impl Into<String>,
        elapsed: Duration,
    ) -> Self {
        Self {
            command: command.into(),
            result,
            prompt: prompt.into(),
            elapsed,
            failure_message: None,
        }
    }

    /// Create a failed response.
    pub fn failed(
        command: impl Into<String>,
        result: Payload,
        prompt: impl Into<String>,
        elapsed: Duration,
        failure_message: impl Into<String>,
    ) -> Self {
        Self {
            command: command.into(),
            result,
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn make_payload(s: &str) -> Payload {
        Payload::from_bytes_mut(BytesMut::from(s))
    }

    #[test]
    fn test_new_response() {
        let resp = Response::new(
            "show version",
            make_payload("Junos: 21.4R1"),
            "router>",
            Duration::from_millis(100),
        );
        assert_eq!(resp.command, "show version");
        assert_eq!(&*resp.result, "Junos: 21.4R1");
        assert_eq!(resp.prompt, "router>");
        assert!(resp.is_success());
        assert!(resp.failure_message.is_none());
    }

    #[test]
    fn test_failed_response() {
        let resp = Response::failed(
            "bad command",
            make_payload("syntax error"),
            "router>",
            Duration::from_millis(50),
            "syntax error",
        );
        assert!(!resp.is_success());
        assert_eq!(resp.failure_message.as_deref(), Some("syntax error"));
    }

    #[test]
    fn test_response_lines() {
        let resp = Response::new(
            "show route",
            make_payload("10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24"),
            "router>",
            Duration::from_millis(100),
        );
        let lines: Vec<&str> = resp.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "10.0.0.0/24");
    }

    #[test]
    fn test_response_contains() {
        let resp = Response::new(
            "show version",
            make_payload("Hostname: router1\nModel: mx240"),
            "router>",
            Duration::from_millis(100),
        );
        assert!(resp.contains("mx240"));
        assert!(!resp.contains("srx300"));
    }

    #[test]
    fn test_response_display() {
        let resp = Response::new(
            "cmd",
            make_payload("output text"),
            "prompt",
            Duration::from_millis(10),
        );
        assert_eq!(format!("{}", resp), "output text");
    }

    #[test]
    fn test_response_result_deref() {
        // Verify that response.result can be used as &str via Deref
        let resp = Response::new(
            "cmd",
            make_payload("hello world"),
            "prompt",
            Duration::from_millis(10),
        );
        // These all work via Deref<Target = str>
        assert!(resp.result.starts_with("hello"));
        assert!(resp.result.ends_with("world"));
        assert_eq!(resp.result.len(), 11);
        let _trimmed: &str = resp.result.trim();
    }

    #[test]
    fn test_response_clone() {
        let resp = Response::new(
            "cmd",
            make_payload("output"),
            "prompt",
            Duration::from_millis(10),
        );
        let cloned = resp.clone();
        assert_eq!(&*cloned.result, &*resp.result);
        // Payload clone is O(1), same underlying pointer
        assert_eq!(
            cloned.result.as_bytes().as_ptr(),
            resp.result.as_bytes().as_ptr()
        );
    }

    #[test]
    fn test_response_empty_result() {
        let resp = Response::new(
            "no-output-cmd",
            make_payload(""),
            "prompt",
            Duration::from_millis(10),
        );
        assert!(resp.result.is_empty());
        assert_eq!(resp.lines().count(), 0);
        assert!(!resp.contains("anything"));
    }
}
