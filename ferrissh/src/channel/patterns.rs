//! Pattern matching utilities for prompt detection.

use regex::bytes::Regex;

/// Trait for prompt matching - regex by default, extensible for custom parsers.
pub trait PromptMatcher: Send + Sync {
    /// Returns byte offset where match ends, or None if no match.
    fn find_match(&self, data: &[u8]) -> Option<usize>;

    /// Check if the data matches the pattern.
    fn is_match(&self, data: &[u8]) -> bool {
        self.find_match(data).is_some()
    }
}

/// Regex-based prompt matcher (the default implementation).
impl PromptMatcher for Regex {
    fn find_match(&self, data: &[u8]) -> Option<usize> {
        self.find(data).map(|m| m.end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_prompt_matcher() {
        let pattern = Regex::new(r"router#\s*$").unwrap();
        assert!(pattern.is_match(b"router# "));
        assert!(pattern.is_match(b"some output\nrouter#"));
        assert!(!pattern.is_match(b"router> "));
    }
}
