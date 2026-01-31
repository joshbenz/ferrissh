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

/// A compiled prompt pattern with optional negative matches.
#[derive(Debug, Clone)]
pub struct CompiledPrompt {
    /// The main pattern to match.
    pattern: Regex,

    /// Patterns that must NOT be present for a match.
    not_contains: Vec<String>,
}

impl CompiledPrompt {
    /// Create a new compiled prompt from a pattern string.
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: Regex::new(pattern)?,
            not_contains: Vec::new(),
        })
    }

    /// Create a compiled prompt with negative patterns.
    pub fn with_not_contains(pattern: &str, not_contains: Vec<String>) -> Result<Self, regex::Error> {
        Ok(Self {
            pattern: Regex::new(pattern)?,
            not_contains,
        })
    }

    /// Get a reference to the underlying regex.
    pub fn regex(&self) -> &Regex {
        &self.pattern
    }
}

impl PromptMatcher for CompiledPrompt {
    fn find_match(&self, data: &[u8]) -> Option<usize> {
        // First check negative patterns
        let data_str = String::from_utf8_lossy(data);
        for nc in &self.not_contains {
            if data_str.contains(nc) {
                return None;
            }
        }

        // Then check the main pattern
        self.pattern.find(data).map(|m| m.end())
    }
}

/// Compile a prompt pattern string into a regex.
///
/// Handles common prompt pattern conveniences:
/// - Anchors to end of string by default if no anchor specified
/// - Handles common shell prompt patterns
pub fn compile_prompt_pattern(pattern: &str) -> Result<Regex, regex::Error> {
    // If pattern doesn't end with $ anchor, add one
    let pattern = if pattern.ends_with('$') || pattern.ends_with("\\s*$") {
        pattern.to_string()
    } else {
        format!("{}\\s*$", pattern)
    };

    Regex::new(&pattern)
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

    #[test]
    fn test_compiled_prompt_not_contains() {
        let prompt = CompiledPrompt::with_not_contains(
            r"#\s*$",
            vec!["(config)".to_string()],
        )
        .unwrap();

        // Should match privilege mode
        assert!(prompt.is_match(b"router#"));

        // Should NOT match config mode (contains "(config)")
        assert!(!prompt.is_match(b"router(config)#"));
    }

    #[test]
    fn test_compile_prompt_pattern() {
        // Pattern without anchor gets one added
        let pattern = compile_prompt_pattern(r"router#").unwrap();
        assert!(pattern.is_match(b"router# "));

        // Pattern with anchor stays as-is
        let pattern = compile_prompt_pattern(r"router#$").unwrap();
        assert!(pattern.is_match(b"router#"));
    }
}
