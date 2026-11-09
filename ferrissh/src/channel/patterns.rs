//! Pattern matching utilities for prompt detection.

use regex::bytes::{Match, Regex};

/// Offset where a prompt search over the last `depth` bytes of `data` should start.
///
/// The raw offset (`len - depth`) usually lands mid-line, and multi-line prompt
/// patterns anchor on `^`, which matches at the start of the haystack. Searching
/// from a mid-line offset therefore lets a line fragment like
/// `GracefulShutdownRcv>` (from `Options: <GracefulShutdownRcv>`) look like a
/// Junos prompt. Advance to the next line start so `^` only matches real line
/// beginnings.
pub(crate) fn tail_start(data: &[u8], depth: usize) -> usize {
    let start = data.len().saturating_sub(depth);
    if start == 0 || data[start - 1] == b'\n' {
        return start;
    }
    match memchr::memchr(b'\n', &data[start..]) {
        Some(nl) => start + nl + 1,
        // a single line longer than the window: nothing better to anchor on
        None => start,
    }
}

/// Find a prompt match that ends the data (only whitespace may follow it).
///
/// A prompt is the last thing a device sends before waiting for input; a
/// prompt-shaped line followed by more output is command output, not a prompt.
pub(crate) fn find_trailing<'a>(pattern: &Regex, data: &'a [u8]) -> Option<Match<'a>> {
    pattern
        .find_iter(data)
        .find(|m| data[m.end()..].iter().all(u8::is_ascii_whitespace))
}

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
    fn test_tail_start_aligns_to_line() {
        let data = b"aaaa\nbbbb\ncccc";
        assert_eq!(tail_start(data, 100), 0);
        assert_eq!(tail_start(data, 7), 10); // mid "bbbb" -> start of "cccc"
        assert_eq!(tail_start(data, 5), 10); // exactly at a line start
        assert_eq!(tail_start(b"no newline here", 4), 11);
    }

    #[test]
    fn test_mid_line_fragment_is_not_a_prompt() {
        let re = Regex::new(r"(?m)(?-u)^[\w\-@()/:\.]+>\s?$").unwrap();
        let data = b"  Options: <GracefulShutdownRcv>\n  Holdtime: 90\n";
        // old behaviour: slicing inside the line made the fragment match
        assert!(re.is_match(&data[12..]));
        let t = tail_start(data, data.len() - 12);
        assert!(find_trailing(&re, &data[t..]).is_none());
    }

    #[test]
    fn test_find_trailing_requires_end() {
        let re = Regex::new(r"(?m)(?-u)^[\w\-@.]+>\s?$").unwrap();
        assert!(find_trailing(&re, b"out\nfoo>\nmore output\n").is_none());
        let m = find_trailing(&re, b"out\nfoo>\nmore\nuser@host> ").unwrap();
        assert_eq!(m.as_bytes(), b"user@host> ");
        assert!(find_trailing(&re, b"out\nuser@host>").is_some());
    }

    #[test]
    fn test_regex_prompt_matcher() {
        let pattern = Regex::new(r"router#\s*$").unwrap();
        assert!(pattern.is_match(b"router# "));
        assert!(pattern.is_match(b"some output\nrouter#"));
        assert!(!pattern.is_match(b"router> "));
    }
}
