//! Pattern matching utilities for prompt detection.

use regex::bytes::{Match, Regex};

/// Offset where a prompt search over the last `depth` bytes of `data` should start.
///
/// The raw offset (`len - depth`) usually lands mid-line, and multi-line prompt
/// patterns anchor on `^`, which matches at the start of the haystack. Searching
/// from a mid-line offset therefore lets a line fragment like
/// `GracefulShutdownRcv>` (from `Options: <GracefulShutdownRcv>`) look like a
/// Junos prompt. Move to a real line start so `^` only matches line beginnings.
///
/// The line the raw offset cuts through is kept whole by stepping *back* to its
/// start (looking back at most one more `depth`), so a two-line prompt such as
/// Nokia's `[/]\nA:admin@router#` or Junos' `{master}\nuser@host>` that straddles
/// the raw offset is still matched in full. Only when that line is itself longer
/// than `depth` does the window advance to the next line start instead.
pub(crate) fn tail_start(data: &[u8], depth: usize) -> usize {
    let start = data.len().saturating_sub(depth);
    if start == 0 || data[start - 1] == b'\n' {
        return start;
    }
    let floor = start.saturating_sub(depth);
    if let Some(nl) = memchr::memrchr(b'\n', &data[floor..start]) {
        return floor + nl + 1;
    }
    if floor == 0 {
        return 0;
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
///
/// The trailing-whitespace boundary is located once, so the cost is one pass
/// over `data` plus the regex scan, however many candidate matches there are.
pub(crate) fn find_trailing<'a>(pattern: &Regex, data: &'a [u8]) -> Option<Match<'a>> {
    let end = data.trim_ascii_end().len();
    pattern.find_iter(data).find(|m| m.end() >= end)
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
        assert_eq!(tail_start(data, 7), 5); // mid "bbbb" -> start of "bbbb"
        assert_eq!(tail_start(data, 4), 10); // exactly at a line start
        assert_eq!(tail_start(data, 5), 5); // on the "\n": keep "bbbb" whole
        // whole buffer is one line: back to 0
        assert_eq!(tail_start(b"no newline here", 8), 0);
        // the cut line is longer than the window: nothing to step back to
        assert_eq!(tail_start(b"no newline here", 4), 11);
        // ... unless a later line start exists, then advance to it
        let mut data = vec![b'x'; 50];
        data.extend_from_slice(b"\nabc");
        assert_eq!(tail_start(&data, 10), 51);
    }

    #[test]
    fn test_tail_start_keeps_multiline_prompt_whole() {
        let re = Regex::new(r"(?m)(?-u)^\[.*\]\n[A-D]:[\w.@-]+#\s?$").unwrap();
        let data = b"line one of output\nline two\n[/]\nA:admin@router# ";
        // raw offset lands inside the "[/]" line
        let depth = b"A:admin@router# ".len() + 2;
        let t = tail_start(data, depth);
        assert_eq!(&data[t..], b"[/]\nA:admin@router# ");
        assert!(find_trailing(&re, &data[t..]).is_some());
    }

    #[test]
    fn test_find_trailing_only_whitespace_after_match() {
        let re = Regex::new(r"(?m)(?-u)^[\w@]+#\s?$").unwrap();
        assert!(find_trailing(&re, b"a#\nb#\nc# \n \t").is_some());
        assert!(find_trailing(&re, b"a#\nb#\nc# \nx").is_none());
        assert!(find_trailing(&re, b"").is_none());
        assert!(find_trailing(&re, b"   \n").is_none());
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
