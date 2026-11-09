//! Pattern buffer with efficient tail-search optimization.
//!
//! This implements scrapli's key optimization: only search the last N bytes
//! of the buffer for prompt patterns, rather than the entire output.
//!
//! For large outputs (e.g., full BGP tables), this is critical for performance.

use bytes::BytesMut;
use regex::bytes::Regex;
use vte::{Parser, Perform};

/// Buffer for accumulating output and efficiently searching for patterns.
///
/// Uses scrapli's optimization of only searching the tail of the buffer
/// for prompt patterns, making it efficient for large command outputs.
///
/// Holds a reusable [`vte::Parser`] so ANSI escape stripping does not
/// allocate on every call and correctly handles sequences split across
/// SSH data messages.
pub struct PatternBuffer {
    /// The accumulated output buffer.
    buffer: BytesMut,

    /// How many bytes from the end to search for patterns.
    /// Default is 1000 bytes.
    search_depth: usize,

    /// Offset of the first `\n` in `buffer`, tracked as data arrives so
    /// [`search_tail_any_after_newline`](Self::search_tail_any_after_newline)
    /// never has to rescan the buffer.
    first_newline: Option<usize>,

    /// Reusable VTE parser for ANSI escape stripping.
    parser: Parser,
}

impl std::fmt::Debug for PatternBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternBuffer")
            .field("buffer", &self.buffer)
            .field("search_depth", &self.search_depth)
            .finish_non_exhaustive()
    }
}

/// VTE `Perform` implementation that writes printable characters and `\n`
/// directly into a `BytesMut`, matching `strip-ansi-escapes` behaviour.
struct AnsiStripper<'a> {
    out: &'a mut BytesMut,
}

impl Perform for AnsiStripper<'_> {
    fn print(&mut self, c: char) {
        let mut buf = [0u8; 4];
        self.out
            .extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }

    fn execute(&mut self, byte: u8) {
        if byte == b'\n' {
            self.out.extend_from_slice(b"\n");
        }
    }
}

impl PatternBuffer {
    /// Create a new pattern buffer with the specified search depth.
    ///
    /// # Arguments
    ///
    /// * `search_depth` - Number of bytes from the end to search for patterns.
    ///   Default recommendation is 1000 bytes.
    pub fn new(search_depth: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
            search_depth,
            first_newline: None,
            parser: Parser::new(),
        }
    }

    /// Extend the buffer with new data, stripping ANSI escape codes.
    ///
    /// The VTE parser is reused across calls, so escape sequences that
    /// span multiple SSH data messages are handled correctly. Only `\n`
    /// survives of the control characters: `\r` never reaches the buffer.
    pub fn extend(&mut self, data: &[u8]) {
        let before = self.buffer.len();
        let mut stripper = AnsiStripper {
            out: &mut self.buffer,
        };
        self.parser.advance(&mut stripper, data);
        if self.first_newline.is_none() {
            self.first_newline = memchr::memchr(b'\n', &self.buffer[before..]).map(|i| before + i);
        }
    }

    /// Search only the tail of the buffer for the pattern.
    ///
    /// This is the key optimization from scrapli - we only search the
    /// last `search_depth` bytes, not the entire buffer. The window is
    /// aligned to a line start so `^` cannot match a line fragment.
    ///
    /// The match may be followed by further output: this is for arbitrary
    /// expect patterns (`Password:`, `[confirm]`) that are not necessarily
    /// the last thing on the line. Prompt detection uses
    /// [`search_tail_any`](Self::search_tail_any), which requires the match
    /// to end the buffer.
    ///
    /// Returns the match if found, with byte offsets relative to the
    /// start of the search region (not the full buffer).
    pub fn search_tail(&self, pattern: &Regex) -> Option<regex::bytes::Match<'_>> {
        let start = super::tail_start(&self.buffer, self.search_depth);
        let tail = &self.buffer[start..];
        pattern.find(tail)
    }

    /// Search the tail for any of the given prompt patterns (short-circuits on
    /// first match). A match only counts if nothing but whitespace follows it.
    ///
    /// Avoids the need for a combined mega-regex — each pattern's NFA is small
    /// and cache-friendly, and prompt patterns are mutually exclusive so at
    /// most one will match.
    pub fn search_tail_any(&self, patterns: &[Regex]) -> Option<regex::bytes::Match<'_>> {
        let start = super::tail_start(&self.buffer, self.search_depth);
        let tail = &self.buffer[start..];
        for pattern in patterns {
            if let Some(m) = super::find_trailing(pattern, tail) {
                return Some(m);
            }
        }
        None
    }

    /// Like [`search_tail_any`](Self::search_tail_any), but only accepts a match
    /// that has a newline somewhere before it in the buffer.
    ///
    /// Used when waiting for the prompt that answers a command on a platform
    /// with `prompt_after_newline` set: the device ends the echoed command
    /// line with a newline before the new prompt. Without this, a device that
    /// redraws the input line on each keystroke (`\rPROMPT# q`, `\rPROMPT# qu`,
    /// ... as WaveServer does once prompt plus input is wider than its line
    /// editor; the `\r` is stripped, so the buffer reads `PROMPT# qPROMPT# qu`)
    /// can leave a bare copy of the old prompt at the end of a packet, which
    /// then passes for the reply.
    ///
    /// The newline position is tracked in [`extend`](Self::extend), so this
    /// costs no more than `search_tail_any`.
    pub fn search_tail_any_after_newline(
        &self,
        patterns: &[Regex],
    ) -> Option<regex::bytes::Match<'_>> {
        let nl = self.first_newline?;
        let start = super::tail_start(&self.buffer, self.search_depth);
        let tail = &self.buffer[start..];
        for pattern in patterns {
            if let Some(m) = super::find_trailing(pattern, tail)
                && nl < start + m.start()
            {
                return Some(m);
            }
        }
        None
    }

    /// Search the entire buffer for a pattern.
    ///
    /// Use sparingly - prefer `search_tail` for prompt detection.
    pub fn search_full(&self, pattern: &Regex) -> Option<regex::bytes::Match<'_>> {
        pattern.find(&self.buffer)
    }

    /// Check if the tail contains a pattern match.
    pub fn tail_contains(&self, pattern: &Regex) -> bool {
        self.search_tail(pattern).is_some()
    }

    /// Take ownership of the buffer contents and reset.
    pub fn take(&mut self) -> BytesMut {
        self.first_newline = None;
        std::mem::take(&mut self.buffer)
    }

    /// Get a reference to the buffer contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the buffer contents as a string (lossy UTF-8 conversion).
    pub fn as_str_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.buffer)
    }

    /// Get the current buffer length.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.first_newline = None;
        self.buffer.clear();
    }

    /// Get the search depth setting.
    pub fn search_depth(&self) -> usize {
        self.search_depth
    }
}

impl Default for PatternBuffer {
    fn default() -> Self {
        Self::new(1000)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_extend() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"Hello, world!");
        assert_eq!(buffer.as_slice(), b"Hello, world!");
    }

    #[test]
    fn test_ansi_stripping() {
        let mut buffer = PatternBuffer::new(100);
        // Typical ANSI color code: \x1b[32m (green)
        buffer.extend(b"\x1b[32mGreen text\x1b[0m");
        assert_eq!(buffer.as_slice(), b"Green text");
    }

    #[test]
    fn test_tail_search() {
        let mut buffer = PatternBuffer::new(20);

        // Add 100 bytes of filler
        buffer.extend(&[b'x'; 100]);

        // Add a prompt at the end
        buffer.extend(b"\nrouter#");

        // Search should find the prompt in the tail
        let pattern = Regex::new(r"router#").unwrap();
        assert!(buffer.search_tail(&pattern).is_some());
    }

    #[test]
    fn test_tail_search_not_in_tail() {
        let mut buffer = PatternBuffer::new(10);

        // Add prompt, then lots of filler
        buffer.extend(b"router#");
        buffer.extend(&[b'x'; 100]);

        // Prompt should NOT be found (outside search depth)
        let pattern = Regex::new(r"router#").unwrap();
        assert!(buffer.search_tail(&pattern).is_none());

        // But full search should find it
        assert!(buffer.search_full(&pattern).is_some());
    }

    #[test]
    fn test_take_returns_bytes_mut() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"test data");
        let taken: BytesMut = buffer.take();
        assert_eq!(&taken[..], b"test data");
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_take_is_reusable() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"first");
        let first = buffer.take();
        assert_eq!(&first[..], b"first");

        // Buffer should be reusable after take
        buffer.extend(b"second");
        let second = buffer.take();
        assert_eq!(&second[..], b"second");
    }

    #[test]
    fn test_take_bytes_mut_can_freeze() {
        // Verify the BytesMut from take() can be frozen to Bytes (zero-copy)
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"freezable data");
        let buf = buffer.take();
        let frozen = buf.freeze();
        assert_eq!(&frozen[..], b"freezable data");
    }

    #[test]
    fn test_multiple_extend_accumulates() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"hello ");
        buffer.extend(b"world");
        assert_eq!(buffer.as_slice(), b"hello world");
    }

    #[test]
    fn test_empty_buffer() {
        let buffer = PatternBuffer::new(100);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.as_slice(), b"");
    }

    #[test]
    fn test_default() {
        let buffer = PatternBuffer::default();
        assert_eq!(buffer.search_depth(), 1000);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_tail_contains() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"output\nrouter#");
        let pattern = Regex::new(r"router#").unwrap();
        assert!(buffer.tail_contains(&pattern));
    }

    #[test]
    fn test_clear() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"data");
        assert!(!buffer.is_empty());
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_as_str_lossy_valid_utf8() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"valid utf-8 text");
        let s = buffer.as_str_lossy();
        assert_eq!(&*s, "valid utf-8 text");
    }

    #[test]
    fn test_as_str_lossy_invalid_utf8() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"hello \xff world");
        let s = buffer.as_str_lossy();
        assert!(s.contains("hello"));
        assert!(s.contains("world"));
    }

    #[test]
    fn test_search_after_newline_ignores_redrawn_prompt() {
        let re = Regex::new(r"(?m)(?-u)^[\w.\-]+\*?(?:\([\w.\-/ ]+\))?# ?$").unwrap();
        let patterns = [re];
        let mut buf = PatternBuffer::new(1000);
        // WaveServer redraws the input line per keystroke ("\rPROMPT# q",
        // "\rPROMPT# qu", ...). A packet holding only the start of a redraw
        // leaves a bare copy of the old prompt as the whole buffer.
        buf.extend(b"\rhost.example.com(topology/show)# ");
        assert_eq!(buf.as_slice(), b"host.example.com(topology/show)# ");
        assert!(buf.search_tail_any(&patterns).is_some());
        assert!(buf.search_tail_any_after_newline(&patterns).is_none());
        // the rest of the echo arrives, then the real reply prompt
        buf.extend(b"q\rhost.example.com(topology/show)# quit\r\n\rhost.example.com# ");
        let m = buf.search_tail_any_after_newline(&patterns).unwrap();
        assert_eq!(m.as_bytes(), b"host.example.com# ");
    }

    #[test]
    fn test_search_after_newline_ignores_newline_inside_prompt() {
        // Nokia's two-line prompt carries its own newline; that one does not
        // count as "the echo line has ended".
        let re = Regex::new(r"(?m)(?-u)^\[.*\]\n[A-D]:[\w.@-]+#\s?$").unwrap();
        let patterns = [re];
        let mut buf = PatternBuffer::new(1000);
        buf.extend(b"[/]\nA:admin@router# ");
        assert!(buf.search_tail_any(&patterns).is_some());
        assert!(buf.search_tail_any_after_newline(&patterns).is_none());
        buf.clear();
        buf.extend(b"show version\n[/]\nA:admin@router# ");
        assert!(buf.search_tail_any_after_newline(&patterns).is_some());
    }

    #[test]
    fn test_first_newline_resets_with_buffer() {
        let re = Regex::new(r"(?m)(?-u)^\w+#\s?$").unwrap();
        let patterns = [re];
        let mut buf = PatternBuffer::new(1000);
        buf.extend(b"stale output\nhost# ");
        assert!(buf.search_tail_any_after_newline(&patterns).is_some());
        buf.take();
        buf.extend(b"host# ");
        assert!(buf.search_tail_any_after_newline(&patterns).is_none());
        buf.clear();
        buf.extend(b"host# ");
        assert!(buf.search_tail_any_after_newline(&patterns).is_none());
    }

    #[test]
    fn test_search_tail_matches_expect_pattern_mid_line() {
        // Interactive / auth patterns need not end the buffer.
        let mut buf = PatternBuffer::new(1000);
        buf.extend(b"start shell user root\nPassword: ");
        assert!(buf.search_tail(&Regex::new(r"Password").unwrap()).is_some());
        assert!(
            buf.search_tail(&Regex::new(r"(?mi)(?-u)^password:\s?$").unwrap())
                .is_some()
        );
        buf.clear();
        buf.extend(b"Proceed with reload? [confirm] ");
        assert!(buf.search_tail(&Regex::new(r"confirm").unwrap()).is_some());
    }

    #[test]
    fn test_search_tail_any_requires_prompt_at_end() {
        let re = Regex::new(r"(?m)(?-u)^\w+#\s?$").unwrap();
        let patterns = [re];
        let mut buf = PatternBuffer::new(1000);
        buf.extend(b"host#\nmore output\n");
        assert!(buf.search_tail_any(&patterns).is_none());
        buf.extend(b"host# ");
        assert!(buf.search_tail_any(&patterns).is_some());
    }

    #[test]
    fn test_carriage_return_is_stripped() {
        let mut buf = PatternBuffer::new(1000);
        buf.extend(b"\r\n\rhost# q\rhost# qu\r\n");
        assert_eq!(buf.as_slice(), b"\nhost# qhost# qu\n");
    }
}
