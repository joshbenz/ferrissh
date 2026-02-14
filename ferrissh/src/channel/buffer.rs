//! Pattern buffer with efficient tail-search optimization.
//!
//! This implements scrapli's key optimization: only search the last N bytes
//! of the buffer for prompt patterns, rather than the entire output.
//!
//! For large outputs (e.g., full BGP tables), this is critical for performance.

use regex::bytes::Regex;

/// Buffer for accumulating output and efficiently searching for patterns.
///
/// Uses scrapli's optimization of only searching the tail of the buffer
/// for prompt patterns, making it efficient for large command outputs.
#[derive(Debug)]
pub struct PatternBuffer {
    /// The accumulated output buffer.
    buffer: Vec<u8>,

    /// How many bytes from the end to search for patterns.
    /// Default is 1000 bytes.
    search_depth: usize,
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
            buffer: Vec::with_capacity(4096),
            search_depth,
        }
    }

    /// Extend the buffer with new data, stripping ANSI escape codes.
    pub fn extend(&mut self, data: &[u8]) {
        // Strip ANSI escape codes using the vte-based crate
        let cleaned = strip_ansi_escapes::strip(data);
        self.buffer.extend_from_slice(&cleaned);
    }

    /// Search only the tail of the buffer for the pattern.
    ///
    /// This is the key optimization from scrapli - we only search the
    /// last `search_depth` bytes, not the entire buffer.
    ///
    /// Returns the match if found, with byte offsets relative to the
    /// start of the search region (not the full buffer).
    pub fn search_tail(&self, pattern: &Regex) -> Option<regex::bytes::Match<'_>> {
        let start = self.buffer.len().saturating_sub(self.search_depth);
        let tail = &self.buffer[start..];
        pattern.find(tail)
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
    pub fn take(&mut self) -> Vec<u8> {
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
    fn test_take_clears_buffer() {
        let mut buffer = PatternBuffer::new(100);
        buffer.extend(b"test data");
        assert_eq!(buffer.take(), b"test data");
        assert!(buffer.is_empty());
    }
}
