//! Zero-copy response payload backed by `Bytes`.
//!
//! `Payload` wraps a reference-counted `Bytes` buffer and implements
//! `Deref<Target = str>`, so it can be used anywhere a `&str` is expected.
//! UTF-8 is validated once at construction time; all subsequent access is
//! zero-copy.
//!
//! Inspired by netconf-rust's `DataPayload` pattern.

use std::fmt;
use std::ops::Deref;

use bytes::{Bytes, BytesMut};

/// A validated UTF-8 payload backed by reference-counted bytes.
///
/// `Payload` implements `Deref<Target = str>`, so existing code using
/// `.contains()`, `.lines()`, `.trim()`, `println!("{}", payload)`, etc.
/// works unchanged via deref coercion.
///
/// Cloning is O(1) — it increments a reference count rather than copying data.
#[derive(Clone)]
pub struct Payload {
    bytes: Bytes,
}

impl Payload {
    /// Create a `Payload` from a `BytesMut` buffer.
    ///
    /// Fast path (valid UTF-8, ~always): freezes the buffer in place — zero copy.
    /// Slow path (invalid UTF-8, rare): lossy conversion into a new buffer.
    pub(crate) fn from_bytes_mut(buf: BytesMut) -> Self {
        let bytes = if std::str::from_utf8(&buf).is_ok() {
            buf.freeze() // zero copy
        } else {
            Bytes::from(String::from_utf8_lossy(&buf).into_owned())
        };
        Self { bytes }
    }

    /// Create an empty payload.
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            bytes: Bytes::new(),
        }
    }

    /// Get the payload as a `&str` (zero-copy).
    pub fn as_str(&self) -> &str {
        // SAFETY: UTF-8 validated at construction time
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Get the payload as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert into an owned `String` (copies the data).
    pub fn into_string(self) -> String {
        // SAFETY: UTF-8 validated at construction time
        unsafe { String::from_utf8_unchecked(self.bytes.to_vec()) }
    }

    /// Unwrap the inner `Bytes`.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

impl Deref for Payload {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Payload {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.as_str();
        if s.len() > 200 {
            write!(f, "Payload({:?}... [{} bytes])", &s[..200], s.len())
        } else {
            write!(f, "Payload({:?})", s)
        }
    }
}

impl PartialEq<str> for Payload {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Payload {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq for Payload {
    fn eq(&self, other: &Payload) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Payload {}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Construction
    // =========================================================================

    #[test]
    fn test_from_bytes_mut_valid_utf8() {
        let buf = BytesMut::from("hello world");
        let payload = Payload::from_bytes_mut(buf);
        assert_eq!(&*payload, "hello world");
    }

    #[test]
    fn test_from_bytes_mut_invalid_utf8() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"hello \xff world");
        let payload = Payload::from_bytes_mut(buf);
        assert_eq!(&*payload, "hello \u{fffd} world");
    }

    #[test]
    fn test_from_bytes_mut_all_invalid_utf8() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\xff\xfe\xfd");
        let payload = Payload::from_bytes_mut(buf);
        // Should produce replacement characters
        assert_eq!(&*payload, "\u{fffd}\u{fffd}\u{fffd}");
    }

    #[test]
    fn test_from_bytes_mut_empty() {
        let buf = BytesMut::new();
        let payload = Payload::from_bytes_mut(buf);
        assert_eq!(&*payload, "");
        assert!(payload.is_empty());
    }

    #[test]
    fn test_empty() {
        let payload = Payload::empty();
        assert_eq!(&*payload, "");
        assert!(payload.is_empty());
        assert_eq!(payload.len(), 0);
    }

    #[test]
    fn test_from_bytes_mut_zero_copy_path() {
        // Valid UTF-8 should freeze in place (zero-copy)
        let mut buf = BytesMut::with_capacity(100);
        buf.extend_from_slice(b"valid utf-8");
        let ptr_before = buf.as_ptr();
        let payload = Payload::from_bytes_mut(buf);
        // After freeze, the pointer should be the same (zero copy)
        assert_eq!(payload.as_bytes().as_ptr(), ptr_before);
    }

    // =========================================================================
    // Deref<Target = str> coercion
    // =========================================================================

    #[test]
    fn test_deref_str_methods() {
        let payload = Payload::from_bytes_mut(BytesMut::from("line1\nline2\nline3"));
        assert!(payload.contains("line2"));
        assert_eq!(payload.lines().count(), 3);
        assert!(payload.starts_with("line1"));
        assert!(payload.ends_with("line3"));
    }

    #[test]
    fn test_deref_trim() {
        let payload = Payload::from_bytes_mut(BytesMut::from("  hello  "));
        assert_eq!(payload.trim(), "hello");
    }

    #[test]
    fn test_deref_split() {
        let payload = Payload::from_bytes_mut(BytesMut::from("a,b,c"));
        let parts: Vec<&str> = payload.split(',').collect();
        assert_eq!(parts, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_deref_len() {
        let payload = Payload::from_bytes_mut(BytesMut::from("hello"));
        assert_eq!(payload.len(), 5);
    }

    #[test]
    fn test_deref_is_empty() {
        let empty = Payload::from_bytes_mut(BytesMut::new());
        assert!(empty.is_empty());

        let nonempty = Payload::from_bytes_mut(BytesMut::from("x"));
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn test_deref_lines_multiline() {
        let payload = Payload::from_bytes_mut(BytesMut::from(
            "ge-0/0/0  up  up\nge-0/0/1  up  down\nge-0/0/2  down  down",
        ));
        let lines: Vec<&str> = payload.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "ge-0/0/0  up  up");
        assert_eq!(lines[2], "ge-0/0/2  down  down");
    }

    #[test]
    fn test_deref_coercion_to_str_ref() {
        // Payload should coerce to &str in function arguments
        fn takes_str(s: &str) -> usize {
            s.len()
        }
        let payload = Payload::from_bytes_mut(BytesMut::from("test"));
        assert_eq!(takes_str(&payload), 4);
    }

    // =========================================================================
    // Display and Debug
    // =========================================================================

    #[test]
    fn test_display() {
        let payload = Payload::from_bytes_mut(BytesMut::from("test output"));
        assert_eq!(format!("{}", payload), "test output");
    }

    #[test]
    fn test_display_in_format_string() {
        let payload = Payload::from_bytes_mut(BytesMut::from("value"));
        let formatted = format!("result: {}", payload);
        assert_eq!(formatted, "result: value");
    }

    #[test]
    fn test_debug_short() {
        let payload = Payload::from_bytes_mut(BytesMut::from("short"));
        let debug = format!("{:?}", payload);
        assert!(debug.contains("short"));
        assert!(debug.starts_with("Payload("));
    }

    #[test]
    fn test_debug_long_truncates() {
        // Create a payload longer than 200 chars
        let long = "x".repeat(300);
        let payload = Payload::from_bytes_mut(BytesMut::from(long.as_str()));
        let debug = format!("{:?}", payload);
        assert!(debug.contains("300 bytes"));
        assert!(debug.contains("..."));
    }

    // =========================================================================
    // Clone (O(1) ref-counted)
    // =========================================================================

    #[test]
    fn test_clone_is_cheap() {
        let payload = Payload::from_bytes_mut(BytesMut::from("shared data"));
        let cloned = payload.clone();
        assert_eq!(&*payload, &*cloned);
        // Both point to the same underlying data
        assert_eq!(payload.as_bytes().as_ptr(), cloned.as_bytes().as_ptr());
    }

    #[test]
    fn test_clone_independence() {
        // Clones should be independent values (even though they share data)
        let payload = Payload::from_bytes_mut(BytesMut::from("data"));
        let cloned = payload.clone();
        // Dropping original shouldn't affect clone
        drop(payload);
        assert_eq!(&*cloned, "data");
    }

    // =========================================================================
    // Equality
    // =========================================================================

    #[test]
    fn test_partial_eq_str() {
        let payload = Payload::from_bytes_mut(BytesMut::from("hello"));
        assert_eq!(payload, "hello");
        assert!(payload != "world");
    }

    #[test]
    fn test_partial_eq_str_ref() {
        let payload = Payload::from_bytes_mut(BytesMut::from("hello"));
        let s: &str = "hello";
        assert_eq!(payload, s);
    }

    #[test]
    fn test_partial_eq_payload() {
        let a = Payload::from_bytes_mut(BytesMut::from("same"));
        let b = Payload::from_bytes_mut(BytesMut::from("same"));
        assert_eq!(a, b);

        let c = Payload::from_bytes_mut(BytesMut::from("different"));
        assert_ne!(a, c);
    }

    #[test]
    fn test_eq_empty() {
        let a = Payload::empty();
        let b = Payload::from_bytes_mut(BytesMut::new());
        assert_eq!(a, b);
        assert_eq!(a, "");
    }

    // =========================================================================
    // Conversion methods
    // =========================================================================

    #[test]
    fn test_as_str() {
        let payload = Payload::from_bytes_mut(BytesMut::from("test"));
        let s: &str = payload.as_str();
        assert_eq!(s, "test");
    }

    #[test]
    fn test_as_bytes() {
        let payload = Payload::from_bytes_mut(BytesMut::from("test"));
        assert_eq!(payload.as_bytes(), b"test");
    }

    #[test]
    fn test_into_string() {
        let payload = Payload::from_bytes_mut(BytesMut::from("owned"));
        let s: String = payload.into_string();
        assert_eq!(s, "owned");
    }

    #[test]
    fn test_into_bytes() {
        let payload = Payload::from_bytes_mut(BytesMut::from("bytes"));
        let b: Bytes = payload.into_bytes();
        assert_eq!(&b[..], b"bytes");
    }

    // =========================================================================
    // AsRef implementations
    // =========================================================================

    #[test]
    fn test_as_ref_str() {
        let payload = Payload::from_bytes_mut(BytesMut::from("test"));
        let s: &str = payload.as_ref();
        assert_eq!(s, "test");
    }

    #[test]
    fn test_as_ref_u8_slice() {
        let payload = Payload::from_bytes_mut(BytesMut::from("test"));
        let b: &[u8] = payload.as_ref();
        assert_eq!(b, b"test");
    }

    // =========================================================================
    // Real-world usage patterns
    // =========================================================================

    #[test]
    fn test_network_output_lines() {
        let payload = Payload::from_bytes_mut(BytesMut::from(
            "Hostname: router1\nModel: mx240\nJunos: 21.4R3-S5",
        ));
        let lines: Vec<&str> = payload.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(payload.contains("mx240"));
        assert!(payload.contains("router1"));
    }

    #[test]
    fn test_empty_command_output() {
        // Some commands produce no output
        let payload = Payload::from_bytes_mut(BytesMut::new());
        assert!(payload.is_empty());
        assert_eq!(payload.lines().count(), 0);
        assert!(!payload.contains("anything"));
    }

    #[test]
    fn test_large_payload() {
        // Simulate a large BGP table output
        let mut buf = BytesMut::with_capacity(100_000);
        for i in 0..1000 {
            buf.extend_from_slice(format!("10.0.{}.0/24 via 192.168.1.1\n", i % 256).as_bytes());
        }
        let payload = Payload::from_bytes_mut(buf);
        assert_eq!(payload.lines().count(), 1000);
        assert!(payload.contains("10.0.0.0/24"));
        assert!(payload.contains("10.0.255.0/24"));
    }

    #[test]
    fn test_payload_to_string_roundtrip() {
        let original = "test data\nwith lines";
        let payload = Payload::from_bytes_mut(BytesMut::from(original));
        let string = payload.to_string();
        assert_eq!(string, original);
    }
}
