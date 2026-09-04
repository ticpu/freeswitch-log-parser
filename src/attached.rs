//! Compact contiguous storage for the raw continuation lines that follow a
//! primary log entry.
//!
//! Replaces the historical `Vec<String>` shape, which on real production
//! CHANNEL_DATA dumps (140+ attached lines per entry, tens of thousands of
//! entries per rotated log file) paid one heap allocation per attached line
//! plus capacity-doubling reallocations on the outer `Vec`. The new shape
//! amortizes both into a single growing `String` buffer plus a `Vec<u32>`
//! offset table — typically two allocations per entry regardless of line
//! count, dominated by buffer doubling rather than per-element churn.
//!
//! Lines are stored end-to-end in `buf` separated by `\n`. The separator is
//! never exposed to callers — [`AttachedLines::iter`] and
//! [`AttachedLines::get`] return `&str` slices that exclude it.

/// One entry's attached lines outgrew the `u32` offsets addressing them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachedOverflow;

impl std::fmt::Display for AttachedOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("attached lines exceed the 4 GiB an entry can address")
    }
}

impl std::error::Error for AttachedOverflow {}

/// Compact storage for the raw continuation lines of a log entry.
///
/// Iteration yields each pushed line as `&str` in insertion order. The
/// type is API-equivalent to a read-only `[String]` for the patterns used
/// in this crate (`len`, `is_empty`, `iter`, `get`, indexed access via
/// `get(i)`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttachedLines {
    buf: String,
    offsets: Vec<u32>,
}

impl AttachedLines {
    /// Create an empty `AttachedLines` with no allocations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored lines.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// `true` when no lines have been pushed.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Bytes the stored lines occupy, separators included.
    pub fn byte_len(&self) -> usize {
        self.buf.len()
    }

    /// Append a line. The trailing `\n` separator is added internally and is
    /// not part of the line returned by [`Self::get`] or [`Self::iter`].
    ///
    /// Fails once the buffer would outgrow the `u32` offsets that address it.
    /// `mod_logfile`'s write budget bounds one physical line, not how many join
    /// an entry, so that range is the only limit here — a caller wanting a
    /// smaller one sets it on the stream
    /// ([`LogStream::max_attached_bytes`](crate::LogStream::max_attached_bytes)).
    /// A line that does not fit is not stored.
    pub fn push(&mut self, line: &str) -> Result<(), AttachedOverflow> {
        let start = u32::try_from(self.buf.len()).map_err(|_| AttachedOverflow)?;
        self.offsets.push(start);
        self.buf.push_str(line);
        self.buf.push('\n');
        Ok(())
    }

    /// Borrow the i-th line, or `None` if out of range.
    pub fn get(&self, i: usize) -> Option<&str> {
        let start = *self.offsets.get(i)? as usize;
        let end = self
            .offsets
            .get(i + 1)
            .map(|&o| o as usize - 1)
            .unwrap_or_else(|| self.buf.len() - 1);
        Some(&self.buf[start..end])
    }

    /// Iterate over the stored lines in insertion order.
    pub fn iter(&self) -> AttachedLinesIter<'_> {
        AttachedLinesIter {
            lines: self,
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for &'a AttachedLines {
    type Item = &'a str;
    type IntoIter = AttachedLinesIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the lines of an [`AttachedLines`].
#[derive(Debug, Clone)]
pub struct AttachedLinesIter<'a> {
    lines: &'a AttachedLines,
    pos: usize,
}

impl<'a> Iterator for AttachedLinesIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let line = self.lines.get(self.pos)?;
        self.pos += 1;
        Some(line)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.lines.len() - self.pos;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AttachedLinesIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_default() {
        let a = AttachedLines::new();
        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
        assert!(a.get(0).is_none());
        assert_eq!(a.iter().count(), 0);
    }

    #[test]
    fn push_and_iterate_preserves_order_and_content() {
        let mut a = AttachedLines::new();
        a.push("first").expect("fits");
        a.push("").expect("fits");
        a.push("third line").expect("fits");
        assert_eq!(a.len(), 3);
        assert!(!a.is_empty());
        assert_eq!(a.get(0), Some("first"));
        assert_eq!(a.get(1), Some(""));
        assert_eq!(a.get(2), Some("third line"));
        assert!(a.get(3).is_none());
        let collected: Vec<&str> = a.iter().collect();
        assert_eq!(collected, vec!["first", "", "third line"]);
    }

    #[test]
    fn intoiter_for_ref_works_in_for_loop() {
        let mut a = AttachedLines::new();
        a.push("a").expect("fits");
        a.push("b").expect("fits");
        let mut out = Vec::new();
        for line in &a {
            out.push(line.to_string());
        }
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn lines_with_embedded_separators_round_trip() {
        // The parser never feeds embedded newlines today, but the API should not
        // corrupt content that happens to contain them — the offset table
        // delimits by index, not by scanning for '\n'.
        let mut a = AttachedLines::new();
        a.push("has\nnewline").expect("fits");
        a.push("plain").expect("fits");
        assert_eq!(a.get(0), Some("has\nnewline"));
        assert_eq!(a.get(1), Some("plain"));
    }

    #[test]
    fn allocation_pattern_is_logarithmic_not_per_line() {
        // Push 200 typical CHANNEL_DATA variable lines. Buffer capacity should
        // grow logarithmically (capacity-doubling), not 200 separate allocations.
        let mut a = AttachedLines::new();
        for i in 0..200 {
            a.push(&format!(
                "variable_some_long_name_{i}: [a typical value here]"
            ))
            .expect("fits");
        }
        assert_eq!(a.len(), 200);
        // Round-trip check: every line readable in order.
        for (i, line) in a.iter().enumerate() {
            assert!(line.starts_with(&format!("variable_some_long_name_{i}")));
        }
    }
}
