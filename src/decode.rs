//! Layer 0 — byte→line decoding with the truncated-UTF-8 case typed distinctly
//! from genuine corruption.
//!
//! `mod_logfile`'s 2 KiB buffer can chop a multi-byte codepoint mid-character,
//! leaving an incomplete sequence in the byte stream — the byte-level twin of the
//! record-level collision [`ParseStats::lines_split`](crate::ParseStats::lines_split)
//! already models. This layer owns `read_until(b'\n')` so byte→line decoding lives
//! in one place, and reports the truncated case as a benign, recoverable outcome
//! rather than an opaque `io::Error`.

use std::io::{self, BufRead};

/// Outcome of classifying a line's bytes as UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Utf8Decode {
    /// Valid UTF-8 throughout.
    Clean,
    /// One or more incomplete multibyte sequences — `mod_logfile`'s 2 KiB buffer
    /// chopping a codepoint mid-character. Benign and recoverable. `at` is the
    /// byte offset of the first truncation.
    TruncatedCodepoint { at: usize },
    /// A byte that cannot be part of any UTF-8 sequence — genuine corruption.
    /// `at` is the byte offset of the first invalid byte.
    InvalidBytes { at: usize },
}

/// A decoded log line plus the UTF-8 verdict for its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLine {
    /// Lossy-recovered text (U+FFFD for invalid bytes) so the record is preserved.
    pub text: String,
    pub decode: Utf8Decode,
}

/// Classify a line's bytes as UTF-8, distinguishing a truncated codepoint (benign)
/// from a genuinely invalid byte (corruption). Pure; no I/O.
pub fn classify_utf8(line: &[u8]) -> Utf8Decode {
    let mut rest = line;
    let mut base = 0;
    // Latch: first truncation skipped, so an Ok reached after a clean tail still
    // reports TruncatedCodepoint rather than Clean.
    let mut truncated_at: Option<usize> = None;
    loop {
        match std::str::from_utf8(rest) {
            Ok(_) => {
                return match truncated_at {
                    Some(at) => Utf8Decode::TruncatedCodepoint { at },
                    None => Utf8Decode::Clean,
                };
            }
            Err(e) => {
                let valid = e.valid_up_to();
                let at = base + valid;
                match e.error_len() {
                    None => {
                        return Utf8Decode::TruncatedCodepoint {
                            at: truncated_at.unwrap_or(at),
                        };
                    }
                    Some(n) => {
                        let bad = &rest[valid..valid + n];
                        if !is_incomplete_multibyte(bad) {
                            return Utf8Decode::InvalidBytes { at };
                        }
                        truncated_at.get_or_insert(at);
                        base = at + n;
                        rest = &rest[valid + n..];
                    }
                }
            }
        }
    }
}

/// Valid lead byte followed only by valid continuations, shorter than the lead
/// requires — i.e. a codepoint cut short rather than a malformed encoding.
fn is_incomplete_multibyte(seq: &[u8]) -> bool {
    let Some((&lead, cont)) = seq.split_first() else {
        return false;
    };
    let need = match lead {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return false,
    };
    seq.len() < need && cont.iter().all(|&b| (0x80..=0xBF).contains(&b))
}

/// Read newline-delimited log lines, decoding each with the truncated-codepoint
/// case typed distinctly from corruption.
///
/// Real I/O errors stay terminal `io::Error`. UTF-8 invalidity is **not** an
/// error — the line is lossy-recovered (U+FFFD) so the record survives, and the
/// verdict is reported in [`DecodedLine::decode`].
pub fn read_log_lines<R: BufRead>(mut r: R) -> impl Iterator<Item = io::Result<DecodedLine>> {
    std::iter::from_fn(move || {
        let mut buf = Vec::new();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                    if buf.last() == Some(&b'\r') {
                        buf.pop();
                    }
                }
                let decode = classify_utf8(&buf);
                let text = String::from_utf8_lossy(&buf).into_owned();
                Some(Ok(DecodedLine { text, decode }))
            }
            Err(e) => Some(Err(e)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn production_pattern_is_truncated() {
        // e2 80 then ASCII '2' — valid lead + continuation, cut short by a record splice.
        assert_eq!(
            classify_utf8(b"\xe2\x80\x32"),
            Utf8Decode::TruncatedCodepoint { at: 0 }
        );
    }

    #[test]
    fn truncation_then_clean_tail_latches_truncated() {
        // The Ok-after-skip latch: a clean tail must not erase the earlier truncation.
        let line = b"CHANNEL_UN\xe2\x80then a long clean ASCII tail follows here";
        assert_eq!(
            classify_utf8(line),
            Utf8Decode::TruncatedCodepoint { at: 10 }
        );
    }

    #[test]
    fn incomplete_at_end_of_line_is_truncated() {
        assert_eq!(
            classify_utf8(b"\xe2\x80"),
            Utf8Decode::TruncatedCodepoint { at: 0 }
        );
        assert_eq!(
            classify_utf8(b"\xe2"),
            Utf8Decode::TruncatedCodepoint { at: 0 }
        );
    }

    #[test]
    fn malformed_bytes_are_invalid() {
        assert_eq!(classify_utf8(b"\xff"), Utf8Decode::InvalidBytes { at: 0 });
        assert_eq!(classify_utf8(b"\x80"), Utf8Decode::InvalidBytes { at: 0 });
        assert_eq!(
            classify_utf8(b"\xc0\x80"),
            Utf8Decode::InvalidBytes { at: 0 }
        );
    }

    #[test]
    fn genuine_wins_over_earlier_truncation() {
        // Truncation first, then a genuine bad byte — corruption must win.
        match classify_utf8(b"\xe2\x80\x32\xff") {
            Utf8Decode::InvalidBytes { .. } => {}
            other => panic!("expected InvalidBytes, got {other:?}"),
        }
    }

    #[test]
    fn clean_line_is_clean() {
        assert_eq!(classify_utf8("héllo wörld".as_bytes()), Utf8Decode::Clean);
        assert_eq!(classify_utf8(b"plain ascii"), Utf8Decode::Clean);
    }

    #[test]
    fn read_log_lines_reports_per_line_verdict() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"first clean line\n");
        buf.extend_from_slice(b"bad\xe2\x80stuff\n");
        buf.extend_from_slice(b"third clean line\n");

        let lines: Vec<DecodedLine> = read_log_lines(Cursor::new(buf))
            .map(|d| d.expect("no io error"))
            .collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].decode, Utf8Decode::Clean);
        assert_eq!(lines[2].decode, Utf8Decode::Clean);
        match lines[1].decode {
            Utf8Decode::TruncatedCodepoint { .. } => {}
            ref other => panic!("expected TruncatedCodepoint, got {other:?}"),
        }
        // Record preserved with U+FFFD standing in for the chopped codepoint.
        assert!(lines[1].text.starts_with("bad"));
        assert!(lines[1].text.contains('\u{fffd}'));
        assert!(lines[1].text.ends_with("stuff"));
    }
}
