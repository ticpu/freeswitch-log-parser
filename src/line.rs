pub(crate) use crate::uuid::{is_uuid_at, UUID_PREFIX_LEN};
use freeswitch_types::LogLevel;

use crate::mask::Mask;
use crate::uuid::{find_uuid_in, UUID_LEN};

use std::fmt;
use std::ops::Range;

/// Classification of a single log line's structural format.
///
/// FreeSWITCH's `switch_log_printf` emits five distinct line shapes depending
/// on whether a session UUID is active, whether the line has a timestamp, and
/// whether a buffer collision truncated the output. The full line-shape
/// anatomy is documented in the repository's CLAUDE.md.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// Format A — UUID, timestamp, idle%, level, source, and message.
    Full,
    /// Format B — same as `Full` but without a UUID prefix (system/global events).
    System,
    /// Format C — UUID and message only, no timestamp or level.
    UuidContinuation,
    /// Format D — raw text with no UUID or timestamp; inherits context from the previous entry.
    BareContinuation,
    /// Format E — buffer collision produced a garbage prefix before the UUID.
    Truncated,
    /// Blank or whitespace-only line.
    Empty,
}

impl fmt::Display for LineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LineKind::Full => f.pad("full"),
            LineKind::System => f.pad("system"),
            LineKind::UuidContinuation => f.pad("uuid-cont"),
            LineKind::BareContinuation => f.pad("bare-cont"),
            LineKind::Truncated => f.pad("truncated"),
            LineKind::Empty => f.pad("empty"),
        }
    }
}

/// Zero-copy result of parsing a single log line.
///
/// Fields are `None` when the line's format doesn't include them (e.g. a
/// `BareContinuation` has no `uuid`, `timestamp`, `level`, or `source`).
/// The `message` field always contains the remaining text.
#[derive(Debug, PartialEq, Eq)]
pub struct RawLine<'a> {
    /// Session UUID, present for `Full`, `UuidContinuation`, and `Truncated` lines.
    pub uuid: Option<&'a str>,
    /// Microsecond-precision timestamp, present only for `Full` and `System` lines.
    pub timestamp: Option<&'a str>,
    /// Core scheduler idle percentage (e.g. `"95.97%"`), a system health indicator.
    pub idle_pct: Option<&'a str>,
    /// Log severity, present only for `Full` and `System` lines.
    pub level: Option<LogLevel>,
    /// Source file and line (e.g. `"sofia.c:7624"`), present only for `Full` and `System` lines.
    pub source: Option<&'a str>,
    /// The message text after all structured fields have been consumed.
    pub message: &'a str,
    /// Which of the five line formats this line matched.
    pub kind: LineKind,
}

pub(crate) fn is_date_at(bytes: &[u8], offset: usize) -> bool {
    if bytes.len() < offset + 5 {
        return false;
    }
    bytes[offset..offset + 4].iter().all(u8::is_ascii_digit) && bytes[offset + 4] == b'-'
}

/// `YYYY-MM-DD HH:MM:SS.ffffff`, the width `mod_logfile` writes.
const TIMESTAMP_LEN: usize = 26;

const TIMESTAMP_MASK: Mask = Mask {
    len: TIMESTAMP_LEN,
    separators: &[
        (4, b'-'),
        (7, b'-'),
        (10, b' '),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
    ],
    filler: u8::is_ascii_digit,
};

/// Widest idle field the logger can write, `"100.00%"`.
const MAX_IDLE_PCT_LEN: usize = 7;

/// Where a FreeSWITCH log header's fields sit, as offsets into the bytes it
/// was found in.
pub(crate) struct HeaderSpan {
    timestamp: Range<usize>,
    idle_pct: Option<Range<usize>>,
    /// Offset of the `[` opening the level.
    level: usize,
}

/// The `D+.D+%` idle field at `from`. The logger writes it followed by a
/// space, so anything else there is not one.
fn idle_pct_span(bytes: &[u8], from: usize) -> Option<Range<usize>> {
    let end = (from + MAX_IDLE_PCT_LEN).min(bytes.len());
    let window = bytes.get(from..end)?;
    let pct = window.iter().position(|&b| b == b'%')?;
    if !window[0].is_ascii_digit()
        || !window[..pct]
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b'.')
    {
        return None;
    }
    (bytes.get(from + pct + 1) == Some(&b' ')).then(|| from..from + pct + 1)
}

/// The spans of a full FreeSWITCH log header at `offset`:
/// `YYYY-MM-DD HH:MM:SS.ffffff [D+.D+% ][LEVEL]`.
///
/// The idle percentage is optional — older/eSInet FS builds omit it and emit
/// `[LEVEL]` directly after the timestamp — but the level bracket is not, so a
/// line the logger cut before it reads as no header rather than as one with an
/// idle field and nothing else.
pub(crate) fn header_at(bytes: &[u8], offset: usize) -> Option<HeaderSpan> {
    if !TIMESTAMP_MASK.matches_at(bytes, offset) || bytes.get(offset + TIMESTAMP_LEN) != Some(&b' ')
    {
        return None;
    }

    let after_stamp = offset + TIMESTAMP_LEN + 1;
    let idle_pct = idle_pct_span(bytes, after_stamp);
    let level = idle_pct.as_ref().map_or(after_stamp, |r| r.end + 1);
    if bytes.get(level) != Some(&b'[') {
        return None;
    }

    Some(HeaderSpan {
        timestamp: offset..offset + TIMESTAMP_LEN,
        idle_pct,
        level,
    })
}

/// Longest name in the switch's `LEVELS[]`, `"CONSOLE"`.
const MAX_LEVEL_LEN: usize = 7;

/// Whether the `[` at `level` closes over a name the field can hold.
fn level_field_closes(bytes: &[u8], level: usize) -> bool {
    let end = (level + MAX_LEVEL_LEN + 2).min(bytes.len());
    bytes
        .get(level + 1..end)
        .and_then(|w| w.iter().position(|&b| b == b']'))
        .is_some_and(|p| p > 0)
}

/// Whether a complete FreeSWITCH log header starts at `offset`.
///
/// Used by Layer 2 to detect same-line collisions where multiple log entries
/// were concatenated without a newline (thread contention on file write, or a
/// caller format string missing its trailing `\n`). A record starts only at a
/// header whose level field closes: an open bracket is a header the write
/// budget cut, and splitting there invents a boundary the file does not hold.
pub(crate) fn is_log_header_at(bytes: &[u8], offset: usize) -> bool {
    header_at(bytes, offset).is_some_and(|h| level_field_closes(bytes, h.level))
}

/// The [`LogLevel`] inside a header's `[LEVEL]` field, or `None` when the
/// brackets are missing or hold no level the switch knows.
///
/// `LogLevel`'s own `FromStr` is the switch's case-sensitive `LEVELS[]` lookup
/// and the log spells the level in upper case, so the names are compared here
/// instead: folding the name would allocate on every header line.
pub fn level_from_bracketed(s: &str) -> Option<LogLevel> {
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    LogLevel::ALL
        .iter()
        .find(|l| l.as_str().eq_ignore_ascii_case(inner))
        .copied()
}

/// The header slices at bytes 26/27 (timestamp + separating space) are only
/// valid when both land on char boundaries — a multi-byte char straddling
/// either offset means the line is not a Format A/B header.
fn header_boundaries_ok(s: &str) -> bool {
    s.len() < 27 || (s.is_char_boundary(26) && s.is_char_boundary(27))
}

/// The structured fields of a timestamped line, each `None` where the line
/// stops short of it.
struct LineHeader<'a> {
    timestamp: Option<&'a str>,
    idle_pct: Option<&'a str>,
    level: Option<LogLevel>,
    source: Option<&'a str>,
    message: &'a str,
}

fn parse_timestamped_fields(s: &str) -> LineHeader<'_> {
    if s.len() < TIMESTAMP_LEN + 1 {
        return LineHeader {
            timestamp: None,
            idle_pct: None,
            level: None,
            source: None,
            message: s,
        };
    }
    let (timestamp, idle_pct, rest) = match header_at(s.as_bytes(), 0) {
        Some(h) => (&s[h.timestamp], h.idle_pct.map(|r| &s[r]), &s[h.level..]),
        None => (&s[..TIMESTAMP_LEN], None, &s[TIMESTAMP_LEN + 1..]),
    };
    let timestamp = Some(timestamp);

    let bracket_end = match rest.find(']') {
        Some(p) => p,
        None => {
            return LineHeader {
                timestamp,
                idle_pct,
                level: None,
                source: None,
                message: rest,
            }
        }
    };
    let level = level_from_bracketed(&rest[0..=bracket_end]);

    if rest.len() < bracket_end + 3 || !rest.is_char_boundary(bracket_end + 2) {
        return LineHeader {
            timestamp,
            idle_pct,
            level,
            source: None,
            message: "",
        };
    }
    let rest = &rest[bracket_end + 2..];

    let source_end = rest.find(' ').unwrap_or(rest.len());
    let message = if source_end < rest.len() {
        &rest[source_end + 1..]
    } else {
        ""
    };

    LineHeader {
        timestamp,
        idle_pct,
        level,
        source: Some(&rest[0..source_end]),
        message,
    }
}

/// Layer 1 entry point: classify a single line and extract its fields.
///
/// Pure function — no state, no allocation. All returned string slices borrow
/// from the input. Use [`classify_message`](crate::classify_message) on the
/// `message` field for semantic classification.
pub fn parse_line(line: &str) -> RawLine<'_> {
    if line.trim().is_empty() {
        return RawLine {
            uuid: None,
            timestamp: None,
            idle_pct: None,
            level: None,
            source: None,
            message: line,
            kind: LineKind::Empty,
        };
    }

    let bytes = line.as_bytes();

    if is_uuid_at(bytes, 0) {
        let uuid = &line[0..UUID_LEN];
        let after_uuid = &line[UUID_PREFIX_LEN..];

        if is_date_at(bytes, UUID_PREFIX_LEN) && header_boundaries_ok(after_uuid) {
            let h = parse_timestamped_fields(after_uuid);
            return RawLine {
                uuid: Some(uuid),
                timestamp: h.timestamp,
                idle_pct: h.idle_pct,
                level: h.level,
                source: h.source,
                message: h.message,
                kind: LineKind::Full,
            };
        }

        return RawLine {
            uuid: Some(uuid),
            timestamp: None,
            idle_pct: None,
            level: None,
            source: None,
            message: after_uuid,
            kind: LineKind::UuidContinuation,
        };
    }

    if is_date_at(bytes, 0) && header_boundaries_ok(line) {
        let h = parse_timestamped_fields(line);
        let (uuid, message) = if is_uuid_at(h.message.as_bytes(), 0) {
            (Some(&h.message[0..UUID_LEN]), &h.message[UUID_PREFIX_LEN..])
        } else {
            (None, h.message)
        };
        return RawLine {
            uuid,
            timestamp: h.timestamp,
            idle_pct: h.idle_pct,
            level: h.level,
            source: h.source,
            message,
            kind: LineKind::System,
        };
    }

    if let Some(uuid_start) = find_uuid_in(bytes) {
        let uuid = &line[uuid_start..uuid_start + UUID_LEN];
        let message = if line.len() > uuid_start + UUID_PREFIX_LEN {
            &line[uuid_start + UUID_PREFIX_LEN..]
        } else {
            ""
        };
        return RawLine {
            uuid: Some(uuid),
            timestamp: None,
            idle_pct: None,
            level: None,
            source: None,
            message,
            kind: LineKind::Truncated,
        };
    }

    RawLine {
        uuid: None,
        timestamp: None,
        idle_pct: None,
        level: None,
        source: None,
        message: line,
        kind: LineKind::BareContinuation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    // --- Format A (Full) ---

    #[test]
    fn full_line_all_fields() {
        let line = format!(
            "{UUID1} 2025-01-15 10:30:45.123456 95.97% [DEBUG] sofia.c:100 Test message here"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Full);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, Some("95.97%"));
        assert_eq!(parsed.level, Some(LogLevel::Debug));
        assert_eq!(parsed.source, Some("sofia.c:100"));
        assert_eq!(parsed.message, "Test message here");
    }

    #[test]
    fn full_line_each_level() {
        for (name, expected) in [
            ("DEBUG", LogLevel::Debug),
            ("INFO", LogLevel::Info),
            ("NOTICE", LogLevel::Notice),
            ("WARNING", LogLevel::Warning),
            ("ERR", LogLevel::Error),
            ("CRIT", LogLevel::Crit),
            ("ALERT", LogLevel::Alert),
            ("CONSOLE", LogLevel::Console),
        ] {
            let line =
                format!("{UUID1} 2025-01-15 10:30:45.123456 95.97% [{name}] sofia.c:100 Test");
            let parsed = parse_line(&line);
            assert_eq!(parsed.kind, LineKind::Full);
            assert_eq!(parsed.level, Some(expected), "failed for [{name}]");
        }
    }

    #[test]
    fn full_line_high_idle() {
        let line =
            format!("{UUID1} 2025-01-15 10:30:45.123456 99.99% [DEBUG] sofia.c:100 High idle");
        let parsed = parse_line(&line);
        assert_eq!(parsed.idle_pct, Some("99.99%"));
    }

    #[test]
    fn full_line_low_idle() {
        let line = format!("{UUID1} 2025-01-15 10:30:45.123456 0.00% [DEBUG] sofia.c:100 Low idle");
        let parsed = parse_line(&line);
        assert_eq!(parsed.idle_pct, Some("0.00%"));
    }

    /// The field is written `"% "`. Without the space it is not one, and
    /// reporting it as one claimed a scheduler reading off a corrupt line.
    #[test]
    fn idle_pct_requires_the_space_after_the_sign() {
        let line = format!("{UUID1} 2025-01-15 10:30:45.123456 9%X[DEBUG] sofia.c:100 Message");
        assert_eq!(parse_line(&line).idle_pct, None);
    }

    #[test]
    fn full_line_long_message() {
        let line = format!(
            "{UUID1} 2025-01-15 10:30:45.123456 95.97% [DEBUG] sofia.c:100 Channel [sofia/internal] key=val:123 (test) {{braces}}"
        );
        let parsed = parse_line(&line);
        assert_eq!(
            parsed.message,
            "Channel [sofia/internal] key=val:123 (test) {braces}"
        );
    }

    // --- Format B (System) ---

    #[test]
    fn system_line_no_uuid() {
        let line =
            "2025-01-15 10:30:45.123456 95.97% [INFO] mod_event_socket.c:1772 Event Socket command";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.uuid, None);
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, Some("95.97%"));
        assert_eq!(parsed.level, Some(LogLevel::Info));
        assert_eq!(parsed.source, Some("mod_event_socket.c:1772"));
        assert_eq!(parsed.message, "Event Socket command");
    }

    #[test]
    fn system_line_with_embedded_uuid() {
        let line = format!(
            "2025-01-15 10:30:45.123456 95.97% [DEBUG] switch_cpp.cpp:1466 {UUID1} DAA-LOG WaveManager PSAP 911 originate"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.level, Some(LogLevel::Debug));
        assert_eq!(parsed.source, Some("switch_cpp.cpp:1466"));
        assert_eq!(parsed.message, "DAA-LOG WaveManager PSAP 911 originate");
    }

    #[test]
    fn system_line_with_embedded_uuid_empty_message() {
        let line = format!("2025-01-15 10:30:45.123456 95.97% [INFO] switch_cpp.cpp:1466 {UUID1} ");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.message, "");
    }

    #[test]
    fn system_line_without_embedded_uuid() {
        let line =
            "2025-01-15 10:30:45.123456 95.97% [INFO] mod_event_socket.c:1772 Event Socket command";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.uuid, None);
        assert_eq!(parsed.message, "Event Socket command");
    }

    #[test]
    fn system_line_event_socket() {
        let line = "2025-01-15 10:30:45.123456 95.97% [NOTICE] mod_logfile.c:217 New log started.";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.level, Some(LogLevel::Notice));
        assert_eq!(parsed.message, "New log started.");
    }

    // --- Format C (UuidContinuation) ---

    #[test]
    fn uuid_continuation_dialplan() {
        let line =
            format!("{UUID1} Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, None);
        assert_eq!(parsed.level, None);
        assert_eq!(
            parsed.message,
            "Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]"
        );
    }

    #[test]
    fn uuid_continuation_execute() {
        let line =
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(
            parsed.message,
            "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"
        );
    }

    #[test]
    fn uuid_continuation_channel_var() {
        let line = format!("{UUID1} Channel-State: [CS_EXECUTE]");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.message, "Channel-State: [CS_EXECUTE]");
    }

    #[test]
    fn uuid_continuation_variable() {
        let line = format!("{UUID1} variable_sip_call_id: [test123@192.0.2.1]");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.message, "variable_sip_call_id: [test123@192.0.2.1]");
    }

    #[test]
    fn uuid_continuation_blank() {
        let line = format!("{UUID1} ");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.message, "");
    }

    // --- Format D (BareContinuation) ---

    #[test]
    fn bare_variable() {
        let line = "variable_foo: [bar]";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.uuid, None);
        assert_eq!(parsed.message, "variable_foo: [bar]");
    }

    #[test]
    fn bare_sdp_origin() {
        let line = "o=- 1234 5678 IN IP4 192.0.2.1";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn bare_sdp_media() {
        let line = "m=audio 47758 RTP/AVP 0 101";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn bare_sdp_attribute() {
        let line = "a=rtpmap:0 PCMU/8000";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn bare_closing_bracket() {
        let line = "]";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, "]");
    }

    #[test]
    fn bare_empty_line() {
        let parsed = parse_line("");
        assert_eq!(parsed.kind, LineKind::Empty);
        assert_eq!(parsed.message, "");
    }

    // --- Format E (Truncated) ---

    #[test]
    fn truncated_varia_prefix() {
        let line = format!(
            "varia{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Truncated);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(
            parsed.message,
            "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
        );
    }

    #[test]
    fn truncated_variab_prefix() {
        let line = format!(
            "variab{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Truncated);
        assert_eq!(parsed.uuid, Some(UUID1));
    }

    #[test]
    fn truncated_var_prefix() {
        let line =
            format!("var{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Truncated);
        assert_eq!(parsed.uuid, Some(UUID1));
    }

    #[test]
    fn truncated_variable_prefix() {
        let line = format!(
            "variable{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Truncated);
        assert_eq!(parsed.uuid, Some(UUID1));
    }

    // --- level_from_bracketed ---

    #[test]
    fn bracketed_level_folds_the_log_spelling() {
        assert_eq!(level_from_bracketed("[DEBUG]"), Some(LogLevel::Debug));
        assert_eq!(level_from_bracketed("[ERR]"), Some(LogLevel::Error));
        assert_eq!(level_from_bracketed("[CONSOLE]"), Some(LogLevel::Console));
    }

    #[test]
    fn bracketed_level_reads_any_case() {
        assert_eq!(level_from_bracketed("[debug]"), Some(LogLevel::Debug));
        assert_eq!(level_from_bracketed("[Warning]"), Some(LogLevel::Warning));
    }

    #[test]
    fn bracketed_level_rejects_malformed() {
        assert_eq!(level_from_bracketed("[FAKE]"), None);
        assert_eq!(level_from_bracketed("DEBUG"), None);
        assert_eq!(level_from_bracketed("[]"), None);
        assert_eq!(level_from_bracketed("["), None);
        assert_eq!(level_from_bracketed(""), None);
    }

    /// Least severe compares greatest, so `>= Debug` admits everything.
    #[test]
    fn levels_order_by_switch_log_level_numbering() {
        assert!(LogLevel::Console < LogLevel::Alert);
        assert!(LogLevel::Error < LogLevel::Warning);
        assert!(LogLevel::Info < LogLevel::Debug);
    }

    // --- is_log_header_at (collision split marker) ---

    #[test]
    fn log_header_with_idle_pct() {
        let line = "2024-04-02 10:31:28.785679 98.03% [NOTICE] sofia.c:1114 Hangup";
        assert!(is_log_header_at(line.as_bytes(), 0));
    }

    #[test]
    fn log_header_no_idle_pct() {
        // Older/eSInet FS builds emit "[LEVEL]" directly after the timestamp.
        let line = "2024-04-02 10:31:28.785679 [NOTICE] sofia.c:1114 Hangup";
        assert!(is_log_header_at(line.as_bytes(), 0));
    }

    #[test]
    fn log_header_no_idle_pct_at_offset() {
        let line = "Session does not exist, aborting REFER.2024-04-02 10:31:28.785679 [WARNING] sofia_presence.c:4546 x";
        let offset = line.find("2024").unwrap();
        assert!(is_log_header_at(line.as_bytes(), offset));
    }

    /// The logger writes the idle field with `"%0.2f"`, so a run of anything
    /// else before the sign is not one — and reading it as one claimed a
    /// scheduler figure off text that never held one.
    #[test]
    fn idle_pct_rejects_non_numeric_run() {
        let line = "2025-01-15 10:30:45.123456 ab% [DEBUG] sofia.c:100 Message";
        assert!(!is_log_header_at(line.as_bytes(), 0));
        assert_eq!(parse_line(line).idle_pct, None);
    }

    /// A header the write budget cut after the idle field carries no level, so
    /// it is no header — and no idle reading either.
    #[test]
    fn idle_pct_needs_the_level_after_it() {
        let line = "2025-01-15 10:30:45.123456 95.97%";
        assert!(!is_log_header_at(line.as_bytes(), 0));
        assert_eq!(parse_line(line).idle_pct, None);
    }

    /// A cut that lands inside the level field leaves a bracket that never
    /// closes; the reading of the fields before it still stands.
    #[test]
    fn a_header_cut_inside_the_level_starts_no_record() {
        for line in [
            "2025-01-15 10:30:45.123456 95.97% [",
            "2025-01-15 10:30:45.123456 95.97% [DEB",
            "2025-01-15 10:30:45.123456 [",
        ] {
            assert!(!is_log_header_at(line.as_bytes(), 0), "split on {line}");
        }
        let cut = "2025-01-15 10:30:45.123456 95.97% [";
        assert_eq!(parse_line(cut).idle_pct, Some("95.97%"));
    }

    #[test]
    fn log_header_rejects_non_header() {
        let line = "2024-04-02 not a real timestamp here";
        assert!(!is_log_header_at(line.as_bytes(), 0));
    }

    // --- No idle percentage (issue #1) ---

    #[test]
    fn full_line_no_idle_pct() {
        let line = format!(
            "{UUID1} 2025-01-15 10:30:45.123456 [NOTICE] switch_core_session.c:1744 Session 3178948 ended"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Full);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, None);
        assert_eq!(parsed.level, Some(LogLevel::Notice));
        assert_eq!(parsed.source, Some("switch_core_session.c:1744"));
        assert_eq!(parsed.message, "Session 3178948 ended");
    }

    #[test]
    fn full_line_no_idle_pct_url_encoded_percent() {
        let line = format!(
            "{UUID1} 2025-01-15 10:30:45.123456 [NOTICE] switch_core_session.c:1744 Session 3178948 (sofia/psap/gw%2Bsg1vofswb-inbound@198.51.100.5:5060) Ended"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Full);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, None);
        assert_eq!(parsed.level, Some(LogLevel::Notice));
        assert_eq!(parsed.source, Some("switch_core_session.c:1744"));
        assert_eq!(
            parsed.message,
            "Session 3178948 (sofia/psap/gw%2Bsg1vofswb-inbound@198.51.100.5:5060) Ended"
        );
    }

    #[test]
    fn system_line_no_idle_pct() {
        let line = "2025-01-15 10:30:45.123456 [INFO] mod_event_socket.c:1772 Event Socket command";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.uuid, None);
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, None);
        assert_eq!(parsed.level, Some(LogLevel::Info));
        assert_eq!(parsed.source, Some("mod_event_socket.c:1772"));
        assert_eq!(parsed.message, "Event Socket command");
    }

    #[test]
    fn full_line_no_idle_pct_hangup_url_encoded() {
        let line = format!(
            "{UUID1} 2025-01-15 10:30:45.123456 [NOTICE] sofia.c:1089 Hangup sofia/psap/gw%2Bgateway@198.51.100.5:5060 [CS_EXCHANGE_MEDIA] [CALL_AWARDED_DELIVERED]"
        );
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::Full);
        assert_eq!(parsed.idle_pct, None);
        assert_eq!(parsed.level, Some(LogLevel::Notice));
        assert_eq!(parsed.source, Some("sofia.c:1089"));
        assert_eq!(
            parsed.message,
            "Hangup sofia/psap/gw%2Bgateway@198.51.100.5:5060 [CS_EXCHANGE_MEDIA] [CALL_AWARDED_DELIVERED]"
        );
    }

    // --- Edge cases ---

    #[test]
    fn not_uuid_36_chars() {
        let line = "this-is-not-a-valid-uuid-value-12345 rest of line";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn uuid_in_message_not_prefix() {
        let line =
            format!("This is some log message body with extra context then {UUID1} appears here");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.message, line.as_str());
    }

    #[test]
    fn whitespace_only_is_empty() {
        let parsed = parse_line("   \t  ");
        assert_eq!(parsed.kind, LineKind::Empty);
    }

    // --- Multi-byte content at fixed header offsets (must not panic) ---

    #[test]
    fn multibyte_straddling_timestamp_end_not_system() {
        // 'é' occupies bytes 25-26: slicing the timestamp at 26 splits it.
        let line = "2025-01-15 10:30:45.12345é more content following here";
        assert!(!line.is_char_boundary(26));
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.timestamp, None);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn multibyte_after_timestamp_not_system() {
        // 'é' occupies bytes 26-27: slicing the message start at 27 splits it.
        let line = "2025-01-15 10:30:45.123456é more content following here";
        assert!(!line.is_char_boundary(27));
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::BareContinuation);
        assert_eq!(parsed.timestamp, None);
        assert_eq!(parsed.message, line);
    }

    #[test]
    fn multibyte_after_uuid_timestamp_is_continuation() {
        let line = format!("{UUID1} 2025-01-15 10:30:45.123456é more content");
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, LineKind::UuidContinuation);
        assert_eq!(parsed.uuid, Some(UUID1));
        assert_eq!(parsed.timestamp, None);
        assert_eq!(parsed.message, "2025-01-15 10:30:45.123456é more content");
    }

    #[test]
    fn multibyte_after_idle_pct_degrades() {
        // 'é' where the "% " separator's trailing space should be.
        let line = "2025-01-15 10:30:45.123456 9%é[DEBUG] x";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, None);
        assert_eq!(parsed.level, None);
    }

    #[test]
    fn multibyte_after_level_bracket_degrades() {
        // 'é' where the "] " separator's trailing space should be.
        let line = "2025-01-15 10:30:45.123456 95.97% [DEBUG]éxx";
        let parsed = parse_line(line);
        assert_eq!(parsed.kind, LineKind::System);
        assert_eq!(parsed.timestamp, Some("2025-01-15 10:30:45.123456"));
        assert_eq!(parsed.idle_pct, Some("95.97%"));
        assert_eq!(parsed.level, Some(LogLevel::Debug));
        assert_eq!(parsed.source, None);
        assert_eq!(parsed.message, "");
    }
}
