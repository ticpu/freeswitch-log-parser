use crate::level::LogLevel;

use std::fmt;

/// Classification of a single log line's structural format.
///
/// FreeSWITCH's `switch_log_printf` emits five distinct line shapes depending
/// on whether a session UUID is active, whether the line has a timestamp, and
/// whether a buffer collision truncated the output. See `docs/design-rationale.md`
/// for the full anatomy.
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

pub(crate) fn is_uuid_at(bytes: &[u8], offset: usize) -> bool {
    if bytes.len() < offset + 37 {
        return false;
    }
    if bytes[offset + 36] != b' ' {
        return false;
    }
    for (i, &b) in bytes[offset..offset + 36].iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn find_uuid_in(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 37 {
        return None;
    }
    let max_start = (bytes.len() - 37).min(50);
    (1..=max_start).find(|&start| is_uuid_at(bytes, start))
}

pub(crate) fn is_date_at(bytes: &[u8], offset: usize) -> bool {
    if bytes.len() < offset + 5 {
        return false;
    }
    bytes[offset..offset + 4].iter().all(u8::is_ascii_digit) && bytes[offset + 4] == b'-'
}

/// Check for a full FreeSWITCH log header at `offset`:
/// `YYYY-MM-DD HH:MM:SS.UUUUUU D+.D+% [`
///
/// Used by Layer 2 to detect same-line collisions where multiple log entries
/// were concatenated without a newline (thread contention on file write).
pub(crate) fn is_log_header_at(bytes: &[u8], offset: usize) -> bool {
    // Minimum: 27-byte timestamp + space + "0% [" = 31 bytes
    if bytes.len() < offset + 31 {
        return false;
    }
    // YYYY-MM-DD HH:MM:SS.UUUUUU (26 bytes + space)
    if !(bytes[offset..offset + 4].iter().all(u8::is_ascii_digit)
        && bytes[offset + 4] == b'-'
        && bytes[offset + 5..offset + 7].iter().all(u8::is_ascii_digit)
        && bytes[offset + 7] == b'-'
        && bytes[offset + 8..offset + 10]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[offset + 10] == b' '
        && bytes[offset + 11..offset + 13]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[offset + 13] == b':'
        && bytes[offset + 14..offset + 16]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[offset + 16] == b':'
        && bytes[offset + 17..offset + 19]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[offset + 19] == b'.'
        && bytes[offset + 20..offset + 26]
            .iter()
            .all(u8::is_ascii_digit)
        && bytes[offset + 26] == b' ')
    {
        return false;
    }
    // Idle percentage: starts with digit, has % within 6 bytes, then " ["
    let rest = &bytes[offset + 27..];
    if !rest[0].is_ascii_digit() {
        return false;
    }
    let Some(pct_pos) = rest[..rest.len().min(7)].iter().position(|&b| b == b'%') else {
        return false;
    };
    rest.len() > pct_pos + 2 && rest[pct_pos + 1] == b' ' && rest[pct_pos + 2] == b'['
}

fn parse_timestamped_fields(
    s: &str,
) -> (
    Option<&str>,
    Option<&str>,
    Option<LogLevel>,
    Option<&str>,
    &str,
) {
    if s.len() < 27 {
        return (None, None, None, None, s);
    }
    let timestamp = &s[0..26];
    let rest = &s[27..];

    let pct_pos = match rest.find('%') {
        Some(p) => p,
        None => return (Some(timestamp), None, None, None, rest),
    };
    let idle_pct = &rest[0..=pct_pos];

    if rest.len() < pct_pos + 3 {
        return (Some(timestamp), Some(idle_pct), None, None, "");
    }
    let rest = &rest[pct_pos + 2..];

    let bracket_end = match rest.find(']') {
        Some(p) => p,
        None => return (Some(timestamp), Some(idle_pct), None, None, rest),
    };
    let level = LogLevel::from_bracketed(&rest[0..=bracket_end]);

    if rest.len() < bracket_end + 3 {
        return (Some(timestamp), Some(idle_pct), level, None, "");
    }
    let rest = &rest[bracket_end + 2..];

    let source_end = rest.find(' ').unwrap_or(rest.len());
    let source = &rest[0..source_end];
    let message = if source_end < rest.len() {
        &rest[source_end + 1..]
    } else {
        ""
    };

    (
        Some(timestamp),
        Some(idle_pct),
        level,
        Some(source),
        message,
    )
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
        let uuid = &line[0..36];
        let after_uuid = &line[37..];

        if is_date_at(bytes, 37) {
            let (timestamp, idle_pct, level, source, message) =
                parse_timestamped_fields(after_uuid);
            return RawLine {
                uuid: Some(uuid),
                timestamp,
                idle_pct,
                level,
                source,
                message,
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

    if is_date_at(bytes, 0) {
        let (timestamp, idle_pct, level, source, message) = parse_timestamped_fields(line);
        let (uuid, message) = if is_uuid_at(message.as_bytes(), 0) {
            (Some(&message[0..36]), &message[37..])
        } else {
            (None, message)
        };
        return RawLine {
            uuid,
            timestamp,
            idle_pct,
            level,
            source,
            message,
            kind: LineKind::System,
        };
    }

    if let Some(uuid_start) = find_uuid_in(bytes) {
        let uuid = &line[uuid_start..uuid_start + 36];
        let message = if line.len() > uuid_start + 37 {
            &line[uuid_start + 37..]
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
            ("ERR", LogLevel::Err),
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
}
