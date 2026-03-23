use crate::level::LogLevel;
use crate::line::{is_date_at, is_log_header_at, is_uuid_at, parse_line, LineKind};
use crate::message::{classify_message, MessageKind, SdpDirection};

/// Structured data extracted from a multi-line dump that follows a primary log entry.
///
/// Each variant corresponds to a block type that the stream state machine
/// recognizes and reassembles from continuation lines.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    /// Channel variable dump — `Channel-*` fields and `variable_*` key-value pairs.
    /// Multi-line variable values (e.g. embedded SDP) are reassembled with `\n` separators.
    ChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
    },
    /// SDP session description body, collected line by line.
    Sdp {
        direction: SdpDirection,
        body: Vec<String>,
    },
    /// Codec negotiation sequence — offered/local comparisons and selected matches.
    CodecNegotiation {
        comparisons: Vec<(String, String)>,
        selected: Vec<String>,
    },
}

/// Controls how much detail is recorded for lines that couldn't be fully classified.
///
/// Higher fidelity levels allocate more memory. The default is `CountOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnclassifiedTracking {
    /// Increment the counter only — zero allocation.
    CountOnly,
    /// Record line number and reason for each unclassified line.
    TrackLines,
    /// Like `TrackLines` plus the full line content.
    CaptureData,
}

/// Why a line was marked as unclassified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnclassifiedReason {
    /// Bare continuation line arrived with no pending entry to attach to.
    OrphanContinuation,
    /// Line was parsed but the message didn't match any known pattern.
    UnknownMessageFormat,
    /// EXECUTE or variable line was only partially readable.
    TruncatedField,
}

/// Record of a single unclassified line, captured when tracking is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclassifiedLine {
    pub line_number: u64,
    pub reason: UnclassifiedReason,
    /// The full line content; only populated under [`UnclassifiedTracking::CaptureData`].
    pub data: Option<String>,
}

/// Cumulative parsing statistics, updated as lines flow through the stream.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub lines_processed: u64,
    pub lines_unclassified: u64,
    /// Lines that became part of entries (primary line + attached lines per entry).
    pub lines_in_entries: u64,
    /// Empty lines that arrived with no pending entry to attach to.
    pub lines_empty_orphan: u64,
    /// Physical lines that were split into multiple logical entries due to
    /// mod_logfile's 2048-byte snprintf truncation causing same-line collisions.
    pub lines_split: u64,
    /// Populated only when tracking is `TrackLines` or `CaptureData`.
    pub unclassified_lines: Vec<UnclassifiedLine>,
}

impl ParseStats {
    /// Lines that were processed but not accounted for by any tracking category.
    ///
    /// Returns 0 when the parser correctly accounts for every input line.
    /// A non-zero value indicates a parser bug — lines were silently lost.
    ///
    /// Invariant: `lines_processed + lines_split == lines_in_entries + lines_empty_orphan`
    pub fn unaccounted_lines(&self) -> u64 {
        let expected = self.lines_in_entries + self.lines_empty_orphan;
        let actual = self.lines_processed + self.lines_split;
        actual.saturating_sub(expected)
    }
}

/// A complete parsed log entry with all context resolved.
///
/// Produced by [`LogStream`]. Continuation lines have been grouped,
/// UUID/timestamp inherited from context where needed, and multi-line blocks
/// reassembled.
#[derive(Debug)]
pub struct LogEntry {
    /// Session UUID, or empty string for system lines.
    pub uuid: String,
    /// Timestamp with microsecond precision; inherited from the previous entry for continuations.
    pub timestamp: String,
    /// `None` for continuation and truncated lines.
    pub level: Option<LogLevel>,
    /// Core scheduler idle percentage; `None` for continuations.
    pub idle_pct: Option<String>,
    /// Source file:line; `None` for continuations.
    pub source: Option<String>,
    /// The primary message text.
    pub message: String,
    /// Which line format originated this entry.
    pub kind: LineKind,
    /// Semantic classification of the message content.
    pub message_kind: MessageKind,
    /// Typed, parsed multi-line block; `None` for entries without a trailing block.
    pub block: Option<Block>,
    /// Raw continuation lines that followed the primary line.
    pub attached: Vec<String>,
    /// 1-based line number in the input stream.
    pub line_number: u64,
    /// Per-entry warnings about parsing anomalies.
    pub warnings: Vec<String>,
}

fn parse_field_line(msg: &str) -> Option<(String, String)> {
    let colon = msg.find(": ")?;
    let name = &msg[..colon];
    if name.contains(' ') || name.is_empty() {
        return None;
    }
    let value_part = &msg[colon + 2..];
    let value = if let Some(inner) = value_part.strip_prefix('[') {
        inner.strip_suffix(']').unwrap_or(inner)
    } else {
        value_part
    };
    Some((name.to_string(), value.to_string()))
}

enum StreamState {
    Idle,
    InChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
        open_var_name: Option<String>,
        open_var_value: Option<String>,
    },
    InSdp {
        direction: SdpDirection,
        body: Vec<String>,
    },
    InCodecNegotiation {
        comparisons: Vec<(String, String)>,
        selected: Vec<String>,
    },
}

impl StreamState {
    fn take_idle(&mut self) -> StreamState {
        std::mem::replace(self, StreamState::Idle)
    }
}

/// Layer 2 structural state machine — groups continuation lines, classifies
/// messages, and detects multi-line blocks (CHANNEL_DATA, SDP, codec negotiation).
///
/// Wraps any `Iterator<Item = String>` and yields [`LogEntry`] values.
/// Maintains `last_uuid` and `last_timestamp` to fill in context for
/// continuation lines that lack their own.
///
/// Use the builder method [`unclassified_tracking()`](LogStream::unclassified_tracking)
/// to control diagnostic detail before iterating.
pub struct LogStream<I> {
    lines: I,
    last_uuid: String,
    last_timestamp: String,
    pending: Option<LogEntry>,
    state: StreamState,
    stats: ParseStats,
    tracking: UnclassifiedTracking,
    line_number: u64,
    split_pending: Option<String>,
    deferred_warning: Option<String>,
}

impl<I: Iterator<Item = String>> LogStream<I> {
    /// Create a new stream from any line iterator.
    pub fn new(lines: I) -> Self {
        LogStream {
            lines,
            last_uuid: String::new(),
            last_timestamp: String::new(),
            pending: None,
            state: StreamState::Idle,
            stats: ParseStats::default(),
            tracking: UnclassifiedTracking::CountOnly,
            line_number: 0,
            split_pending: None,
            deferred_warning: None,
        }
    }

    /// Set the unclassified line tracking level (builder pattern). Defaults to `CountOnly`.
    pub fn unclassified_tracking(mut self, level: UnclassifiedTracking) -> Self {
        self.tracking = level;
        self
    }

    /// Cumulative parsing statistics up to the current position.
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Take all accumulated unclassified line records, leaving the internal vec empty.
    ///
    /// The `lines_unclassified` counter is not reset.
    pub fn drain_unclassified(&mut self) -> Vec<UnclassifiedLine> {
        std::mem::take(&mut self.stats.unclassified_lines)
    }

    fn record_unclassified(&mut self, reason: UnclassifiedReason, data: Option<&str>) {
        self.stats.lines_unclassified += 1;
        match self.tracking {
            UnclassifiedTracking::CountOnly => {}
            UnclassifiedTracking::TrackLines => {
                self.stats.unclassified_lines.push(UnclassifiedLine {
                    line_number: self.line_number,
                    reason,
                    data: None,
                });
            }
            UnclassifiedTracking::CaptureData => {
                self.stats.unclassified_lines.push(UnclassifiedLine {
                    line_number: self.line_number,
                    reason,
                    data: data.map(|s| s.to_string()),
                });
            }
        }
    }

    fn finalize_block(&mut self) -> (Option<Block>, Vec<String>) {
        let mut warnings = Vec::new();
        match self.state.take_idle() {
            StreamState::Idle => (None, warnings),
            StreamState::InChannelData {
                fields,
                mut variables,
                open_var_name,
                open_var_value,
            } => {
                if let (Some(ref name), Some(value)) = (&open_var_name, open_var_value) {
                    warnings.push(format!("unclosed multi-line variable: {name}"));
                    variables.push((name.clone(), value));
                }
                (Some(Block::ChannelData { fields, variables }), warnings)
            }
            StreamState::InSdp { direction, body } => {
                (Some(Block::Sdp { direction, body }), warnings)
            }
            StreamState::InCodecNegotiation {
                comparisons,
                selected,
            } => (
                Some(Block::CodecNegotiation {
                    comparisons,
                    selected,
                }),
                warnings,
            ),
        }
    }

    fn finalize_pending(&mut self) -> Option<LogEntry> {
        let (block, warnings) = self.finalize_block();
        if let Some(ref mut p) = self.pending {
            p.block = block;
            p.warnings.extend(warnings);
            self.stats.lines_in_entries += 1 + p.attached.len() as u64;
        }
        self.pending.take()
    }

    fn start_block_for_message(&mut self, message_kind: &MessageKind) {
        self.state = match message_kind {
            MessageKind::ChannelData => StreamState::InChannelData {
                fields: Vec::new(),
                variables: Vec::new(),
                open_var_name: None,
                open_var_value: None,
            },
            MessageKind::SdpMarker { direction } => StreamState::InSdp {
                direction: direction.clone(),
                body: Vec::new(),
            },
            MessageKind::CodecNegotiation => StreamState::InCodecNegotiation {
                comparisons: Vec::new(),
                selected: Vec::new(),
            },
            _ => StreamState::Idle,
        };
    }

    fn accumulate_codec_entry(&mut self, msg: &str) {
        let mut warning = None;
        if let StreamState::InCodecNegotiation {
            comparisons,
            selected,
        } = &mut self.state
        {
            let rest = msg.strip_prefix("Audio Codec Compare ").unwrap_or(msg);
            if rest.contains("is saved as a match") {
                let codec = rest.find(']').map(|end| &rest[1..end]).unwrap_or(rest);
                selected.push(codec.to_string());
            } else if let Some(slash) = rest.find("]/[") {
                let offered = &rest[1..slash];
                let local = &rest[slash + 3..rest.len().saturating_sub(1)];
                comparisons.push((offered.to_string(), local.to_string()));
            } else {
                warning = Some(format!(
                    "unrecognized codec negotiation line: {}",
                    if msg.len() > 80 { &msg[..80] } else { msg }
                ));
            }
        }
        if let (Some(w), Some(ref mut pending)) = (warning, &mut self.pending) {
            pending.warnings.push(w);
        }
    }

    fn accumulate_continuation(&mut self, msg: &str, line: &str) {
        let msg_kind = classify_message(msg);
        let mut warning = None;
        match &mut self.state {
            StreamState::InChannelData {
                fields,
                variables,
                open_var_name,
                open_var_value,
            } => {
                if let Some(ref mut val) = open_var_value {
                    val.push('\n');
                    val.push_str(msg);
                    if msg.ends_with(']') {
                        let trimmed = val.trim_end_matches(']').to_string();
                        let name = open_var_name.take().unwrap();
                        *open_var_value = None;
                        variables.push((name, trimmed));
                    }
                } else {
                    match &msg_kind {
                        MessageKind::ChannelField { name, value } => {
                            fields.push((name.clone(), value.clone()));
                        }
                        MessageKind::Variable { name, value } => {
                            if !msg.ends_with(']') && msg.contains(": [") {
                                *open_var_name = Some(name.clone());
                                *open_var_value = Some(value.clone());
                            } else {
                                variables.push((name.clone(), value.clone()));
                            }
                        }
                        _ => {
                            if let Some((name, value)) = parse_field_line(msg) {
                                fields.push((name, value));
                            } else {
                                warning = Some(format!(
                                    "unparseable CHANNEL_DATA line: {}",
                                    if msg.len() > 80 { &msg[..80] } else { msg }
                                ));
                            }
                        }
                    }
                }
            }
            StreamState::InSdp { body, .. } => {
                body.push(msg.to_string());
            }
            StreamState::InCodecNegotiation { .. } => {
                warning = Some(format!(
                    "unexpected codec negotiation continuation: {}",
                    if msg.len() > 80 { &msg[..80] } else { msg }
                ));
            }
            StreamState::Idle => {}
        }
        if let Some(ref mut pending) = self.pending {
            if let Some(w) = warning {
                pending.warnings.push(w);
            }
            pending.attached.push(line.to_string());
        }
    }

    fn new_entry(
        &mut self,
        uuid: String,
        timestamp: String,
        message: String,
        kind: LineKind,
        message_kind: MessageKind,
    ) -> LogEntry {
        let mut warnings = Vec::new();
        if let Some(w) = self.deferred_warning.take() {
            warnings.push(w);
        }
        LogEntry {
            uuid,
            timestamp,
            message,
            kind,
            message_kind,
            level: None,
            idle_pct: None,
            source: None,
            block: None,
            attached: Vec::new(),
            line_number: self.line_number,
            warnings,
        }
    }
}

/// mod_logfile's `snprintf` buffer size for UUID-prefixed lines.
/// Lines exceeding this in the formatted output lose their trailing newline,
/// causing the next queue entry to collide on the same physical line.
const MOD_LOGFILE_BUF_SIZE: usize = 2048;

/// Effective maximum payload per line (buffer minus UUID, space, newline).
const MAX_LINE_PAYLOAD: usize = MOD_LOGFILE_BUF_SIZE - 36 - 1 - 1;

impl<I: Iterator<Item = String>> LogStream<I> {
    /// Detect same-line collisions where multiple log entries were concatenated
    /// without a newline separator.
    ///
    /// Two collision mechanisms exist in production:
    ///
    /// 1. **Buffer truncation** (Format E): `mod_logfile`'s 2048-byte `snprintf`
    ///    buffer truncates a long line, losing the trailing `\n`. The next entry
    ///    from the log queue collides on the same physical line. These lines
    ///    always exceed `MAX_LINE_PAYLOAD`.
    ///
    /// 2. **Write contention**: multiple threads writing to the log file can
    ///    interleave output, producing concatenated entries at any line length.
    ///    Common with system lines (Format B) that lack UUID prefixes.
    ///
    /// Returns the (possibly truncated) line. If a collision is detected,
    /// the suffix is stored in `split_pending` for processing in the next
    /// iteration. Recursive: split suffixes pass through this function again.
    fn detect_collision(&mut self, line: String) -> String {
        if line.len() > MAX_LINE_PAYLOAD {
            let warning = format!(
                "line exceeds mod_logfile 2048-byte buffer ({} bytes), data may be truncated",
                line.len() + 38,
            );
            if let Some(ref mut pending) = self.pending {
                pending.warnings.push(warning);
            } else {
                self.deferred_warning = Some(warning);
            }
        }

        // Skip past the line's own header to avoid matching itself.
        let bytes = line.as_bytes();
        let min_scan = if is_uuid_at(bytes, 0) {
            if bytes.len() > 37 && bytes[37].is_ascii_digit() {
                64 // Full line: UUID + timestamp
            } else {
                37 // UUID continuation
            }
        } else if is_date_at(bytes, 0) {
            27 // System line: skip own timestamp
        } else {
            0
        };

        let end = bytes.len().saturating_sub(28);
        for offset in min_scan..=end {
            // Timestamp collision (System or Full line header)
            if is_log_header_at(bytes, offset) {
                // Check if a UUID precedes the timestamp (Full line collision)
                let split_at = if offset >= 37 && is_uuid_at(bytes, offset - 37) {
                    offset - 37
                } else {
                    offset
                };
                self.split_pending = Some(line[split_at..].to_string());
                return line[..split_at].to_string();
            }
            // UUID collision without timestamp (Format E — truncated buffer)
            if is_uuid_at(bytes, offset) && bytes.len() > MAX_LINE_PAYLOAD {
                self.split_pending = Some(line[offset..].to_string());
                return line[..offset].to_string();
            }
        }

        line
    }
}

impl<I: Iterator<Item = String>> Iterator for LogStream<I> {
    type Item = LogEntry;

    fn next(&mut self) -> Option<LogEntry> {
        loop {
            let line = if let Some(split) = self.split_pending.take() {
                self.stats.lines_split += 1;
                split
            } else {
                let Some(line) = self.lines.next() else {
                    return self.finalize_pending();
                };

                if line.starts_with('\x00') {
                    let yielded = self.finalize_pending();
                    self.last_uuid.clear();
                    self.last_timestamp.clear();
                    if yielded.is_some() {
                        return yielded;
                    }
                    continue;
                }

                self.line_number += 1;
                self.stats.lines_processed += 1;
                line
            };

            let line = self.detect_collision(line);

            let parsed = parse_line(&line);

            match parsed.kind {
                LineKind::Full | LineKind::System | LineKind::Truncated => {
                    let uuid = parsed.uuid.unwrap_or("").to_string();
                    let message_kind = classify_message(parsed.message);

                    // Merge consecutive codec negotiation entries with same UUID
                    if message_kind == MessageKind::CodecNegotiation {
                        if let (Some(ref pending), StreamState::InCodecNegotiation { .. }) =
                            (&self.pending, &self.state)
                        {
                            if uuid == pending.uuid {
                                self.accumulate_codec_entry(parsed.message);
                                if let Some(ref mut p) = self.pending {
                                    p.attached.push(line);
                                }
                                continue;
                            }
                        }
                    }

                    let yielded = self.finalize_pending();

                    let timestamp = parsed
                        .timestamp
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| self.last_timestamp.clone());

                    if !uuid.is_empty() {
                        self.last_uuid = uuid.clone();
                    }
                    if parsed.timestamp.is_some() {
                        self.last_timestamp = timestamp.clone();
                    }

                    self.start_block_for_message(&message_kind);
                    if message_kind == MessageKind::CodecNegotiation {
                        self.accumulate_codec_entry(parsed.message);
                    }

                    let mut entry = self.new_entry(
                        uuid,
                        timestamp,
                        parsed.message.to_string(),
                        parsed.kind,
                        message_kind,
                    );
                    entry.level = parsed.level;
                    entry.idle_pct = parsed.idle_pct.map(|s| s.to_string());
                    entry.source = parsed.source.map(|s| s.to_string());
                    self.pending = Some(entry);

                    if yielded.is_some() {
                        return yielded;
                    }
                }

                LineKind::UuidContinuation => {
                    let uuid = parsed.uuid.unwrap_or("").to_string();
                    let is_primary = parsed.message.starts_with("EXECUTE ");

                    if let Some(ref pending) = self.pending {
                        if !is_primary && uuid == pending.uuid {
                            self.accumulate_continuation(parsed.message, &line);
                        } else {
                            let yielded = self.finalize_pending();
                            let message_kind = classify_message(parsed.message);

                            if !uuid.is_empty() {
                                self.last_uuid = uuid.clone();
                            }

                            self.start_block_for_message(&message_kind);
                            self.pending = Some(self.new_entry(
                                uuid,
                                self.last_timestamp.clone(),
                                parsed.message.to_string(),
                                parsed.kind,
                                message_kind,
                            ));

                            return yielded;
                        }
                    } else {
                        let message_kind = classify_message(parsed.message);

                        if !uuid.is_empty() {
                            self.last_uuid = uuid.clone();
                        }

                        self.start_block_for_message(&message_kind);
                        self.pending = Some(self.new_entry(
                            uuid,
                            self.last_timestamp.clone(),
                            parsed.message.to_string(),
                            parsed.kind,
                            message_kind,
                        ));
                    }
                }

                LineKind::BareContinuation => {
                    if self.pending.is_some() {
                        self.accumulate_continuation(parsed.message, &line);
                    } else {
                        self.record_unclassified(
                            UnclassifiedReason::OrphanContinuation,
                            Some(&line),
                        );
                        let message_kind = classify_message(parsed.message);
                        self.pending = Some(self.new_entry(
                            self.last_uuid.clone(),
                            self.last_timestamp.clone(),
                            parsed.message.to_string(),
                            parsed.kind,
                            message_kind,
                        ));
                    }
                }

                LineKind::Empty => {
                    if let Some(ref mut pending) = self.pending {
                        pending.attached.push(line);
                    } else {
                        self.stats.lines_empty_orphan += 1;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const UUID2: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

    fn full_line(uuid: &str, ts: &str, msg: &str) -> String {
        format!("{uuid} {ts} 95.97% [DEBUG] sofia.c:100 {msg}")
    }

    const TS1: &str = "2025-01-15 10:30:45.123456";
    const TS2: &str = "2025-01-15 10:30:46.234567";

    // --- Existing behavior tests (preserved) ---

    #[test]
    fn inherits_uuid_for_bare_continuation() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            "variable_foo: [bar]".to_string(),
            "variable_baz: [qux]".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uuid, UUID1);
        assert_eq!(entries[0].attached.len(), 2);
        assert_eq!(entries[0].attached[0], "variable_foo: [bar]");
        assert_eq!(entries[0].attached[1], "variable_baz: [qux]");
    }

    #[test]
    fn inherits_timestamp_for_uuid_continuation() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID2} Channel-State: [CS_EXECUTE]"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].timestamp, TS1);
        assert_eq!(entries[1].uuid, UUID2);
        assert_eq!(entries[1].timestamp, TS1);
    }

    #[test]
    fn new_full_line_yields_previous() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            full_line(UUID2, TS2, "Second"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let first = stream.next().unwrap();
        assert_eq!(first.uuid, UUID1);
        assert_eq!(first.message, "First");
        let second = stream.next().unwrap();
        assert_eq!(second.uuid, UUID2);
        assert_eq!(second.message, "Second");
        assert!(stream.next().is_none());
    }

    #[test]
    fn channel_data_collected_as_attached() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} Unique-ID: [{UUID1}]"),
            "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "CHANNEL_DATA:");
        assert_eq!(entries[0].attached.len(), 3);
    }

    #[test]
    fn sdp_body_collected_as_attached() {
        let lines = vec![
            full_line(UUID1, TS1, "Local SDP:"),
            "v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            "s=-".to_string(),
            "c=IN IP4 192.0.2.1".to_string(),
            "m=audio 10000 RTP/AVP 0".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attached.len(), 5);
    }

    #[test]
    fn truncated_starts_new_entry() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!(
                "varia{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
            ),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let first = stream.next().unwrap();
        assert_eq!(first.uuid, UUID1);
        assert_eq!(first.message, "First");
        let second = stream.next().unwrap();
        assert_eq!(second.uuid, UUID2);
        assert_eq!(second.kind, LineKind::Truncated);
    }

    #[test]
    fn empty_lines_in_attached() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            String::new(),
            "continuation".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attached.len(), 2);
        assert_eq!(entries[0].attached[0], "");
        assert_eq!(entries[0].attached[1], "continuation");
    }

    #[test]
    fn system_line_no_uuid() {
        let lines = vec![format!(
            "{TS1} 95.97% [INFO] mod_event_socket.c:1772 Event Socket command"
        )];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uuid, "");
        assert_eq!(entries[0].kind, LineKind::System);
    }

    #[test]
    fn final_entry_on_exhaustion() {
        let lines = vec![full_line(UUID1, TS1, "Only entry")];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "Only entry");
    }

    #[test]
    fn consecutive_full_lines() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            full_line(UUID1, TS2, "Second"),
            full_line(UUID2, TS1, "Third"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 3);
        for entry in &entries {
            assert!(entry.attached.is_empty());
        }
    }

    #[test]
    fn execute_after_channel_data_same_uuid() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            format!("{UUID1} variable_sip_call_id: [test@192.0.2.1]"),
            "variable_foo: [bar]".to_string(),
            String::new(),
            String::new(),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)"),
            full_line(UUID1, TS2, "EXPORT (export_vars) [originate_timeout]=[3600]"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "CHANNEL_DATA:");
        assert_eq!(entries[0].attached.len(), 5);
        assert_eq!(entries[1].message, "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)");
        assert_eq!(entries[1].kind, LineKind::UuidContinuation);
        assert_eq!(
            entries[2].message,
            "EXPORT (export_vars) [originate_timeout]=[3600]"
        );
    }

    #[test]
    fn execute_between_full_lines_same_uuid() {
        let lines = vec![
            full_line(UUID1, TS1, "CoreSession::setVariable(X-C911P-City, ST GEORGES)"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/ng_{UUID1}/city/ST GEORGES)"),
            full_line(UUID1, TS2, "CoreSession::setVariable(X-C911P-Region, SGS)"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0].message,
            "CoreSession::setVariable(X-C911P-City, ST GEORGES)"
        );
        assert!(entries[0].attached.is_empty());
        assert!(entries[1].message.starts_with("EXECUTE "));
        assert_eq!(entries[1].kind, LineKind::UuidContinuation);
        assert_eq!(
            entries[2].message,
            "CoreSession::setVariable(X-C911P-Region, SGS)"
        );
    }

    #[test]
    fn multiple_execute_between_full_lines() {
        let lines = vec![
            full_line(UUID1, TS1, "CoreSession::setVariable(ngcs_call_id, urn:emergency:uid:callid:test)"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/ng_{UUID1}/call_id/urn:emergency:uid:callid:test)"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/callid_codecs/urn:emergency:uid:callid:test/PCMU@8000h)"),
            full_line(UUID1, TS2, "CoreSession::setVariable(ngcs_short_call_id, test)"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 4);
        assert!(entries[0].attached.is_empty());
        assert!(entries[1].message.contains("call_id"));
        assert!(entries[2].message.contains("callid_codecs"));
        assert_eq!(
            entries[3].message,
            "CoreSession::setVariable(ngcs_short_call_id, test)"
        );
    }

    #[test]
    fn uuid_continuation_different_uuid_yields() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            format!("{UUID2} Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let first = stream.next().unwrap();
        assert_eq!(first.uuid, UUID1);
        assert_eq!(first.attached.len(), 1);
        let second = stream.next().unwrap();
        assert_eq!(second.uuid, UUID2);
        assert_eq!(
            second.message,
            "Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]"
        );
    }

    // --- New: Block detection tests ---

    #[test]
    fn channel_data_block_fields_and_variables() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            format!("{UUID1} Unique-ID: [{UUID1}]"),
            "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
            "variable_direction: [inbound]".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message_kind, MessageKind::ChannelData);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 3);
                assert_eq!(
                    fields[0],
                    (
                        "Channel-Name".to_string(),
                        "sofia/internal/+15550001234@192.0.2.1".to_string()
                    )
                );
                assert_eq!(
                    fields[1],
                    ("Channel-State".to_string(), "CS_EXECUTE".to_string())
                );
                assert_eq!(fields[2], ("Unique-ID".to_string(), UUID1.to_string()));
                assert_eq!(variables.len(), 2);
                assert_eq!(
                    variables[0],
                    (
                        "variable_sip_call_id".to_string(),
                        "test123@192.0.2.1".to_string()
                    )
                );
                assert_eq!(
                    variables[1],
                    ("variable_direction".to_string(), "inbound".to_string())
                );
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
    }

    #[test]
    fn channel_data_multiline_variable_reassembly() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            "variable_switch_r_sdp: [v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            "s=-".to_string(),
            "c=IN IP4 192.0.2.1".to_string(),
            "m=audio 47758 RTP/AVP 0 101".to_string(),
            "a=rtpmap:0 PCMU/8000".to_string(),
            "]".to_string(),
            "variable_direction: [inbound]".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 1);
                assert_eq!(variables.len(), 2);
                assert_eq!(variables[0].0, "variable_switch_r_sdp");
                assert!(variables[0].1.starts_with("v=0\n"));
                assert!(variables[0].1.contains("m=audio 47758 RTP/AVP 0 101"));
                assert!(!variables[0].1.ends_with(']'));
                assert_eq!(
                    variables[1],
                    ("variable_direction".to_string(), "inbound".to_string())
                );
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
        assert_eq!(entries[0].attached.len(), 9);
    }

    #[test]
    fn sdp_block_detection() {
        let lines = vec![
            full_line(UUID1, TS1, "Local SDP:"),
            "v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            "s=-".to_string(),
            "c=IN IP4 192.0.2.1".to_string(),
            "m=audio 10000 RTP/AVP 0".to_string(),
            "a=rtpmap:0 PCMU/8000".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        match &entries[0].message_kind {
            MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Local),
            other => panic!("expected SdpMarker, got {other:?}"),
        }
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::Sdp { direction, body } => {
                assert_eq!(*direction, SdpDirection::Local);
                assert_eq!(body.len(), 6);
                assert_eq!(body[0], "v=0");
                assert_eq!(body[5], "a=rtpmap:0 PCMU/8000");
            }
            other => panic!("expected Sdp block, got {other:?}"),
        }
    }

    #[test]
    fn sdp_block_terminated_by_primary_line() {
        let lines = vec![
            full_line(UUID1, TS1, "Remote SDP:"),
            "v=0".to_string(),
            "m=audio 10000 RTP/AVP 0".to_string(),
            full_line(UUID1, TS2, "Next event"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 2);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::Sdp { direction, body } => {
                assert_eq!(*direction, SdpDirection::Remote);
                assert_eq!(body.len(), 2);
            }
            other => panic!("expected Sdp block, got {other:?}"),
        }
        assert!(entries[1].block.is_none());
    }

    #[test]
    fn sdp_from_uuid_continuation() {
        let lines = vec![
            format!("{UUID1} Local SDP:"),
            format!("{UUID1} v=0"),
            format!("{UUID1} o=FreeSWITCH 1234 5678 IN IP4 192.0.2.1"),
            format!("{UUID1} s=FreeSWITCH"),
            format!("{UUID1} c=IN IP4 192.0.2.1"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::Sdp { direction, body } => {
                assert_eq!(*direction, SdpDirection::Local);
                assert_eq!(body.len(), 4);
                assert_eq!(body[0], "v=0");
            }
            other => panic!("expected Sdp block, got {other:?}"),
        }
    }

    #[test]
    fn channel_data_interrupted_by_different_uuid() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID2} Dialplan: sofia/internal/+15559999999@192.0.2.1 parsing [public]"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 2);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, .. } => {
                assert_eq!(fields.len(), 1);
            }
            other => panic!("expected ChannelData, got {other:?}"),
        }
    }

    #[test]
    fn no_block_for_non_block_message() {
        let lines = vec![full_line(UUID1, TS1, "some random freeswitch log message")];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].block.is_none());
        assert_eq!(entries[0].message_kind, MessageKind::General);
    }

    #[test]
    fn message_kind_on_execute() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 2);
        match &entries[1].message_kind {
            MessageKind::Execute {
                application,
                arguments,
                ..
            } => {
                assert_eq!(application, "set");
                assert_eq!(arguments, "foo=bar");
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }

    // --- New: ParseStats tests ---

    #[test]
    fn stats_lines_processed() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            full_line(UUID1, TS2, "Second"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_eq!(stream.stats().lines_processed, 3);
    }

    #[test]
    fn stats_unclassified_orphan() {
        let lines = vec![
            "variable_foo: [bar]".to_string(),
            full_line(UUID1, TS1, "After orphan"),
        ];
        let mut stream = LogStream::new(lines.into_iter())
            .unclassified_tracking(UnclassifiedTracking::TrackLines);
        let _: Vec<_> = stream.by_ref().collect();
        assert_eq!(stream.stats().lines_unclassified, 1);
        assert_eq!(stream.stats().unclassified_lines.len(), 1);
        assert_eq!(
            stream.stats().unclassified_lines[0].reason,
            UnclassifiedReason::OrphanContinuation,
        );
    }

    #[test]
    fn stats_capture_data() {
        let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
        let mut stream = LogStream::new(lines.into_iter())
            .unclassified_tracking(UnclassifiedTracking::CaptureData);
        let _: Vec<_> = stream.by_ref().collect();
        assert_eq!(stream.stats().unclassified_lines.len(), 1);
        assert_eq!(
            stream.stats().unclassified_lines[0].data.as_deref(),
            Some("orphan line"),
        );
    }

    #[test]
    fn stats_count_only_no_allocation() {
        let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_eq!(stream.stats().lines_unclassified, 1);
        assert!(stream.stats().unclassified_lines.is_empty());
    }

    #[test]
    fn line_number_tracking() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            full_line(UUID2, TS2, "Third"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].line_number, 3);
    }

    #[test]
    fn drain_unclassified() {
        let lines = vec![
            "orphan1".to_string(),
            "orphan2".to_string(),
            full_line(UUID1, TS1, "After"),
        ];
        let mut stream = LogStream::new(lines.into_iter())
            .unclassified_tracking(UnclassifiedTracking::TrackLines);
        let _: Vec<_> = stream.by_ref().collect();
        let drained = stream.drain_unclassified();
        assert_eq!(drained.len(), 1);
        assert!(stream.stats().unclassified_lines.is_empty());
        assert_eq!(stream.stats().lines_unclassified, 1);
    }

    // BUG 1: When LogStream processes a TrackedChain of multiple file segments,
    // last_timestamp from the previous segment bleeds into continuation lines
    // at the start of the next segment. This causes entries to get timestamps
    // from a completely different file (potentially hours earlier).
    //
    // Reproduces: f2cb66d4 getting timestamp 23:58:03 from the rotated file
    // when freeswitch.log starts with its continuation lines.
    #[test]
    fn continuation_lines_at_file_boundary_must_not_inherit_previous_timestamp() {
        use crate::TrackedChain;

        let uuid_a = "aaaaaaaa-1111-2222-3333-444444444444";
        let uuid_b = "bbbbbbbb-1111-2222-3333-444444444444";
        let ts_old = "2025-01-15 23:58:03.000000";
        let ts_new = "2025-01-16 08:37:12.000000";

        let seg1: Vec<String> = vec![format!(
            "{uuid_a} {ts_old} 95.00% [DEBUG] test.c:1 Last line in rotated file"
        )];

        // Segment 2 starts with UUID-continuation lines (Format C: UUID + message, no timestamp)
        // followed by a real timestamped line
        let seg2: Vec<String> = vec![
            format!("{uuid_b} CHANNEL_DATA:"),
            format!("{uuid_b} Channel-State: [CS_EXECUTE]"),
            format!("{uuid_b} {ts_new} 95.00% [DEBUG] test.c:1 First timestamped line in new file"),
        ];

        let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = vec![
            ("rotated.log".to_string(), Box::new(seg1.into_iter())),
            ("freeswitch.log".to_string(), Box::new(seg2.into_iter())),
        ];

        let (chain, _) = TrackedChain::new(segments);
        let entries: Vec<_> = LogStream::new(chain).collect();

        let b_entry = entries
            .iter()
            .find(|e| e.uuid == uuid_b)
            .expect("should find entry for uuid_b");

        // The CHANNEL_DATA entry for uuid_b must NOT have the timestamp from
        // segment 1 — it should either have the new file's first real timestamp
        // or be empty (indicating unknown).
        assert_ne!(
            b_entry.timestamp, ts_old,
            "continuation lines in a new file segment inherited timestamp \
             '{ts_old}' from the previous segment — timestamps must not bleed \
             across file boundaries"
        );
    }

    // --- Line accounting tests ---

    fn assert_accounting(stream: &LogStream<impl Iterator<Item = String>>) {
        let stats = stream.stats();
        assert_eq!(
            stats.unaccounted_lines(),
            0,
            "line accounting invariant violated: \
             processed={} + split={} != in_entries={} + empty_orphan={}",
            stats.lines_processed,
            stats.lines_split,
            stats.lines_in_entries,
            stats.lines_empty_orphan,
        );
    }

    #[test]
    fn accounting_full_lines() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            full_line(UUID2, TS2, "Second"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(stream.stats().lines_in_entries, 2);
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_with_attached() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            "variable_foo: [bar]".to_string(),
            full_line(UUID2, TS2, "Next"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 2);
        // Entry 1: 1 primary + 2 attached = 3 lines
        // Entry 2: 1 primary = 1 line
        assert_eq!(stream.stats().lines_in_entries, 4);
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_system_line() {
        let lines = vec![format!(
            "{TS1} 95.97% [NOTICE] mod_logfile.c:217 New log started."
        )];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_eq!(stream.stats().lines_in_entries, 1);
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_empty_orphan() {
        let lines = vec![
            String::new(),
            "   ".to_string(),
            full_line(UUID1, TS1, "After"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(stream.stats().lines_empty_orphan, 2);
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_empty_attached() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            String::new(),
            "continuation".to_string(),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attached.len(), 2);
        assert_eq!(stream.stats().lines_empty_orphan, 0);
        assert_eq!(stream.stats().lines_in_entries, 3);
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_orphan_continuation() {
        let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_codec_merging() {
        let lines = vec![
            full_line(
                UUID1,
                TS1,
                "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
            ),
            full_line(
                UUID1,
                TS1,
                "Audio Codec Compare [PCMU:0:8000:20:64000:1] is saved as a match",
            ),
            full_line(UUID2, TS2, "Next"),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_truncated_line() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!(
                "varia{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"
            ),
        ];
        let mut stream = LogStream::new(lines.into_iter());
        let _: Vec<_> = stream.by_ref().collect();
        assert_accounting(&stream);
    }

    #[test]
    fn accounting_long_line_collision_split() {
        // Simulate a long variable value exceeding mod_logfile's 2048-byte buffer,
        // followed by a collision UUID on the same physical line.
        let long_value = "x".repeat(MAX_LINE_PAYLOAD + 10);
        let line = format!(
            "variable_sip_multipart: [{long_value}]{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"
        );
        let lines = vec![full_line(UUID1, TS1, "CHANNEL_DATA:"), line];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();

        // The CHANNEL_DATA entry should have the truncated variable as attached
        assert_eq!(entries[0].message, "CHANNEL_DATA:");

        // The collision should have been split out as a separate entry
        let split_entry = entries.iter().find(|e| e.uuid == UUID2);
        assert!(
            split_entry.is_some(),
            "collision UUID should produce a separate entry"
        );

        assert_eq!(stream.stats().lines_split, 1);
        assert_accounting(&stream);
    }

    #[test]
    fn no_split_on_short_lines() {
        // Lines within the payload limit should never be split,
        // even if they happen to contain a UUID-like pattern.
        let line = format!("variable_call_uuid: [{UUID2}]");
        let lines = vec![full_line(UUID1, TS1, "CHANNEL_DATA:"), line];
        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(stream.stats().lines_split, 0);
        assert_accounting(&stream);
    }

    #[test]
    fn timestamp_collision_splits_system_lines() {
        let line = format!(
            "{TS1} 98.03% [INFO] mod_event_socket.c:1752 Event Socket Command from ::1:42864: api sofia jsonstatus{TS2} 97.93% [INFO] mod_event_socket.c:1752 Event Socket Command from ::1:42898: api fsctl pause_check"
        );
        let mut stream = LogStream::new(std::iter::once(line));
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].message,
            "Event Socket Command from ::1:42864: api sofia jsonstatus"
        );
        assert_eq!(
            entries[1].message,
            "Event Socket Command from ::1:42898: api fsctl pause_check"
        );
        assert_eq!(stream.stats().lines_split, 1);
        assert_accounting(&stream);
    }

    #[test]
    fn timestamp_collision_splits_three_entries() {
        let ts3 = "2025-01-15 10:30:47.345678";
        let line = format!(
            "{TS1} 95.00% [INFO] mod.c:1 first{TS2} 96.00% [INFO] mod.c:1 second{ts3} 97.00% [INFO] mod.c:1 third"
        );
        let mut stream = LogStream::new(std::iter::once(line));
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].message, "second");
        assert_eq!(entries[2].message, "third");
        assert_eq!(stream.stats().lines_split, 2);
        assert_accounting(&stream);
    }

    #[test]
    fn timestamp_collision_with_uuid_prefix() {
        // System line collides with Full line (UUID + timestamp)
        let line = format!(
            "{TS1} 95.00% [INFO] mod.c:1 first{UUID1} {TS2} 96.00% [DEBUG] sofia.c:100 second"
        );
        let mut stream = LogStream::new(std::iter::once(line));
        let entries: Vec<_> = stream.by_ref().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].uuid, UUID1);
        assert_eq!(entries[1].message, "second");
        assert_eq!(stream.stats().lines_split, 1);
        assert_accounting(&stream);
    }

    #[test]
    fn channel_data_multiline_variable_spans_many_lines() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            "variable_switch_r_sdp: [v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            "s=-".to_string(),
            "c=IN IP4 192.0.2.1".to_string(),
            "t=0 0".to_string(),
            "m=audio 47758 RTP/AVP 0 8 101".to_string(),
            "a=rtpmap:0 PCMU/8000".to_string(),
            "a=rtpmap:8 PCMA/8000".to_string(),
            "a=rtpmap:101 telephone-event/8000".to_string(),
            "a=fmtp:101 0-16".to_string(),
            "]".to_string(),
            "variable_direction: [inbound]".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 1);
                assert_eq!(variables.len(), 2);
                assert_eq!(variables[0].0, "variable_switch_r_sdp");
                let sdp = &variables[0].1;
                assert!(sdp.starts_with("v=0\n"));
                assert!(sdp.contains("a=fmtp:101 0-16"));
                assert!(!sdp.ends_with(']'));
                assert_eq!(variables[1].0, "variable_direction");
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
    }

    #[test]
    fn sdp_from_verto_update_media() {
        let lines = vec![
            full_line(UUID1, TS1, "updateMedia: Local SDP"),
            "v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            "m=audio 10000 RTP/AVP 0".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        match &entries[0].message_kind {
            MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Local),
            other => panic!("expected SdpMarker, got {other:?}"),
        }
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::Sdp { direction, body } => {
                assert_eq!(*direction, SdpDirection::Local);
                assert_eq!(body.len(), 3);
            }
            other => panic!("expected Sdp block, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_sdp_marker() {
        let lines = vec![
            full_line(UUID1, TS1, "Duplicate SDP"),
            "v=0".to_string(),
            "m=audio 10000 RTP/AVP 0".to_string(),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        match &entries[0].message_kind {
            MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Unknown),
            other => panic!("expected SdpMarker, got {other:?}"),
        }
        assert!(entries[0].block.is_some());
    }

    #[test]
    fn warning_on_unclosed_multiline_variable() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            "variable_switch_r_sdp: [v=0".to_string(),
            "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
            full_line(UUID2, TS2, "Next entry"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 2);
        assert!(
            entries[0]
                .warnings
                .iter()
                .any(|w| w.contains("unclosed multi-line variable")),
            "expected unclosed variable warning, got: {:?}",
            entries[0].warnings
        );
    }

    #[test]
    fn warning_on_unparseable_channel_data_line() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} this is not a valid field line"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .warnings
                .iter()
                .any(|w| w.contains("unparseable CHANNEL_DATA")),
            "expected unparseable warning, got: {:?}",
            entries[0].warnings
        );
    }

    #[test]
    fn warning_on_unexpected_codec_continuation() {
        let lines = vec![
            full_line(
                UUID1,
                TS1,
                "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
            ),
            format!("{UUID1} some unexpected continuation line"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .warnings
                .iter()
                .any(|w| w.contains("unexpected codec negotiation")),
            "expected codec warning, got: {:?}",
            entries[0].warnings
        );
    }

    #[test]
    fn system_line_uuid_continuation_not_absorbed() {
        // After the bug fix, a UUID continuation should NOT be absorbed
        // by a pending system line (empty UUID).
        let lines = vec![
            format!("{TS1} 95.97% [INFO] mod_event_socket.c:1772 Event Socket command"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        ];
        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
        assert_eq!(
            entries.len(),
            2,
            "UUID continuation should not be absorbed by system entry"
        );
        assert_eq!(entries[0].uuid, "");
        assert_eq!(entries[1].uuid, UUID1);
    }

    #[test]
    fn truncated_collision_in_channel_data_variable() {
        // A CHANNEL_DATA block where a variable value exceeds the 2048-byte
        // mod_logfile buffer, causing a truncated collision (Format E).
        // The variable_long_xml value opens with [ but the buffer truncation
        // causes a UUID+EXECUTE to collide on the same physical line before
        // the closing ].
        let padding = "x".repeat(2000);
        let collision_line = format!(
            "{UUID1} variable_long_xml: [{padding}{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(foo=bar)"
        );
        assert!(
            collision_line.len() > super::MAX_LINE_PAYLOAD,
            "test line must exceed buffer limit, got {}",
            collision_line.len()
        );

        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} variable_direction: [inbound]"),
            collision_line,
            full_line(UUID1, TS2, "Next log entry"),
        ];

        let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();

        // Entry 0: CHANNEL_DATA with the variables
        assert_eq!(entries[0].message, "CHANNEL_DATA:");
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 1, "should have Channel-Name field");
                assert_eq!(fields[0].0, "Channel-Name");
                assert_eq!(
                    variables.len(),
                    2,
                    "should have direction + unclosed long_xml"
                );
                assert_eq!(variables[0].0, "variable_direction");
                assert_eq!(variables[0].1, "inbound");
                assert_eq!(variables[1].0, "variable_long_xml");
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
        assert!(
            entries[0]
                .warnings
                .iter()
                .any(|w| w.contains("line exceeds mod_logfile 2048-byte buffer")),
            "expected buffer overflow warning, got: {:?}",
            entries[0].warnings
        );
        assert!(
            entries[0]
                .warnings
                .iter()
                .any(|w| w.contains("unclosed multi-line variable")),
            "expected unclosed variable warning, got: {:?}",
            entries[0].warnings
        );

        // Entry 1: the split EXECUTE line
        assert_eq!(entries[1].uuid, UUID1);
        assert!(
            entries[1].message.starts_with("EXECUTE "),
            "split entry should be EXECUTE, got: {}",
            entries[1].message
        );

        // Entry 2: the next full log line
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].message, "Next log entry");
    }

    #[test]
    fn channel_data_uuid_drops_mid_block() {
        // Production scenario: mod_logfile stops prepending the UUID mid-way
        // through a CHANNEL_DATA dump. The first few variable lines carry the
        // UUID prefix (UuidContinuation), then the remaining lines arrive as
        // bare continuations. All should be accumulated into the same block.
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} variable_max_forwards: [69]"),
            format!("{UUID1} variable_presence_id: [1251@[2001:db8::10]]"),
            format!("{UUID1} variable_sip_h_X-Custom-ID: [c4da84eb-88a7-40b2-b90d-e5bc2a0f634e]"),
            // UUID drops — bare continuations for the rest
            "variable_sip_h_X-Call-Info: [<urn:test:callid:20260316>;purpose=emergency-CallId]"
                .to_string(),
            "variable_ep_codec_string: [mod_opus.opus@48000h@20i@2c]".to_string(),
            "variable_remote_media_ip: [2001:db8::10]".to_string(),
            "variable_remote_media_port: [9952]".to_string(),
            "variable_rtp_use_codec_name: [opus]".to_string(),
            full_line(UUID1, TS2, "Next entry"),
        ];

        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "CHANNEL_DATA:");
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 0);
                assert_eq!(variables.len(), 8);
                // UUID-prefixed variables
                assert_eq!(variables[0].0, "variable_max_forwards");
                assert_eq!(variables[0].1, "69");
                assert_eq!(variables[1].0, "variable_presence_id");
                assert_eq!(variables[1].1, "1251@[2001:db8::10]");
                assert_eq!(variables[2].0, "variable_sip_h_X-Custom-ID");
                // Bare variables (UUID dropped)
                assert_eq!(variables[3].0, "variable_sip_h_X-Call-Info");
                assert!(variables[3].1.contains("emergency-CallId"));
                assert_eq!(variables[4].0, "variable_ep_codec_string");
                assert_eq!(variables[7].0, "variable_rtp_use_codec_name");
                assert_eq!(variables[7].1, "opus");
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
        assert_eq!(entries[0].attached.len(), 8);
        assert_eq!(entries[1].message, "Next entry");
        assert_accounting(&stream);
    }

    #[test]
    fn channel_data_uuid_drops_with_multiline_variable() {
        // UUID drops mid-block AND a multi-line variable (SDP body embedded
        // in variable_switch_r_sdp) spans many bare continuation lines.
        // The \r characters are real — SDP uses \r\n per RFC 4566, and
        // mod_logfile splits on \n leaving \r in the content.
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} variable_max_forwards: [69]"),
            format!("{UUID1} variable_sip_h_X-Custom-ID: [c4da84eb-88a7-40b2-b90d-e5bc2a0f634e]"),
            // UUID drops
            "variable_switch_r_sdp: [v=0\r".to_string(),
            "o=FreeSWITCH 1773663549 1773663550 IN IP6 2001:db8::10\r".to_string(),
            "s=FreeSWITCH\r".to_string(),
            "c=IN IP6 2001:db8::10\r".to_string(),
            "t=0 0\r".to_string(),
            "m=audio 9952 RTP/AVP 102 101 13\r".to_string(),
            "a=rtpmap:102 opus/48000/2\r".to_string(),
            "a=ptime:20\r".to_string(),
            "]".to_string(),
            "variable_ep_codec_string: [mod_opus.opus@48000h@20i@2c]".to_string(),
            "variable_direction: [inbound]".to_string(),
            full_line(UUID1, TS2, "Next entry"),
        ];

        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();

        assert_eq!(entries.len(), 2);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 0);
                assert_eq!(variables.len(), 5);
                assert_eq!(variables[0].0, "variable_max_forwards");
                assert_eq!(variables[1].0, "variable_sip_h_X-Custom-ID");
                // Multi-line SDP variable reassembled from bare continuations
                assert_eq!(variables[2].0, "variable_switch_r_sdp");
                let sdp = &variables[2].1;
                assert!(
                    sdp.starts_with("v=0\r\n"),
                    "SDP should start with v=0\\r\\n, got: {sdp:?}"
                );
                assert!(sdp.contains("m=audio 9952 RTP/AVP 102 101 13\r"));
                assert!(sdp.contains("a=ptime:20\r"));
                assert!(!sdp.ends_with(']'), "closing bracket should be stripped");
                // Post-SDP bare variables
                assert_eq!(variables[3].0, "variable_ep_codec_string");
                assert_eq!(variables[4].0, "variable_direction");
                assert_eq!(variables[4].1, "inbound");
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }
        // 2 UUID continuations + 9 SDP lines (open + 7 content + close) + 2 bare = 13
        assert_eq!(entries[0].attached.len(), 13);
        assert_accounting(&stream);
    }

    #[test]
    fn channel_data_bare_variable_collision_with_execute() {
        // Production collision: bare variable_call_uuid line on same physical
        // line as a UUID EXECUTE. The UUID appears at byte 20 ("variable_call_uuid: "
        // is 20 chars), within find_uuid_in's 50-byte scan window, so Layer 1
        // classifies it as Truncated — extracting the UUID and EXECUTE message.
        // The CHANNEL_DATA block loses variable_call_uuid (eaten as truncation
        // prefix) but correctly recovers the EXECUTE as a separate entry.
        let collision = format!(
            "variable_call_uuid: {UUID1} EXECUTE [depth=0] \
             sofia/internal-v6/1251@[2001:db8::10] export(nolocal:test_var=value)"
        );

        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} variable_max_forwards: [69]"),
            // UUID drops — bare continuations
            "variable_DP_MATCH: [ARRAY::create_conference|:create_conference]".to_string(),
            collision,
            // Full line resumes normal logging
            full_line(
                UUID1,
                TS2,
                "EXPORT (export_vars) (REMOTE ONLY) [test_var]=[value]",
            ),
        ];

        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();

        // Entry 0: CHANNEL_DATA — variable_call_uuid lost to truncation prefix
        assert_eq!(entries.len(), 3);
        let block = entries[0].block.as_ref().expect("should have block");
        match block {
            Block::ChannelData { fields, variables } => {
                assert_eq!(fields.len(), 0);
                assert_eq!(variables.len(), 2);
                assert_eq!(variables[0].0, "variable_max_forwards");
                assert_eq!(variables[1].0, "variable_DP_MATCH");
            }
            other => panic!("expected ChannelData block, got {other:?}"),
        }

        // Entry 1: EXECUTE recovered from the Truncated classification
        assert_eq!(entries[1].uuid, UUID1);
        assert_eq!(entries[1].kind, LineKind::Truncated);
        assert!(
            entries[1].message.starts_with("EXECUTE "),
            "truncated line should yield EXECUTE, got: {}",
            entries[1].message
        );

        // Entry 2: normal EXPORT line
        assert_eq!(entries[2].message_kind.label(), "variable");
        assert_accounting(&stream);
    }

    #[test]
    fn system_line_with_embedded_uuid_gets_entry_uuid() {
        // System lines (Format B) where switch_cpp.cpp logs the UUID at the
        // start of the message body should produce entries with the correct UUID.
        let lines = vec![
            format!(
                "{TS1} 95.97% [DEBUG] switch_cpp.cpp:1466 {UUID1} DAA-LOG WaveManager originate"
            ),
            format!(
                "{TS1} 95.97% [WARNING] switch_cpp.cpp:1466 {UUID1} DAA-LOG Failed to create session"
            ),
            full_line(UUID1, TS2, "State Change CS_EXECUTE -> CS_HIBERNATE"),
        ];

        let mut stream = LogStream::new(lines.into_iter());
        let entries: Vec<_> = stream.by_ref().collect();

        assert_eq!(entries.len(), 3);
        // Both System lines should have the UUID extracted from the message
        assert_eq!(entries[0].uuid, UUID1);
        assert_eq!(entries[0].kind, LineKind::System);
        assert_eq!(entries[0].message, "DAA-LOG WaveManager originate");

        assert_eq!(entries[1].uuid, UUID1);
        assert_eq!(entries[1].kind, LineKind::System);
        assert_eq!(entries[1].message, "DAA-LOG Failed to create session");

        // Full line still works normally
        assert_eq!(entries[2].uuid, UUID1);
        assert_eq!(entries[2].kind, LineKind::Full);
        assert_accounting(&stream);
    }
}
