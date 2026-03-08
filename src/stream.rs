use crate::level::LogLevel;
use crate::line::{parse_line, LineKind};
use crate::message::{classify_message, MessageKind, SdpDirection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    ChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
    },
    Sdp {
        direction: SdpDirection,
        body: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnclassifiedTracking {
    CountOnly,
    TrackLines,
    CaptureData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnclassifiedReason {
    OrphanContinuation,
    UnknownMessageFormat,
    TruncatedField,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclassifiedLine {
    pub line_number: u64,
    pub reason: UnclassifiedReason,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub lines_processed: u64,
    pub lines_unclassified: u64,
    pub unclassified_lines: Vec<UnclassifiedLine>,
}

#[derive(Debug)]
pub struct LogEntry {
    pub uuid: String,
    pub timestamp: String,
    pub level: Option<LogLevel>,
    pub idle_pct: Option<String>,
    pub source: Option<String>,
    pub message: String,
    pub kind: LineKind,
    pub message_kind: MessageKind,
    pub block: Option<Block>,
    pub attached: Vec<String>,
    pub line_number: u64,
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
}

impl StreamState {
    fn take_idle(&mut self) -> StreamState {
        std::mem::replace(self, StreamState::Idle)
    }
}

pub struct LogStream<I> {
    lines: I,
    last_uuid: String,
    last_timestamp: String,
    pending: Option<LogEntry>,
    state: StreamState,
    stats: ParseStats,
    tracking: UnclassifiedTracking,
    line_number: u64,
}

impl<I: Iterator<Item = String>> LogStream<I> {
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
        }
    }

    pub fn unclassified_tracking(mut self, level: UnclassifiedTracking) -> Self {
        self.tracking = level;
        self
    }

    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

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

    fn finalize_block(&mut self) -> Option<Block> {
        match self.state.take_idle() {
            StreamState::Idle => None,
            StreamState::InChannelData {
                fields,
                mut variables,
                open_var_name,
                open_var_value,
            } => {
                if let (Some(name), Some(value)) = (open_var_name, open_var_value) {
                    variables.push((name, value));
                }
                Some(Block::ChannelData { fields, variables })
            }
            StreamState::InSdp { direction, body } => Some(Block::Sdp { direction, body }),
        }
    }

    fn finalize_pending(&mut self) -> Option<LogEntry> {
        let block = self.finalize_block();
        if let Some(ref mut p) = self.pending {
            p.block = block;
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
            _ => StreamState::Idle,
        };
    }

    fn accumulate_continuation(&mut self, msg: &str, line: &str) {
        let msg_kind = classify_message(msg);
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
                            }
                        }
                    }
                }
            }
            StreamState::InSdp { body, .. } => {
                body.push(msg.to_string());
            }
            StreamState::Idle => {}
        }
        if let Some(ref mut pending) = self.pending {
            pending.attached.push(line.to_string());
        }
    }

    fn new_entry(
        &self,
        uuid: String,
        timestamp: String,
        message: String,
        kind: LineKind,
        message_kind: MessageKind,
    ) -> LogEntry {
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
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for LogStream<I> {
    type Item = LogEntry;

    fn next(&mut self) -> Option<LogEntry> {
        loop {
            let Some(line) = self.lines.next() else {
                return self.finalize_pending();
            };

            self.line_number += 1;
            self.stats.lines_processed += 1;

            let parsed = parse_line(&line);

            match parsed.kind {
                LineKind::Full | LineKind::System | LineKind::Truncated => {
                    let yielded = self.finalize_pending();

                    let uuid = parsed.uuid.unwrap_or("").to_string();
                    let timestamp = parsed
                        .timestamp
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| self.last_timestamp.clone());
                    let message_kind = classify_message(parsed.message);

                    if !uuid.is_empty() {
                        self.last_uuid = uuid.clone();
                    }
                    if parsed.timestamp.is_some() {
                        self.last_timestamp = timestamp.clone();
                    }

                    self.start_block_for_message(&message_kind);

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
                        if !is_primary && (uuid == pending.uuid || pending.uuid.is_empty()) {
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
    fn no_block_for_general_message() {
        let lines = vec![full_line(UUID1, TS1, "CoreSession::setVariable(foo, bar)")];
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
}
