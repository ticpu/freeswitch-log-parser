use std::collections::HashMap;
use std::str::FromStr;

use freeswitch_types::CallDirection;

use crate::line::parse_line;
use crate::message::{classify_message, MessageKind};
use crate::stream::{Block, LogEntry, LogStream, ParseStats, UnclassifiedLine};

/// Mutable per-UUID state accumulator, updated as entries are processed.
///
/// Fields are `None` until the corresponding data is first seen in the stream.
/// Variables accumulate from CHANNEL_DATA dumps, `set()`/`export()` executions,
/// `SET`/`EXPORT` log lines, and inline `variable_*` lines.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// `None` until a `Channel-Name` field is encountered.
    pub channel_name: Option<String>,
    /// `None` until a state change or `Channel-State` field is encountered.
    pub channel_state: Option<String>,
    /// First dialplan context seen; set once and never overwritten.
    pub initial_context: Option<String>,
    /// Current dialplan context; updated on each transfer/continue.
    pub dialplan_context: Option<String>,
    /// Source extension in the dialplan routing; `None` until a dialplan line is processed.
    pub dialplan_from: Option<String>,
    /// Target extension in the dialplan routing; `None` until a dialplan line is processed.
    pub dialplan_to: Option<String>,
    /// Call direction from `Call-Direction` CHANNEL_DATA field; `None` until seen.
    pub call_direction: Option<CallDirection>,
    /// Caller ID number from `Caller-Caller-ID-Number` CHANNEL_DATA field; `None` until seen.
    pub caller_id_number: Option<String>,
    /// Destination number from `Caller-Destination-Number` CHANNEL_DATA field; `None` until seen.
    pub destination_number: Option<String>,
    /// All variables learned so far, with the `variable_` prefix stripped from names.
    pub variables: HashMap<String, String>,
}

/// Immutable point-in-time copy of a session's state, attached to each [`EnrichedEntry`].
///
/// Does not include `variables` to keep snapshots lightweight — access the full
/// variable map via [`SessionTracker::sessions()`].
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub channel_name: Option<String>,
    pub channel_state: Option<String>,
    pub initial_context: Option<String>,
    pub dialplan_context: Option<String>,
    pub dialplan_from: Option<String>,
    pub dialplan_to: Option<String>,
    pub call_direction: Option<CallDirection>,
    pub caller_id_number: Option<String>,
    pub destination_number: Option<String>,
}

impl SessionState {
    fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            channel_name: self.channel_name.clone(),
            channel_state: self.channel_state.clone(),
            initial_context: self.initial_context.clone(),
            dialplan_context: self.dialplan_context.clone(),
            dialplan_from: self.dialplan_from.clone(),
            dialplan_to: self.dialplan_to.clone(),
            call_direction: self.call_direction,
            caller_id_number: self.caller_id_number.clone(),
            destination_number: self.destination_number.clone(),
        }
    }

    fn update_from_entry(&mut self, entry: &LogEntry) {
        if let Some(Block::ChannelData { fields, variables }) = &entry.block {
            for (name, value) in fields {
                match name.as_str() {
                    "Channel-Name" => self.channel_name = Some(value.clone()),
                    "Channel-State" => self.channel_state = Some(value.clone()),
                    "Call-Direction" => {
                        self.call_direction = CallDirection::from_str(value).ok();
                    }
                    "Caller-Caller-ID-Number" => {
                        self.caller_id_number = Some(value.clone());
                    }
                    "Caller-Destination-Number" => {
                        self.destination_number = Some(value.clone());
                    }
                    _ => {}
                }
            }
            for (name, value) in variables {
                let var_name = name.strip_prefix("variable_").unwrap_or(name);
                self.variables.insert(var_name.to_string(), value.clone());
            }
        }

        match &entry.message_kind {
            MessageKind::Dialplan { detail, .. } => {
                if let Some(dp) = parse_dialplan_context(detail) {
                    self.initial_context.get_or_insert(dp.context.clone());
                    self.dialplan_context = Some(dp.context);
                    self.dialplan_from = Some(dp.from);
                    self.dialplan_to = Some(dp.to);
                }
            }
            MessageKind::Execute {
                application,
                arguments,
                ..
            } => match application.as_str() {
                "set" | "export" => {
                    if let Some((name, value)) = arguments.split_once('=') {
                        self.variables.insert(name.to_string(), value.to_string());
                    }
                }
                _ => {}
            },
            MessageKind::Variable { name, value } => {
                let var_name = name.strip_prefix("variable_").unwrap_or(name);
                self.variables.insert(var_name.to_string(), value.clone());
            }
            MessageKind::ChannelField { name, value } => match name.as_str() {
                "Channel-Name" => self.channel_name = Some(value.clone()),
                "Channel-State" => self.channel_state = Some(value.clone()),
                _ => {}
            },
            MessageKind::StateChange { detail } => {
                if let Some(new_state) = parse_state_change(detail) {
                    self.channel_state = Some(new_state);
                }
            }
            MessageKind::ChannelLifecycle { detail } => {
                if let Some(name) = parse_new_channel(detail) {
                    if self.channel_name.is_none() {
                        self.channel_name = Some(name);
                    }
                }
            }
            _ => {}
        }

        if entry.message.contains("Processing ") && entry.message.contains(" in context ") {
            if let Some(dp) = parse_processing_line(&entry.message) {
                self.initial_context.get_or_insert(dp.context.clone());
                self.dialplan_context = Some(dp.context);
                self.dialplan_from = Some(dp.from);
                self.dialplan_to = Some(dp.to);
            }
        }

        for attached in &entry.attached {
            let parsed = parse_line(attached);
            self.update_from_message(parsed.message);
        }
    }

    fn update_from_message(&mut self, msg: &str) {
        let kind = classify_message(msg);
        match &kind {
            MessageKind::Dialplan { detail, .. } => {
                if let Some(dp) = parse_dialplan_context(detail) {
                    self.initial_context.get_or_insert(dp.context.clone());
                    self.dialplan_context = Some(dp.context);
                    self.dialplan_from = Some(dp.from);
                    self.dialplan_to = Some(dp.to);
                }
            }
            MessageKind::Variable { name, value } => {
                let var_name = name.strip_prefix("variable_").unwrap_or(name);
                self.variables.insert(var_name.to_string(), value.clone());
            }
            MessageKind::ChannelField { name, value } => match name.as_str() {
                "Channel-Name" => self.channel_name = Some(value.clone()),
                "Channel-State" => self.channel_state = Some(value.clone()),
                _ => {}
            },
            MessageKind::StateChange { detail } => {
                if let Some(new_state) = parse_state_change(detail) {
                    self.channel_state = Some(new_state);
                }
            }
            _ => {}
        }
    }
}

struct DialplanContext {
    from: String,
    to: String,
    context: String,
}

fn parse_dialplan_context(detail: &str) -> Option<DialplanContext> {
    if !detail.starts_with("parsing [") {
        return None;
    }
    let rest = &detail["parsing [".len()..];
    let bracket_end = rest.find(']')?;
    let inner = &rest[..bracket_end];

    let arrow = inner.find("->")?;
    let from_part = &inner[..arrow];
    let to_part = &inner[arrow + 2..];

    let context = if rest.len() > bracket_end + 1 {
        let after = rest[bracket_end + 1..].trim();
        if let Some(stripped) = after.strip_prefix("continue=") {
            let _ = stripped;
        }
        from_part.to_string()
    } else {
        from_part.to_string()
    };

    Some(DialplanContext {
        from: from_part.to_string(),
        to: to_part.to_string(),
        context,
    })
}

fn parse_processing_line(msg: &str) -> Option<DialplanContext> {
    let proc_idx = msg.find("Processing ")?;
    let rest = &msg[proc_idx + "Processing ".len()..];

    let arrow = rest.find("->")?;
    let from = &rest[..arrow];

    let after_arrow = &rest[arrow + 2..];
    let space = after_arrow.find(' ')?;
    let to = &after_arrow[..space];

    let ctx_idx = after_arrow.find("in context ")?;
    let ctx_rest = &after_arrow[ctx_idx + "in context ".len()..];
    let context = ctx_rest.split_whitespace().next()?;

    Some(DialplanContext {
        from: from.to_string(),
        to: to.to_string(),
        context: context.to_string(),
    })
}

fn parse_new_channel(detail: &str) -> Option<String> {
    let rest = detail.strip_prefix("New Channel ")?;
    let bracket = rest.rfind(" [")?;
    Some(rest[..bracket].to_string())
}

fn parse_state_change(detail: &str) -> Option<String> {
    let arrow = detail.find(" -> ")?;
    Some(detail[arrow + 4..].trim().to_string())
}

/// A [`LogEntry`] paired with the session's state snapshot at that point in time.
#[derive(Debug)]
pub struct EnrichedEntry {
    pub entry: LogEntry,
    /// `None` for system lines (entries with an empty UUID).
    pub session: Option<SessionSnapshot>,
}

/// Layer 3 per-session state machine — tracks per-UUID state (dialplan context,
/// channel state, variables) across entries and yields [`EnrichedEntry`] values.
///
/// Wraps a [`LogStream`] and maintains a `HashMap<String, SessionState>` keyed by UUID.
/// Sessions are never automatically cleaned up; call [`remove_session()`](SessionTracker::remove_session)
/// when a call ends.
pub struct SessionTracker<I> {
    inner: LogStream<I>,
    sessions: HashMap<String, SessionState>,
}

impl<I: Iterator<Item = String>> SessionTracker<I> {
    /// Wrap a [`LogStream`] to add per-session state tracking.
    pub fn new(inner: LogStream<I>) -> Self {
        SessionTracker {
            inner,
            sessions: HashMap::new(),
        }
    }

    /// All currently tracked sessions, keyed by UUID.
    pub fn sessions(&self) -> &HashMap<String, SessionState> {
        &self.sessions
    }

    /// Remove and return a session's accumulated state. Call this when a call ends
    /// (e.g. `CS_DESTROY` or hangup) to free memory.
    pub fn remove_session(&mut self, uuid: &str) -> Option<SessionState> {
        self.sessions.remove(uuid)
    }

    /// Delegates to [`LogStream::stats()`].
    pub fn stats(&self) -> &ParseStats {
        self.inner.stats()
    }

    /// Delegates to [`LogStream::drain_unclassified()`].
    pub fn drain_unclassified(&mut self) -> Vec<UnclassifiedLine> {
        self.inner.drain_unclassified()
    }
}

impl<I: Iterator<Item = String>> Iterator for SessionTracker<I> {
    type Item = EnrichedEntry;

    fn next(&mut self) -> Option<EnrichedEntry> {
        let entry = self.inner.next()?;

        if entry.uuid.is_empty() {
            return Some(EnrichedEntry {
                entry,
                session: None,
            });
        }

        let state = self.sessions.entry(entry.uuid.clone()).or_default();
        state.update_from_entry(&entry);
        let snapshot = state.snapshot();

        Some(EnrichedEntry {
            entry,
            session: Some(snapshot),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const UUID2: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
    const TS1: &str = "2025-01-15 10:30:45.123456";
    const TS2: &str = "2025-01-15 10:30:46.234567";

    fn full_line(uuid: &str, ts: &str, msg: &str) -> String {
        format!("{uuid} {ts} 95.97% [DEBUG] sofia.c:100 {msg}")
    }

    fn collect_enriched(lines: Vec<String>) -> Vec<EnrichedEntry> {
        let stream = LogStream::new(lines.into_iter());
        SessionTracker::new(stream).collect()
    }

    #[test]
    fn system_line_no_session() {
        let lines = vec![format!(
            "{TS1} 95.97% [INFO] mod_event_socket.c:1772 Event Socket command"
        )];
        let entries = collect_enriched(lines);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].session.is_none());
    }

    #[test]
    fn dialplan_context_propagation() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 answer"),
            format!("{UUID1} Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public->global] continue=true"),
            full_line(UUID1, TS2, "Some later event"),
        ];
        let entries = collect_enriched(lines);
        let last = entries.last().unwrap();
        let session = last.session.as_ref().unwrap();
        assert_eq!(session.dialplan_context.as_deref(), Some("public"));
        assert_eq!(session.dialplan_from.as_deref(), Some("public"));
        assert_eq!(session.dialplan_to.as_deref(), Some("global"));
    }

    #[test]
    fn processing_line_extracts_context() {
        let lines = vec![full_line(
            UUID1,
            TS1,
            "Processing 5551234567->5559876543 in context public",
        )];
        let entries = collect_enriched(lines);
        let session = entries[0].session.as_ref().unwrap();
        assert_eq!(session.dialplan_context.as_deref(), Some("public"));
        assert_eq!(session.dialplan_from.as_deref(), Some("5551234567"));
        assert_eq!(session.dialplan_to.as_deref(), Some("5559876543"));
    }

    #[test]
    fn initial_context_preserved_across_transfers() {
        let lines = vec![
            full_line(
                UUID1,
                TS1,
                "Processing 5551234567->5559876543 in context public",
            ),
            full_line(
                UUID1,
                TS2,
                "Processing 5551234567->start_recording in context recordings",
            ),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let entries: Vec<_> = tracker.by_ref().collect();

        let first = entries[0].session.as_ref().unwrap();
        assert_eq!(
            first.initial_context.as_deref(),
            Some("public"),
            "initial_context set on first Processing line"
        );
        assert_eq!(first.dialplan_context.as_deref(), Some("public"));

        let state = tracker.sessions().get(UUID1).unwrap();
        assert_eq!(
            state.initial_context.as_deref(),
            Some("public"),
            "initial_context keeps the first context seen"
        );
        assert_eq!(
            state.dialplan_context.as_deref(),
            Some("recordings"),
            "dialplan_context tracks the current context"
        );
        assert_eq!(state.dialplan_to.as_deref(), Some("start_recording"));
    }

    #[test]
    fn new_channel_sets_channel_name() {
        let lines = vec![full_line(
            UUID1,
            TS1,
            "New Channel sofia/internal-v4/sos [a1b2c3d4-e5f6-7890-abcd-ef1234567890]",
        )];
        let entries = collect_enriched(lines);
        let session = entries[0].session.as_ref().unwrap();
        assert_eq!(
            session.channel_name.as_deref(),
            Some("sofia/internal-v4/sos")
        );
    }

    #[test]
    fn channel_data_populates_session() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} Channel-State: [CS_EXECUTE]"),
            "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
            "variable_direction: [inbound]".to_string(),
        ];
        let entries = collect_enriched(lines);
        assert_eq!(entries.len(), 1);
        let session = entries[0].session.as_ref().unwrap();
        assert_eq!(
            session.channel_name.as_deref(),
            Some("sofia/internal/+15550001234@192.0.2.1")
        );
        assert_eq!(session.channel_state.as_deref(), Some("CS_EXECUTE"));
    }

    #[test]
    fn variables_learned_from_channel_data() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
            "variable_direction: [inbound]".to_string(),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let _: Vec<_> = tracker.by_ref().collect();
        let state = tracker.sessions().get(UUID1).unwrap();
        assert_eq!(
            state.variables.get("sip_call_id").map(|s| s.as_str()),
            Some("test123@192.0.2.1")
        );
        assert_eq!(
            state.variables.get("direction").map(|s| s.as_str()),
            Some("inbound")
        );
    }

    #[test]
    fn variables_learned_from_set_execute() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(call_direction=inbound)"),
            full_line(UUID1, TS2, "After set"),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let entries: Vec<_> = tracker.by_ref().collect();
        assert_eq!(entries.len(), 3);
        let state = tracker.sessions().get(UUID1).unwrap();
        assert_eq!(
            state.variables.get("call_direction").map(|s| s.as_str()),
            Some("inbound")
        );
    }

    #[test]
    fn variables_learned_from_export_execute() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)"),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let _: Vec<_> = tracker.by_ref().collect();
        let state = tracker.sessions().get(UUID1).unwrap();
        assert_eq!(
            state.variables.get("originate_timeout").map(|s| s.as_str()),
            Some("3600")
        );
    }

    #[test]
    fn session_isolation_between_uuids() {
        let lines = vec![
            full_line(
                UUID1,
                TS1,
                "Processing 5551111111->5552222222 in context public",
            ),
            full_line(
                UUID2,
                TS2,
                "Processing 5553333333->5554444444 in context private",
            ),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let _: Vec<_> = tracker.by_ref().collect();
        let s1 = tracker.sessions().get(UUID1).unwrap();
        let s2 = tracker.sessions().get(UUID2).unwrap();
        assert_eq!(s1.dialplan_context.as_deref(), Some("public"));
        assert_eq!(s2.dialplan_context.as_deref(), Some("private"));
        assert_eq!(s1.dialplan_from.as_deref(), Some("5551111111"));
        assert_eq!(s2.dialplan_from.as_deref(), Some("5553333333"));
    }

    #[test]
    fn state_change_updates_channel_state() {
        let lines = vec![full_line(UUID1, TS1, "State Change CS_INIT -> CS_ROUTING")];
        let entries = collect_enriched(lines);
        let session = entries[0].session.as_ref().unwrap();
        assert_eq!(session.channel_state.as_deref(), Some("CS_ROUTING"));
    }

    #[test]
    fn remove_session() {
        let lines = vec![full_line(
            UUID1,
            TS1,
            "Processing 5551111111->5552222222 in context public",
        )];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let _: Vec<_> = tracker.by_ref().collect();
        assert!(tracker.sessions().contains_key(UUID1));
        let removed = tracker.remove_session(UUID1).unwrap();
        assert_eq!(removed.dialplan_context.as_deref(), Some("public"));
        assert!(!tracker.sessions().contains_key(UUID1));
    }

    #[test]
    fn stats_delegation() {
        let lines = vec![
            full_line(UUID1, TS1, "First"),
            full_line(UUID1, TS2, "Second"),
        ];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        let _: Vec<_> = tracker.by_ref().collect();
        assert_eq!(tracker.stats().lines_processed, 2);
    }

    #[test]
    fn snapshot_reflects_cumulative_state() {
        let lines = vec![
            full_line(UUID1, TS1, "CHANNEL_DATA:"),
            format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
            format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"),
            full_line(
                UUID1,
                TS2,
                "Processing 5551111111->5552222222 in context public",
            ),
        ];
        let entries = collect_enriched(lines);
        assert_eq!(entries.len(), 3);
        let first = entries[0].session.as_ref().unwrap();
        assert_eq!(
            first.channel_name.as_deref(),
            Some("sofia/internal/+15550001234@192.0.2.1"),
        );
        assert!(first.dialplan_context.is_none());

        let last = entries[2].session.as_ref().unwrap();
        assert_eq!(
            last.channel_name.as_deref(),
            Some("sofia/internal/+15550001234@192.0.2.1"),
        );
        assert_eq!(last.dialplan_context.as_deref(), Some("public"));
    }
}
