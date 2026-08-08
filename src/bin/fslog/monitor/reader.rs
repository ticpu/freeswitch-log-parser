//! The reader thread — parses log segments into row updates and applies them
//! to the UI state.

use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Instant;

use log::{error, warn};

use freeswitch_log_parser::{
    CallDirection, ChannelState, ChannelVariable, EnrichedEntry, LogStream, MessageKind,
    SessionState, SessionTracker, SofiaVariable, TrackedChain,
};

use crate::files::{discover_log_files, open_full_tail_reader, open_log_reader};

use super::model::{AppState, CallEnd, CallEvent, CallFields, CallRow, ReaderMsg};

pub(super) fn build_update(
    enriched: &EnrichedEntry,
    sessions: &std::collections::HashMap<String, SessionState>,
) -> Option<ReaderMsg> {
    let uuid = enriched.entry.uuid.clone();
    if uuid.is_empty() || enriched.entry.timestamp.is_empty() {
        return None;
    }

    let cs_destroy = ChannelState::CsDestroy.to_string();
    let is_hangup = matches!(
        &enriched.entry.message_kind,
        MessageKind::ChannelLifecycle { detail }
            if detail.contains("Hangup") || detail.contains("Destroy")
    ) || matches!(
        &enriched.entry.message_kind,
        MessageKind::StateChange { detail }
            if detail.contains(cs_destroy.as_str())
    );

    let is_new_channel = matches!(
        &enriched.entry.message_kind,
        MessageKind::ChannelLifecycle { detail }
            if detail.starts_with("New Channel ")
    );

    let snap = enriched.session.as_ref();
    let state = sessions.get(&uuid);

    let event = if is_hangup {
        Some(CallEvent::Hangup)
    } else if is_new_channel {
        Some(CallEvent::NewChannel)
    } else {
        None
    };

    let fields = CallFields {
        other_leg_uuid: state
            .and_then(|s| s.other_leg_uuid.clone())
            .or_else(|| snap.and_then(|s| s.other_leg_uuid.clone())),
        channel_state: state
            .and_then(|s| s.channel_state)
            .or_else(|| snap.and_then(|s| s.channel_state)),
        call_state: state
            .and_then(|s| s.call_state)
            .or_else(|| snap.and_then(|s| s.call_state)),
        context: state
            .and_then(|s| s.initial_context.clone())
            .or_else(|| snap.and_then(|s| s.initial_context.clone())),
        direction: state.and_then(|s| s.call_direction).or_else(|| {
            state.and_then(|s| {
                s.variables
                    .get(ChannelVariable::Direction.as_str())
                    .and_then(|v| CallDirection::from_str(v).ok())
            })
        }),
        caller: state
            .and_then(|s| s.caller_id_number.clone())
            .or_else(|| {
                state.and_then(|s| {
                    s.variables
                        .get(SofiaVariable::SipFromUser.as_str())
                        .cloned()
                })
            })
            .or_else(|| state.and_then(|s| s.dialplan_from.clone())),
        callee: state
            .and_then(|s| s.destination_number.clone())
            .or_else(|| {
                state.and_then(|s| s.variables.get(SofiaVariable::SipToUser.as_str()).cloned())
            })
            .or_else(|| state.and_then(|s| s.dialplan_to.clone())),
    };

    Some(ReaderMsg {
        timestamp: enriched.entry.timestamp.clone(),
        uuid,
        fields,
        event,
    })
}
/// The tracker lives with the reader, so removal must happen here.
pub(super) fn drain_session_removals<I: Iterator<Item = String>>(
    tracker: &mut SessionTracker<I>,
    remove_rx: &mpsc::Receiver<String>,
) {
    while let Ok(uuid) = remove_rx.try_recv() {
        tracker.remove_session(&uuid);
    }
}

pub(super) type LineIter = Box<dyn Iterator<Item = String>>;

/// Build the parse segments: the newest rotated file (if any, skipped with a
/// warning on failure) followed by the current log opened via `open_current`
/// (full-then-tail for the TUI, plain read for --dump).
pub(super) fn build_segments(
    dir: &Path,
    path: &Path,
    open_current: fn(&Path) -> io::Result<LineIter>,
) -> io::Result<Vec<(String, LineIter)>> {
    let mut segments: Vec<(String, LineIter)> = Vec::new();

    match discover_log_files(dir) {
        Ok(files) => {
            if let Some(prev) = files.iter().rev().find(|f| f.date.is_some()) {
                match open_log_reader(&prev.path) {
                    Ok(reader) => {
                        let name = prev
                            .path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();
                        segments.push((name, reader));
                    }
                    Err(e) => warn!(
                        "skipping rotated history {}: open failed: {e}",
                        prev.path.display()
                    ),
                }
            }
        }
        Err(e) => warn!(
            "skipping rotated history: discovery in {} failed: {e}",
            dir.display()
        ),
    }

    let current = open_current(path)?;
    let current_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    segments.push((current_name, current));
    Ok(segments)
}

pub(super) fn spawn_reader(
    dir: PathBuf,
    path: PathBuf,
    tx: mpsc::Sender<ReaderMsg>,
    remove_rx: mpsc::Receiver<String>,
) -> io::Result<std::thread::JoinHandle<()>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", path.display()),
        ));
    }
    let handle = std::thread::spawn(move || {
        let segments = match build_segments(&dir, &path, open_full_tail_reader) {
            Ok(s) => s,
            Err(e) => {
                error!("reader failed to open {}: {e}", path.display());
                return;
            }
        };

        let (chain, _seg_tracker) = TrackedChain::new(segments);
        let stream = LogStream::new(chain);
        let mut tracker = SessionTracker::new(stream);

        while let Some(enriched) = tracker.next() {
            drain_session_removals(&mut tracker, &remove_rx);
            if let Some(msg) = build_update(&enriched, tracker.sessions()) {
                if tx.send(msg).is_err() {
                    break;
                }
            }
        }
    });
    Ok(handle)
}

pub(super) fn apply_update(state: &mut AppState, msg: ReaderMsg) {
    let ReaderMsg {
        uuid,
        timestamp,
        fields,
        event,
    } = msg;

    if !timestamp.is_empty() && timestamp > state.latest_timestamp {
        state.latest_timestamp.clone_from(&timestamp);
    }

    let is_hangup = matches!(event, Some(CallEvent::Hangup));

    if state.filtered_uuids.contains(&uuid) {
        if is_hangup {
            state.filtered_uuids.remove(&uuid);
            state.request_session_removal(uuid);
        }
        return;
    }

    let uuid_key = uuid.clone();
    if let Some(row) = state.calls.iter_mut().find(|r| r.uuid == uuid_key) {
        if !timestamp.is_empty() {
            row.log_last = timestamp.clone();
        }
        row.fields.merge(fields);
        if is_hangup && row.end.is_none() {
            row.end = Some(CallEnd {
                at: Instant::now(),
                log_ts: timestamp,
            });
        }
    } else if matches!(event, Some(CallEvent::NewChannel)) {
        state.calls.push(CallRow {
            uuid,
            fields,
            log_last: timestamp.clone(),
            log_start: timestamp,
            end: None,
            first_seen: Instant::now(),
        });
    } else {
        if is_hangup {
            // No row exists and none will linger, so the tracker's session
            // state for this UUID would otherwise never be freed.
            state.request_session_removal(uuid_key);
        }
        return;
    }

    if let Some(pos) = state.calls.iter().position(|r| r.uuid == uuid_key) {
        if !state
            .context_filter
            .matches(state.calls[pos].fields.context.as_deref())
        {
            state.calls.remove(pos);
            state.filtered_uuids.insert(uuid_key);
            return;
        }
    }

    state.sort_calls();
}

pub(super) fn gc_ended(state: &mut AppState) {
    let linger = state.linger;
    let mut expired = Vec::new();
    state.calls.retain(|r| {
        let keep = r.end.as_ref().is_none_or(|e| e.at.elapsed() < linger);
        if !keep {
            expired.push(r.uuid.clone());
        }
        keep
    });
    for uuid in expired {
        state.request_session_removal(uuid);
    }
    if let Some(ref uuid) = state.selected_uuid {
        if !state.calls.iter().any(|r| r.uuid == *uuid) {
            state.selected_uuid = state.calls.first().map(|r| r.uuid.clone());
        }
    }
}
