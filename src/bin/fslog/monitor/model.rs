//! The rows the monitor keeps and the UI state around them.

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config::Tool;

use freeswitch_log_parser::{CallDirection, CallState, ChannelState};

/// Channel state parsed once at the reader boundary: usually a `CS_*`
/// ChannelState, sometimes a CallState; anything else passes through raw.
pub(super) enum LegState {
    Channel(ChannelState),
    Call(CallState),
    Raw(String),
}

impl LegState {
    pub(super) fn parse(raw: &str) -> Self {
        if let Ok(cs) = ChannelState::from_str(raw) {
            LegState::Channel(cs)
        } else if let Ok(cs) = CallState::from_str(raw) {
            LegState::Call(cs)
        } else {
            LegState::Raw(raw.to_string())
        }
    }

    /// Short column label for the call table.
    pub(super) fn short(&self) -> String {
        match self {
            LegState::Channel(ChannelState::CsExchangeMedia) => "MEDIA".to_string(),
            LegState::Channel(ChannelState::CsConsumeMedia) => "CONSUME".to_string(),
            LegState::Channel(ChannelState::CsSoftExecute) => "SOFTEX".to_string(),
            LegState::Channel(ChannelState::CsReporting) => "REPORT".to_string(),
            LegState::Channel(cs) => {
                let s = cs.to_string();
                s.strip_prefix("CS_").unwrap_or(&s).to_string()
            }
            LegState::Call(cs) => cs.to_string(),
            LegState::Raw(s) => s.clone(),
        }
    }
}

/// Call fields carried by reader updates and merged into the table row.
#[derive(Default)]
pub(super) struct CallFields {
    pub(super) other_leg_uuid: Option<String>,
    pub(super) direction: Option<CallDirection>,
    pub(super) caller: Option<String>,
    pub(super) callee: Option<String>,
    pub(super) channel_state: Option<LegState>,
    pub(super) context: Option<String>,
}

impl CallFields {
    /// Field-wise merge: `Some` in `update` overwrites, `None` keeps existing.
    pub(super) fn merge(&mut self, update: CallFields) {
        let CallFields {
            other_leg_uuid,
            direction,
            caller,
            callee,
            channel_state,
            context,
        } = update;
        if other_leg_uuid.is_some() {
            self.other_leg_uuid = other_leg_uuid;
        }
        if direction.is_some() {
            self.direction = direction;
        }
        if caller.is_some() {
            self.caller = caller;
        }
        if callee.is_some() {
            self.callee = callee;
        }
        if channel_state.is_some() {
            self.channel_state = channel_state;
        }
        if context.is_some() {
            self.context = context;
        }
    }
}

/// When a call ended: wall clock for linger GC, log timestamp for display.
pub(super) struct CallEnd {
    pub(super) at: Instant,
    pub(super) log_ts: String,
}

pub(super) struct CallRow {
    pub(super) uuid: String,
    pub(super) fields: CallFields,
    pub(super) log_start: String,
    pub(super) log_last: String,
    pub(super) end: Option<CallEnd>,
    pub(super) first_seen: Instant,
}

pub(super) enum ContextFilter {
    None,
    Include(Vec<String>),
    Exclude(Vec<String>),
}

impl ContextFilter {
    pub(super) fn parse(spec: &str) -> Self {
        let tokens: Vec<&str> = spec
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if tokens.is_empty() {
            return Self::None;
        }
        if tokens[0].starts_with('-') {
            Self::Exclude(
                tokens
                    .iter()
                    .map(|t| t.strip_prefix('-').unwrap_or(t).to_string())
                    .collect(),
            )
        } else {
            Self::Include(tokens.iter().map(|t| t.to_string()).collect())
        }
    }

    pub(super) fn matches(&self, context: Option<&str>) -> bool {
        match self {
            Self::None => true,
            Self::Include(list) => context.is_some_and(|c| list.iter().any(|f| c == f)),
            Self::Exclude(list) => context.is_none_or(|c| !list.iter().any(|f| c == f)),
        }
    }
}

/// Which overlay owns the keyboard. The action menu always has a target, and
/// the leg picker and menu cannot both be open — illegal combinations are
/// unrepresentable.
pub(super) enum UiMode {
    Table,
    LegPicker {
        selected: usize,
    },
    Menu {
        target_uuid: String,
        selected: usize,
    },
}

pub(super) struct AppState {
    pub(super) calls: Vec<CallRow>,
    pub(super) selected_uuid: Option<String>,
    pub(super) ui_mode: UiMode,
    pub(super) tools: Vec<Tool>,
    pub(super) linger: Duration,
    pub(super) should_quit: bool,
    pub(super) dir: PathBuf,
    pub(super) page_size: usize,
    pub(super) context_filter: ContextFilter,
    pub(super) filtered_uuids: HashSet<String>,
    pub(super) latest_timestamp: String,
    /// Requests the reader thread drop a UUID's SessionTracker state; `None`
    /// in one-shot (dump) mode where the tracker dies with the read.
    pub(super) remove_tx: Option<mpsc::Sender<String>>,
}

impl AppState {
    pub(super) fn new(
        dir: PathBuf,
        context_filter: ContextFilter,
        tools: Vec<Tool>,
        linger: Duration,
    ) -> Self {
        AppState {
            calls: Vec::new(),
            selected_uuid: None,
            ui_mode: UiMode::Table,
            tools,
            linger,
            should_quit: false,
            dir,
            page_size: 20,
            context_filter,
            filtered_uuids: HashSet::new(),
            latest_timestamp: String::new(),
            remove_tx: None,
        }
    }

    pub(super) fn selected_index(&self) -> usize {
        match &self.selected_uuid {
            Some(uuid) => self.calls.iter().position(|r| r.uuid == *uuid).unwrap_or(0),
            None => 0,
        }
    }

    pub(super) fn select_index(&mut self, idx: usize) {
        self.selected_uuid = self.calls.get(idx).map(|r| r.uuid.clone());
    }

    pub(super) fn request_session_removal(&mut self, uuid: String) {
        if let Some(tx) = &self.remove_tx {
            // A closed channel means the reader thread (and its tracker) is
            // gone, so there is no session state left to free.
            if tx.send(uuid).is_err() {
                self.remove_tx = None;
            }
        }
    }

    pub(super) fn sort_calls(&mut self) {
        self.calls.sort_by(|a, b| {
            let a_ended = a.end.is_some();
            let b_ended = b.end.is_some();
            match (a_ended, b_ended) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => b.first_seen.cmp(&a.first_seen),
            }
        });
    }
}

/// Lifecycle transition detected in a log entry, if any.
pub(super) enum CallEvent {
    NewChannel,
    Hangup,
}

pub(super) struct ReaderMsg {
    pub(super) uuid: String,
    pub(super) timestamp: String,
    pub(super) fields: CallFields,
    pub(super) event: Option<CallEvent>,
}
