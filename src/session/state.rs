//! Per-UUID accumulated state and the point-in-time snapshot attached to each
//! enriched entry.

use std::collections::HashMap;
use std::str::FromStr;

use freeswitch_types::variables::{SofiaVariable, VariableName};
use freeswitch_types::{CallDirection, CallState, ChannelState, EventHeader, HangupCause};

use crate::line::parse_line;
use crate::message::{classify_message, LifecycleEvent, MessageKind};
use crate::stream::{Block, LogEntry, ParseWarning, SessionReading};
use crate::uuid::is_uuid;

use super::conference::ConferenceMembership;
use super::media::SessionMedia;
use super::parse::{
    parse_bridge_args, parse_dialplan_context, parse_hangup, parse_new_channel,
    parse_processing_line, parse_state_change, StateChange,
};

/// Resolve a typed value into `slot`, or record that it could not be read.
///
/// The failed reading leaves whatever `slot` already held — a repeat of a field
/// the vocabulary cannot read must not erase what an earlier one established.
fn read<T: FromStr>(
    slot: &mut Option<T>,
    value: &str,
    reading: SessionReading,
    warnings: &mut Vec<ParseWarning>,
) {
    match T::from_str(value) {
        Ok(parsed) => *slot = Some(parsed),
        Err(_) => warnings.push(ParseWarning::UnreadableValue {
            reading,
            value: ParseWarning::excerpt(value),
        }),
    }
}

/// Where an entry's dump values come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpSource {
    /// A reassembled block holds them, so the raw attached lines are skipped:
    /// re-applying one would clobber a multi-line value with its first fragment.
    Block,
    /// The attached lines are all there is.
    AttachedLines,
}

/// Mutable per-UUID state accumulator, updated as entries are processed.
///
/// Fields are `None` until the corresponding data is first seen in the stream.
/// Variables accumulate from CHANNEL_DATA dumps, `set()`/`export()` executions,
/// `SET`/`EXPORT` log lines, and inline `variable_*` lines.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SessionState {
    /// `None` until a `Channel-Name` field is encountered.
    pub channel_name: Option<String>,
    /// `None` until a `State Change` line or a `Channel-State` field is seen.
    pub channel_state: Option<ChannelState>,
    /// `None` until a `Callstate Change` line is seen. A distinct vocabulary from
    /// [`channel_state`](Self::channel_state); neither displaces the other.
    pub call_state: Option<CallState>,
    /// First dialplan context seen; set once and never overwritten.
    pub initial_context: Option<String>,
    /// Destination of the first `Processing` line = the dialed number at ingress;
    /// set once and never overwritten (unlike last-wins `dialplan_to`).
    pub initial_destination: Option<String>,
    /// Number half of the first `Processing` line's caller side, the caller
    /// profile's `caller_id_number` at ingress. Set once, and first *seen*: a
    /// window starting mid-call pins whatever line arrived first in it.
    pub initial_caller_number: Option<String>,
    /// Name half of the first `Processing` line's caller side. Set once on the
    /// same terms as [`initial_caller_number`](Self::initial_caller_number), and
    /// a rendering rather than the bytes — the line is session-bound, so the
    /// prefix stage paired off its apostrophes and consumed its backslashes.
    pub initial_caller_name: Option<String>,
    /// Current dialplan context; updated on each transfer/continue.
    pub dialplan_context: Option<String>,
    /// Caller side of the last `Processing` line — a number, or a display name
    /// and number. `None` until one is seen.
    pub dialplan_from: Option<String>,
    /// Dialed destination of the last `Processing` line. `None` until one is seen.
    pub dialplan_to: Option<String>,
    /// Call direction from `Call-Direction` CHANNEL_DATA field; `None` until seen.
    pub call_direction: Option<CallDirection>,
    /// Caller ID number from `Caller-Caller-ID-Number` CHANNEL_DATA field; `None` until seen.
    pub caller_id_number: Option<String>,
    /// Caller ID name from `Caller-Caller-ID-Name` CHANNEL_DATA field; `None` until seen.
    pub caller_id_name: Option<String>,
    /// Destination number from `Caller-Destination-Number` CHANNEL_DATA field; `None` until seen.
    pub destination_number: Option<String>,
    /// Hangup cause extracted from ChannelLifecycle Hangup detail; `None` until hangup seen.
    pub hangup_cause: Option<HangupCause>,
    /// Timestamp when "has been answered" lifecycle event was seen; `None` until answered.
    pub answered_at: Option<String>,
    /// Other leg's UUID; `None` until bridged. Set from `Originate Resulted in Success` on A-leg,
    /// and from `New Channel` on B-leg (back-pointing to A-leg via originate context).
    pub other_leg_uuid: Option<String>,
    /// Conference this session is currently a member of; `None` once it leaves.
    pub conference: Option<ConferenceMembership>,
    /// Codecs negotiated on this leg, by media type and direction.
    pub media: SessionMedia,
    /// Pending bridge target channel from `EXECUTE bridge()`, consumed when B-leg `New Channel` matches.
    pub(crate) pending_bridge_target: Option<String>,
    /// All variables learned so far, with the `variable_` prefix stripped from names.
    pub variables: HashMap<String, String>,
}
/// Immutable point-in-time copy of a session's state, attached to each [`EnrichedEntry`](crate::EnrichedEntry).
///
/// Does not include `variables` to keep snapshots lightweight — access the full
/// variable map via [`SessionTracker::sessions()`](crate::SessionTracker::sessions).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionSnapshot {
    pub channel_name: Option<String>,
    pub channel_state: Option<ChannelState>,
    pub call_state: Option<CallState>,
    pub initial_context: Option<String>,
    pub initial_destination: Option<String>,
    pub initial_caller_number: Option<String>,
    pub initial_caller_name: Option<String>,
    pub dialplan_context: Option<String>,
    pub dialplan_from: Option<String>,
    pub dialplan_to: Option<String>,
    pub call_direction: Option<CallDirection>,
    pub caller_id_number: Option<String>,
    pub caller_id_name: Option<String>,
    pub destination_number: Option<String>,
    pub hangup_cause: Option<HangupCause>,
    pub answered_at: Option<String>,
    pub other_leg_uuid: Option<String>,
    pub conference: Option<ConferenceMembership>,
    pub media: SessionMedia,
}

impl SessionState {
    /// Value of a typed channel variable, or `None` if this session never saw it.
    ///
    /// Accepts any of `freeswitch-types`' variable-name enums, and spares the
    /// caller from knowing that [`variables`](Self::variables) keys are stored
    /// with the `variable_` prefix stripped.
    pub fn variable<V: VariableName>(&self, var: V) -> Option<&str> {
        self.variables.get(var.as_str()).map(String::as_str)
    }

    /// The caller's number, from the most trustworthy source this session saw:
    /// the dump's `Caller-Caller-ID-Number`, then `sip_from_user`, then the
    /// first `Processing` line's number half.
    ///
    /// Whether a leg dumps depends on the box's dialplan and log verbosity, so
    /// the lower rungs are what answer for the legs that never do.
    ///
    /// Not on [`SessionSnapshot`], which carries no variables and so cannot walk
    /// the middle rung.
    pub fn caller_number(&self) -> Option<&str> {
        self.caller_id_number
            .as_deref()
            .or_else(|| self.variable(SofiaVariable::SipFromUser))
            .or(self.initial_caller_number.as_deref())
    }

    /// The dialed number, on the same terms as
    /// [`caller_number`](Self::caller_number): the dump's
    /// `Caller-Destination-Number`, then `sip_to_user`, then the first
    /// `Processing` line's destination.
    pub fn callee_number(&self) -> Option<&str> {
        self.destination_number
            .as_deref()
            .or_else(|| self.variable(SofiaVariable::SipToUser))
            .or(self.initial_destination.as_deref())
    }

    /// Bound exhaustively so a field added here and forgotten in the snapshot
    /// fails to compile; the two `_` bindings are the deliberate omissions.
    pub(super) fn snapshot(&self) -> SessionSnapshot {
        let SessionState {
            channel_name,
            channel_state,
            call_state,
            initial_context,
            initial_destination,
            initial_caller_number,
            initial_caller_name,
            dialplan_context,
            dialplan_from,
            dialplan_to,
            call_direction,
            caller_id_number,
            caller_id_name,
            destination_number,
            hangup_cause,
            answered_at,
            other_leg_uuid,
            conference,
            media,
            pending_bridge_target: _,
            variables: _,
        } = self;

        SessionSnapshot {
            channel_name: channel_name.clone(),
            channel_state: *channel_state,
            call_state: *call_state,
            initial_context: initial_context.clone(),
            initial_destination: initial_destination.clone(),
            initial_caller_number: initial_caller_number.clone(),
            initial_caller_name: initial_caller_name.clone(),
            dialplan_context: dialplan_context.clone(),
            dialplan_from: dialplan_from.clone(),
            dialplan_to: dialplan_to.clone(),
            call_direction: *call_direction,
            caller_id_number: caller_id_number.clone(),
            caller_id_name: caller_id_name.clone(),
            destination_number: destination_number.clone(),
            hangup_cause: *hangup_cause,
            answered_at: answered_at.clone(),
            other_leg_uuid: other_leg_uuid.clone(),
            conference: conference.clone(),
            media: media.clone(),
        }
    }

    /// Absorb one CHANNEL_DATA field. The collision splitter can hand a dump
    /// field over as its own entry rather than inside a block, so both arrival
    /// shapes decode here — a lighter reading on one of them would drop whatever
    /// it left out, `Other-Leg-Unique-ID` included, only for split dumps.
    fn apply_channel_field(&mut self, name: &str, value: &str, warnings: &mut Vec<ParseWarning>) {
        match EventHeader::from_str(name) {
            Ok(EventHeader::ChannelName) => self.channel_name = Some(value.to_string()),
            Ok(EventHeader::ChannelState) => read(
                &mut self.channel_state,
                value,
                SessionReading::ChannelState,
                warnings,
            ),
            Ok(EventHeader::CallDirection) => read(
                &mut self.call_direction,
                value,
                SessionReading::CallDirection,
                warnings,
            ),
            Ok(EventHeader::CallerCallerIdNumber) => {
                self.caller_id_number = Some(value.to_string())
            }
            Ok(EventHeader::CallerCallerIdName) => self.caller_id_name = Some(value.to_string()),
            Ok(EventHeader::CallerDestinationNumber) => {
                self.destination_number = Some(value.to_string())
            }
            Ok(EventHeader::OtherLegUniqueId) => self.other_leg_uuid = Some(value.to_string()),
            _ => {}
        }
    }

    /// Whether this session has reached a state it cannot leave. Stragglers in a
    /// terminal state are never candidates for leg linking.
    ///
    /// `DOWN` is not terminal: it doubles as the initial call state before any
    /// change is observed.
    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.channel_state,
            Some(
                ChannelState::CsHangup
                    | ChannelState::CsReporting
                    | ChannelState::CsDestroy
                    | ChannelState::CsNone
            )
        ) || matches!(self.call_state, Some(CallState::Hangup))
    }

    /// Absorb an entry, returning whatever readings its values defeated.
    pub(super) fn update_from_entry(&mut self, entry: &LogEntry) -> Vec<ParseWarning> {
        let mut warnings = Vec::new();
        let dump = match entry.block {
            Some(Block::ChannelData { .. }) => DumpSource::Block,
            _ => DumpSource::AttachedLines,
        };
        if let Some(Block::ChannelData { fields, variables }) = &entry.block {
            for (name, value) in fields {
                self.apply_channel_field(name, value, &mut warnings);
            }
            for (name, value) in variables {
                self.variables
                    .insert(name.bare().to_string(), value.clone());
            }
        }

        match &entry.message_kind {
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
                "bridge" => {
                    if let Some(info) = parse_bridge_args(arguments) {
                        if let Some(uuid) = &info.origination_uuid {
                            self.other_leg_uuid = Some(uuid.clone());
                        }
                        self.pending_bridge_target = Some(info.target_channel);
                    }
                }
                _ => {}
            },
            MessageKind::ChannelLifecycle { event, detail } => match event {
                LifecycleEvent::NewChannel => {
                    if self.channel_name.is_none() {
                        self.channel_name = parse_new_channel(detail).map(str::to_string);
                    }
                }
                LifecycleEvent::Hangup => {
                    if let Some(cause) = parse_hangup(detail) {
                        read(
                            &mut self.hangup_cause,
                            cause,
                            SessionReading::HangupCause,
                            &mut warnings,
                        );
                    }
                }
                LifecycleEvent::Answered => {
                    self.answered_at
                        .get_or_insert_with(|| entry.timestamp.clone());
                }
                _ => {}
            },
            kind => self.apply_kind(kind, &mut warnings),
        }

        self.apply_processing(&entry.message);
        self.media.update_from_entry(entry);

        for attached in &entry.attached {
            let parsed = parse_line(attached);
            self.update_from_message(parsed.message, dump, &mut warnings);
        }
        warnings
    }

    /// Canonical extraction for message kinds that appear on both primary and
    /// attached lines. Entry-only kinds (Execute, ChannelLifecycle — the
    /// latter needs the entry timestamp) stay in `update_from_entry`.
    fn apply_kind(&mut self, kind: &MessageKind, warnings: &mut Vec<ParseWarning>) {
        match kind {
            MessageKind::Dialplan { detail, .. } => {
                if let Some(context) = parse_dialplan_context(detail) {
                    self.initial_context.get_or_insert(context.to_string());
                    self.dialplan_context = Some(context.to_string());
                }
            }
            MessageKind::Variable { name, value } => {
                self.variables
                    .insert(name.bare().to_string(), value.clone());
            }
            MessageKind::ChannelField { name, value } => {
                self.apply_channel_field(name, value, warnings)
            }
            // A suffix the log wrote is evidence of a peer, so a value that is
            // not a UUID is named rather than left to read as an absent suffix.
            MessageKind::OriginateSuccess {
                peer_uuid: Some(peer),
                ..
            } if !is_uuid(peer) => warnings.push(ParseWarning::UnreadableValue {
                reading: SessionReading::PeerUuid,
                value: ParseWarning::excerpt(peer),
            }),
            MessageKind::StateChange { detail } => match parse_state_change(detail) {
                Some(StateChange::Channel(to)) => read(
                    &mut self.channel_state,
                    to,
                    SessionReading::ChannelState,
                    warnings,
                ),
                Some(StateChange::Call(to)) => read(
                    &mut self.call_state,
                    to,
                    SessionReading::CallState,
                    warnings,
                ),
                None => {}
            },
            _ => {}
        }
    }

    /// `Processing <caller>-><dest> in context <ctx>` — emitted by the dialplan
    /// hunt on both primary and attached lines; anchored on raw text because
    /// `classify_message` folds it into `Dialplan` with the prefix stripped.
    fn apply_processing(&mut self, msg: &str) {
        if let Some(dp) = parse_processing_line(msg) {
            self.initial_context.get_or_insert(dp.context.clone());
            self.initial_destination.get_or_insert(dp.to.clone());
            if let Some(number) = dp.from_number {
                self.initial_caller_number.get_or_insert(number);
            }
            if let Some(name) = dp.from_name {
                self.initial_caller_name.get_or_insert(name);
            }
            self.dialplan_context = Some(dp.context);
            self.dialplan_from = Some(dp.from);
            self.dialplan_to = Some(dp.to);
        }
    }

    fn update_from_message(
        &mut self,
        msg: &str,
        dump: DumpSource,
        warnings: &mut Vec<ParseWarning>,
    ) {
        let kind = classify_message(msg);
        match &kind {
            MessageKind::Variable { .. } | MessageKind::ChannelField { .. }
                if dump == DumpSource::Block => {}
            kind => self.apply_kind(kind, warnings),
        }
        self.apply_processing(msg);
    }
}
