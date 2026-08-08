//! Channel state, hangup and answer lifecycle, and tracker bookkeeping.

use freeswitch_types::{CallState, ChannelState, HangupCause};

use crate::stream::{ParseWarning, SessionReading};

use super::super::parse::{is_answered, parse_hangup};
use super::*;

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
fn unreadable_state_warns_and_keeps_the_last_one() {
    let lines = vec![
        full_line(UUID1, TS1, "State Change CS_INIT -> CS_ROUTING"),
        full_line(UUID1, TS2, "State Change CS_ROUTING -> CS_TELEPORT"),
    ];
    let entries = collect_enriched(lines);
    let last = entries.last().unwrap();
    assert_eq!(
        last.session.as_ref().unwrap().channel_state,
        Some(ChannelState::CsRouting),
        "the reading that failed leaves the last one that resolved"
    );
    assert_eq!(
        last.entry.warnings,
        [ParseWarning::UnreadableValue {
            reading: SessionReading::ChannelState,
            value: "CS_TELEPORT".to_string(),
        }]
    );
}

#[test]
fn state_change_updates_channel_state() {
    let lines = vec![full_line(UUID1, TS1, "State Change CS_INIT -> CS_ROUTING")];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.channel_state, Some(ChannelState::CsRouting));
}

#[test]
fn callstate_change_updates_call_state() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "(sofia/internal-v4/sos) Callstate Change DOWN -> RINGING",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.call_state, Some(CallState::Ringing));
}

#[test]
fn the_two_state_vocabularies_do_not_displace_each_other() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "(sofia/internal-v4/sos) Callstate Change DOWN -> RINGING",
        ),
        full_line(
            UUID1,
            TS2,
            "(sofia/internal-v4/sos) State Change CS_CONSUME_MEDIA -> CS_EXCHANGE_MEDIA",
        ),
    ];
    let entries = collect_enriched(lines);
    assert_eq!(
        entries[0].session.as_ref().unwrap().call_state,
        Some(CallState::Ringing)
    );

    let last = entries[1].session.as_ref().unwrap();
    assert_eq!(last.channel_state, Some(ChannelState::CsExchangeMedia));
    assert_eq!(
        last.call_state,
        Some(CallState::Ringing),
        "a channel-state change must not erase the call state"
    );
}

#[test]
fn bleg_lifecycle_extracts_data_from_processing() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "New Channel sofia/internal-v4/sos [a1b2c3d4-e5f6-7890-abcd-ef1234567890]",
        ),
        full_line(
            UUID1,
            TS1,
            "(sofia/internal-v4/sos) State Change CS_NEW -> CS_INIT",
        ),
        full_line(
            UUID1,
            TS1,
            "(sofia/internal-v4/sos) State Change CS_INIT -> CS_ROUTING",
        ),
        full_line(
            UUID1,
            TS1,
            "(sofia/internal-v4/sos) State Change CS_ROUTING -> CS_CONSUME_MEDIA",
        ),
        full_line(
            UUID1,
            TS1,
            "(sofia/internal-v4/sos) Callstate Change DOWN -> RINGING",
        ),
        full_line(
            UUID1,
            TS2,
            "(sofia/internal-v4/sos) State Change CS_CONSUME_MEDIA -> CS_EXCHANGE_MEDIA",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Emergency S R <5550001234>->start_recording in context recordings",
        ),
        full_line(
            UUID1,
            TS2,
            "(sofia/internal-v4/sos) State Change CS_EXCHANGE_MEDIA -> CS_HANGUP",
        ),
    ];
    let entries = collect_enriched(lines);

    let after_ringing = entries[4].session.as_ref().unwrap();
    assert_eq!(after_ringing.call_state, Some(CallState::Ringing));
    assert!(after_ringing.initial_context.is_none());

    let after_processing = entries[6].session.as_ref().unwrap();
    assert_eq!(
        after_processing.channel_state,
        Some(ChannelState::CsExchangeMedia)
    );
    assert_eq!(
        after_processing.initial_context.as_deref(),
        Some("recordings")
    );
    assert_eq!(
        after_processing.dialplan_from.as_deref(),
        Some("Emergency S R <5550001234>")
    );
    assert_eq!(
        after_processing.dialplan_to.as_deref(),
        Some("start_recording")
    );

    let after_hangup = entries[7].session.as_ref().unwrap();
    assert_eq!(after_hangup.channel_state, Some(ChannelState::CsHangup));
    assert_eq!(after_hangup.initial_context.as_deref(), Some("recordings"));
}

#[test]
fn channel_name_from_new_channel() {
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

#[test]
fn parse_hangup_extracts_cause() {
    assert_eq!(
        parse_hangup("Hangup sofia/internal/1234 [NORMAL_CLEARING]"),
        Some("NORMAL_CLEARING".to_string())
    );
    assert_eq!(
        parse_hangup("Hangup sofia/internal/1234 [USER_BUSY]"),
        Some("USER_BUSY".to_string())
    );
    assert_eq!(parse_hangup("Some other message"), None);
    assert_eq!(parse_hangup("New Channel sofia/internal/1234 [uuid]"), None);
}

#[test]
fn is_answered_detects_answer_event() {
    assert!(is_answered("sofia/internal/1234 has been answered"));
    assert!(!is_answered("sofia/internal/1234 is ringing"));
    assert!(!is_answered("New Channel sofia/internal/1234"));
}

#[test]
fn hangup_cause_from_lifecycle() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Hangup sofia/internal/+15550001234@192.0.2.1 [NORMAL_CLEARING]",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(
        session.hangup_cause,
        Some(HangupCause::NormalClearing),
        "hangup_cause extracted from ChannelLifecycle Hangup"
    );
}

#[test]
fn answered_at_from_lifecycle() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "sofia/internal/+15550001234@192.0.2.1 has been answered",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(
        session.answered_at.as_deref(),
        Some(TS1),
        "answered_at captures timestamp when 'has been answered' seen"
    );
}

#[test]
fn answered_at_not_overwritten() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "sofia/internal/+15550001234@192.0.2.1 has been answered",
        ),
        full_line(
            UUID1,
            TS2,
            "sofia/internal/+15550001234@192.0.2.1 has been answered",
        ),
    ];
    let entries = collect_enriched(lines);
    let session = entries[1].session.as_ref().unwrap();
    assert_eq!(
        session.answered_at.as_deref(),
        Some(TS1),
        "answered_at preserves first answer timestamp"
    );
}
