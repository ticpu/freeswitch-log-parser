//! Variables and channel fields learned from dumps and executions.

use freeswitch_types::CallDirection;

use super::*;

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
fn unreadable_call_direction_keeps_the_known_one() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Call-Direction: [inbound]"),
        full_line(UUID1, TS2, "CHANNEL_DATA:"),
        format!("{UUID1} Call-Direction: [sideways]"),
    ];
    let entries = collect_enriched(lines);
    let session = entries.last().unwrap().session.as_ref().unwrap();
    assert_eq!(session.call_direction, Some(CallDirection::Inbound));
}

/// A dump field split out of its block by a truncated-line collision still
/// carries the peer UUID that leg linking depends on.
#[test]
fn standalone_channel_field_carries_the_peer_uuid() {
    let lines = vec![
        full_line(UUID1, TS1, "Ring-Ready sofia/internal/1000@192.0.2.1"),
        format!("{UUID1} Other-Leg-Unique-ID: [{UUID2}]"),
    ];
    let entries = collect_enriched(lines);
    let session = entries.last().unwrap().session.as_ref().unwrap();
    assert_eq!(session.other_leg_uuid.as_deref(), Some(UUID2));
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
fn typed_variable_accessor() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream);
    let _: Vec<_> = tracker.by_ref().collect();
    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        state.variable(SofiaVariable::SipCallId),
        Some("test123@192.0.2.1")
    );
    assert_eq!(state.variable(ChannelVariable::Direction), None);
}

#[test]
fn multi_line_variable_survives_attached_rescan() {
    // The block carries the reassembled multi-line value; re-scanning the
    // raw attached opening fragment must not clobber it back to "v=0".
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID1} variable_switch_r_sdp: [v=0"),
        "o=FreeSWITCH 1737000000 1737000001 IN IP4 192.0.2.10".to_string(),
        "s=FreeSWITCH".to_string(),
        "c=IN IP4 192.0.2.10".to_string(),
        "m=audio 30000 RTP/AVP 0 101".to_string(),
        "]".to_string(),
        format!("{UUID1} variable_direction: [inbound]"),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream);
    let _: Vec<_> = tracker.by_ref().collect();

    let state = tracker.sessions().get(UUID1).unwrap();
    let sdp = state
        .variables
        .get("switch_r_sdp")
        .expect("switch_r_sdp variable present");
    assert!(
        sdp.contains('\n'),
        "expected full reassembled value, got fragment: {sdp:?}"
    );
    assert!(sdp.starts_with("v=0\n"));
    assert!(sdp.contains("m=audio 30000 RTP/AVP 0 101"));
    assert_eq!(
        state.variables.get("direction").map(|s| s.as_str()),
        Some("inbound")
    );
    assert_eq!(
        state.channel_name.as_deref(),
        Some("sofia/internal/+15550001234@192.0.2.1")
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
fn caller_id_name_from_channel_data() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Caller-Caller-ID-Name: [Test Caller Name]"),
    ];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(
        session.caller_id_name.as_deref(),
        Some("Test Caller Name"),
        "caller_id_name extracted from CHANNEL_DATA"
    );
}
