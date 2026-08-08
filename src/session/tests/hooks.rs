//! Consumer hooks — ordering against built-in extraction, and index upkeep.

use freeswitch_types::ChannelState;

use super::*;

#[test]
fn post_hook_sets_other_leg_uuid() {
    let lines = vec![
        full_line(UUID1, TS1, "First entry"),
        format!(
            "{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(api_result=+OK {UUID2} Job-UUID: ...)"
        ),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_post_hook(|entry, state| {
        if let MessageKind::Execute {
            application,
            arguments,
            ..
        } = &entry.message_kind
        {
            if application == "set" {
                if let Some(value) = arguments.strip_prefix("api_result=+OK ") {
                    let uuid = value.split_whitespace().next().unwrap_or("");
                    if uuid.len() == 36 && state.other_leg_uuid.is_none() {
                        state.other_leg_uuid = Some(uuid.to_string());
                    }
                }
            }
        }
    });

    let entries: Vec<_> = tracker.by_ref().collect();
    assert_eq!(entries.len(), 2);

    let session = entries[1].session.as_ref().unwrap();
    assert_eq!(
        session.other_leg_uuid.as_deref(),
        Some(UUID2),
        "post_hook should detect uuid_bridge API result"
    );
}

#[test]
fn post_hook_does_not_override_builtin() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Other-Leg-Unique-ID: [{UUID2}]"),
        format!(
            "{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(api_result=+OK {UUID3} Job-UUID: ...)"
        ),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_post_hook(|entry, state| {
        if let MessageKind::Execute {
            application,
            arguments,
            ..
        } = &entry.message_kind
        {
            if application == "set" {
                if let Some(value) = arguments.strip_prefix("api_result=+OK ") {
                    let uuid = value.split_whitespace().next().unwrap_or("");
                    if uuid.len() == 36 && state.other_leg_uuid.is_none() {
                        state.other_leg_uuid = Some(uuid.to_string());
                    }
                }
            }
        }
    });

    let entries: Vec<_> = tracker.by_ref().collect();
    assert_eq!(entries.len(), 2);

    let session = entries[1].session.as_ref().unwrap();
    assert_eq!(
        session.other_leg_uuid.as_deref(),
        Some(UUID2),
        "built-in Other-Leg-Unique-ID takes precedence over hook"
    );
}

#[test]
fn pre_hook_runs_before_builtin() {
    let lines = vec![full_line(UUID1, TS1, "State Change CS_INIT -> CS_ROUTING")];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_pre_hook(|_entry, state| {
        state.channel_state = Some(ChannelState::CsNew);
    });
    let entries: Vec<_> = tracker.by_ref().collect();
    assert_eq!(
        entries[0].session.as_ref().unwrap().channel_state,
        Some(ChannelState::CsRouting),
        "built-in overwrites pre_hook value when no guard"
    );
}

#[test]
fn post_hook_runs_after_builtin() {
    let lines = vec![full_line(UUID1, TS1, "State Change CS_INIT -> CS_ROUTING")];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_post_hook(|_entry, state| {
        if state.channel_state == Some(ChannelState::CsRouting) {
            state
                .variables
                .insert("routing_seen".to_string(), "true".to_string());
        }
    });
    let _: Vec<_> = tracker.by_ref().collect();
    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        state.variables.get("routing_seen").map(|s| s.as_str()),
        Some("true"),
        "post_hook can read fields set by built-in"
    );
}

#[test]
fn post_hook_other_leg_uuid_maintains_index_for_backlink() {
    // A hook-set other_leg_uuid must reach by_other_leg so the B-leg's
    // later New Channel back-links to the A-leg like built-in sources do.
    let lines = vec![
        full_line(UUID1, TS1, "First entry"),
        format!(
            "{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(api_result=+OK {UUID2})"
        ),
        full_line(
            UUID2,
            TS2,
            "New Channel sofia/internal/target@192.0.2.9 [b2c3d4e5-f6a7-8901-bcde-f12345678901]",
        ),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_post_hook(|entry, state| {
        if let MessageKind::Execute {
            application,
            arguments,
            ..
        } = &entry.message_kind
        {
            if application == "set" {
                if let Some(value) = arguments.strip_prefix("api_result=+OK ") {
                    let uuid = value.split_whitespace().next().unwrap_or("");
                    if uuid.len() == 36 && state.other_leg_uuid.is_none() {
                        state.other_leg_uuid = Some(uuid.to_string());
                    }
                }
            }
        }
    });
    let _: Vec<_> = tracker.by_ref().collect();

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(a_leg.other_leg_uuid.as_deref(), Some(UUID2));

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "B-leg back-links via by_other_leg index populated by the hook"
    );
}

#[test]
fn pre_hook_channel_name_maintains_index_for_originate_fallback() {
    // A hook-set channel_name must reach by_channel_name so the
    // originate-success channel-name fallback can find the B-leg.
    let lines = vec![
        full_line(UUID2, TS1, "custom-channel-announce sofia/custom/6244"),
        full_line(
            UUID1,
            TS2,
            "Originate Resulted in Success: [sofia/custom/6244]",
        ),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream).with_pre_hook(|entry, state| {
        if let Some(chan) = entry.message.strip_prefix("custom-channel-announce ") {
            state.channel_name = Some(chan.to_string());
        }
    });
    let _: Vec<_> = tracker.by_ref().collect();

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "fallback finds hook-named B-leg via by_channel_name index"
    );
    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(b_leg.other_leg_uuid.as_deref(), Some(UUID1));
}
