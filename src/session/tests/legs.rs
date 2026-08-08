//! Cross-session leg linking — originate, bridge and loopback pairing.

use super::*;

#[test]
fn originate_success_links_both_legs() {
    // "Originate Resulted in Success" contains both the A-leg UUID (line prefix)
    // and B-leg UUID (Peer UUID field). Both legs should learn about each other.
    let lines = vec![
        full_line(UUID2, TS1, "New Channel sofia/esinet1-v6-tcp/sip:target.example.com [b2c3d4e5-f6a7-8901-bcde-f12345678901]"),
        full_line(UUID1, TS2, "Originate Resulted in Success: [sofia/esinet1-v6-tcp/sip:target.example.com] Peer UUID: b2c3d4e5-f6a7-8901-bcde-f12345678901"),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "A-leg other_leg_uuid set from Originate Resulted in Success"
    );

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "B-leg other_leg_uuid points back to A-leg"
    );
}

#[test]
fn originate_success_channel_fallback_links_legs() {
    // FS 1.10.5-dev and similar omit `Peer UUID:` from "Originate Resulted in Success".
    // The b-leg's New Channel populates channel_name 3.5 s before originate; the
    // fallback path matches by channel name when the Peer UUID is absent.
    let lines = vec![
        full_line(
            UUID2,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [b2c3d4e5-f6a7-8901-bcde-f12345678901]",
        ),
        full_line(
            UUID1,
            TS2,
            "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744]",
        ),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "A-leg linked to B-leg via channel-name fallback when Peer UUID absent"
    );

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "B-leg linked back to A-leg"
    );
}

#[test]
fn originate_success_peer_uuid_wins_over_channel_fallback() {
    // When Peer UUID is present, channel-name fallback must not fire — even if
    // another session shares the channel name. Peer UUID is authoritative.
    let lines = vec![
        full_line(
            UUID2,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [b2c3d4e5-f6a7-8901-bcde-f12345678901]",
        ),
        full_line(
            UUID3,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [c3d4e5f6-a7b8-9012-cdef-234567890123]",
        ),
        full_line(
            UUID1,
            TS2,
            "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744] Peer UUID: b2c3d4e5-f6a7-8901-bcde-f12345678901",
        ),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "Peer UUID wins over channel-name match"
    );

    let decoy = tracker.sessions().get(UUID3).unwrap();
    assert_eq!(
        decoy.other_leg_uuid, None,
        "Decoy session sharing channel name is not touched"
    );
}

#[test]
fn originate_success_channel_fallback_skips_when_ambiguous() {
    // Two b-leg candidates share the same channel name. The fallback must not
    // guess — correctness over coverage.
    let lines = vec![
        full_line(
            UUID2,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [b2c3d4e5-f6a7-8901-bcde-f12345678901]",
        ),
        full_line(
            UUID3,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [c3d4e5f6-a7b8-9012-cdef-234567890123]",
        ),
        full_line(
            UUID1,
            TS2,
            "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744]",
        ),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid, None,
        "Ambiguous channel name yields no link"
    );
    assert_eq!(tracker.sessions().get(UUID2).unwrap().other_leg_uuid, None);
    assert_eq!(tracker.sessions().get(UUID3).unwrap().other_leg_uuid, None);
}

#[test]
fn originate_success_channel_fallback_skips_terminated_candidates() {
    // Two b-leg sessions share the same channel_name, but one is in
    // CS_DESTROY (stale prior call on the same registered phone). The
    // liveness filter must drop the terminated candidate so the live one
    // becomes the unambiguous match.
    let lines = vec![
        full_line(
            UUID2,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [b2c3d4e5-f6a7-8901-bcde-f12345678901]",
        ),
        full_line(
            UUID2,
            TS1,
            "(sofia/internal/6244@192.0.2.72:50744) State Change CS_EXECUTE -> CS_DESTROY",
        ),
        full_line(
            UUID3,
            TS1,
            "New Channel sofia/internal/6244@192.0.2.72:50744 [c3d4e5f6-a7b8-9012-cdef-234567890123]",
        ),
        full_line(
            UUID1,
            TS2,
            "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744]",
        ),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID3),
        "Live b-leg wins over CS_DESTROY straggler"
    );

    let live_b = tracker.sessions().get(UUID3).unwrap();
    assert_eq!(
        live_b.other_leg_uuid.as_deref(),
        Some(UUID1),
        "Live b-leg points back to a-leg"
    );

    let stale_b = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        stale_b.other_leg_uuid, None,
        "Terminated b-leg is not touched"
    );
}

#[test]
fn originate_success_channel_fallback_skips_when_no_match() {
    // a-leg fires Originate with a bracketed channel name no session has.
    // Must not panic, must not create a spurious link.
    let lines = vec![full_line(
        UUID1,
        TS2,
        "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744]",
    )];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(a_leg.other_leg_uuid, None);
    assert_eq!(a_leg.pending_bridge_target, None);
}

#[test]
fn bridge_origination_uuid_links_a_leg_immediately() {
    // bridge([origination_uuid=BLEG_UUID,...]) guarantees B-leg UUID from execute args alone.
    // A-leg knows B-leg immediately, B-leg learns A-leg when New Channel appears.
    let lines = vec![
        full_line(UUID1, TS1, "EXECUTE [depth=0] sofia/internal-v6/1232@[2001:db8::10] bridge([origination_uuid=b2c3d4e5-f6a7-8901-bcde-f12345678901,leg_timeout=2]sofia/esinet1-v6-tcp/sip:target.example.com)"),
        full_line(UUID2, TS1, "New Channel sofia/esinet1-v6-tcp/sip:target.example.com [b2c3d4e5-f6a7-8901-bcde-f12345678901]"),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "A-leg knows B-leg UUID from origination_uuid in bridge args"
    );

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "B-leg knows A-leg once New Channel correlates"
    );
}

#[test]
fn bridge_target_matches_new_channel() {
    // bridge() without origination_uuid — B-leg UUID is auto-generated by FS.
    // Match via bridge target channel matching next New Channel with same target.
    let lines = vec![
        full_line(UUID1, TS1, "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 bridge(sofia/gateway/carrier/+15559876543)"),
        full_line(UUID1, TS1, "Parsing session specific variables"),
        full_line(UUID2, TS1, "New Channel sofia/gateway/carrier/+15559876543 [b2c3d4e5-f6a7-8901-bcde-f12345678901]"),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID2),
        "A-leg linked to B-leg via bridge target matching New Channel"
    );

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "B-leg linked back to A-leg"
    );
}

#[test]
fn concurrent_bridges_to_one_target_link_nothing() {
    // Two A legs waiting on the same target string: the New Channel that follows
    // belongs to one of them and the log does not say which.
    let lines = vec![
        full_line(UUID1, TS1, "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 bridge(sofia/gateway/carrier/+15559876543)"),
        full_line(UUID3, TS1, "EXECUTE [depth=0] sofia/internal/+15550005678@192.0.2.1 bridge(sofia/gateway/carrier/+15559876543)"),
        full_line(UUID2, TS2, "New Channel sofia/gateway/carrier/+15559876543 [b2c3d4e5-f6a7-8901-bcde-f12345678901]"),
    ];
    let tracker = track(lines);

    for uuid in [UUID1, UUID2, UUID3] {
        assert_eq!(
            tracker.sessions().get(uuid).unwrap().other_leg_uuid,
            None,
            "{uuid} must not be linked on an ambiguous target"
        );
    }
}

#[test]
fn originate_success_corrects_wrong_target_match() {
    // Bridge target matching guessed UUID2 as B-leg, but originate success reveals
    // the actual B-leg is UUID3. The authoritative success message must override.
    let lines = vec![
        full_line(UUID1, TS1, "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 bridge(sofia/gateway/carrier/+15559876543)"),
        full_line(UUID2, TS1, "New Channel sofia/gateway/carrier/+15559876543 [b2c3d4e5-f6a7-8901-bcde-f12345678901]"),
        full_line(UUID1, TS2, "Originate Resulted in Success: [sofia/gateway/carrier/+15559876543] Peer UUID: c3d4e5f6-a7b8-9012-cdef-234567890123"),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        a_leg.other_leg_uuid.as_deref(),
        Some(UUID3),
        "Originate success overrides earlier target-match guess"
    );

    let real_b_leg = tracker.sessions().get(UUID3).unwrap();
    assert_eq!(
        real_b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "Real B-leg points back to A-leg"
    );
}

#[test]
fn channel_data_other_leg_uuid() {
    // Other-Leg-Unique-ID in CHANNEL_DATA (post-bridge info dump) sets other_leg_uuid
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Other-Leg-Unique-ID: [{UUID2}]"),
    ];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        state.other_leg_uuid.as_deref(),
        Some(UUID2),
        "other_leg_uuid set from Other-Leg-Unique-ID CHANNEL_DATA field"
    );
}

#[test]
fn relink_removes_stale_by_other_leg_entry() {
    // B first points at C (Other-Leg-Unique-ID), then an authoritative
    // Peer UUID relinks B to A. The superseded C-keyed by_other_leg entry
    // must be removed — otherwise a later New Channel on C back-links to
    // B and clobbers the authoritative A<->B pair.
    let lines = vec![
        full_line(UUID2, TS1, "CHANNEL_DATA:"),
        format!("{UUID2} Other-Leg-Unique-ID: [{UUID3}]"),
        full_line(
            UUID1,
            TS2,
            &format!(
                "Originate Resulted in Success: [sofia/internal/6244@192.0.2.72:50744] Peer UUID: {UUID2}"
            ),
        ),
        full_line(
            UUID3,
            TS2,
            &format!("New Channel sofia/external/dest@192.0.2.9 [{UUID3}]"),
        ),
    ];
    let tracker = track(lines);

    let a_leg = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(a_leg.other_leg_uuid.as_deref(), Some(UUID2));

    let b_leg = tracker.sessions().get(UUID2).unwrap();
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(UUID1),
        "authoritative Peer UUID link must survive the unrelated New Channel"
    );

    let c_leg = tracker.sessions().get(UUID3).unwrap();
    assert_eq!(
        c_leg.other_leg_uuid, None,
        "New Channel on C must not back-link via the superseded index entry"
    );
}

#[test]
fn loopback_b_leg_links_to_its_a_leg() {
    let tracker = track(vec![
        full_line(UUID1, TS1, "New Channel loopback/tty-a [ignored]"),
        full_line(UUID2, TS1, "New Channel loopback/tty-b [ignored]"),
    ]);
    assert_eq!(
        tracker.sessions()[UUID1].other_leg_uuid.as_deref(),
        Some(UUID2)
    );
    assert_eq!(
        tracker.sessions()[UUID2].other_leg_uuid.as_deref(),
        Some(UUID1)
    );
}

#[test]
fn concurrent_loopbacks_to_one_destination_do_not_link() {
    let tracker = track(vec![
        full_line(UUID1, TS1, "New Channel loopback/tty-a [ignored]"),
        full_line(UUID2, TS1, "New Channel loopback/tty-a [ignored]"),
        full_line(UUID3, TS1, "New Channel loopback/tty-b [ignored]"),
    ]);
    assert!(
        tracker.sessions()[UUID3].other_leg_uuid.is_none(),
        "two live A legs share the name; picking one would be a guess"
    );
}
