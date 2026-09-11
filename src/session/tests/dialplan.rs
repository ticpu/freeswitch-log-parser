//! Dialplan context propagation and `Processing` line shapes.

use super::super::parse::parse_processing_line;
use super::*;

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
    assert_eq!(
        (&session.dialplan_from, &session.dialplan_to),
        (&None, &None),
        "a parsing [ctx->ext] line names a context and an entry point, neither of \
         which is the caller/dialed pair these fields carry"
    );
}

#[test]
fn processing_line_extracts_context() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing Jane Doe <5551234567>->5559876543 in context public",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.dialplan_context.as_deref(), Some("public"));
    assert_eq!(
        session.dialplan_from.as_deref(),
        Some("Jane Doe <5551234567>")
    );
    assert_eq!(session.dialplan_to.as_deref(), Some("5559876543"));
    assert_eq!(session.initial_caller_number.as_deref(), Some("5551234567"));
    assert_eq!(session.initial_caller_name.as_deref(), Some("Jane Doe"));
}

#[test]
fn padded_multibyte_context_survives_the_tracker() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing Jane Doe <5551234567>->5559876543 in context  café",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.dialplan_context.as_deref(), Some("café"));
}

#[test]
fn initial_context_preserved_across_transfers() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Processing Jane Doe <5551234567>->5559876543 in context public",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Jane Doe <5551234567>->start_recording in context recordings",
        ),
    ];
    let entries = collect_enriched(lines.clone());
    let tracker = track(lines);

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
fn attached_processing_line_updates_context() {
    // A Format C continuation must update context like a primary line.
    let lines = vec![
        full_line(UUID1, TS1, "Ring-Ready sofia/internal-v4/sos!"),
        format!("{UUID1} Processing Extension 1263 <1263>->start_recording in context recordings"),
    ];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.dialplan_context.as_deref(), Some("recordings"));
    assert_eq!(
        state.dialplan_from.as_deref(),
        Some("Extension 1263 <1263>")
    );
    assert_eq!(state.dialplan_to.as_deref(), Some("start_recording"));
    assert_eq!(
        state.initial_destination.as_deref(),
        Some("start_recording")
    );
}

#[test]
fn processing_line_with_regex_type_and_angle_bracket_caller() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing Emergency S R <5550001234>->start_recording in context recordings",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.initial_context.as_deref(), Some("recordings"));
    assert_eq!(session.dialplan_context.as_deref(), Some("recordings"));
    assert_eq!(
        session.dialplan_from.as_deref(),
        Some("Emergency S R <5550001234>")
    );
    assert_eq!(session.dialplan_to.as_deref(), Some("start_recording"));
}

#[test]
fn parse_processing_line_anchors_on_last_arrow() {
    let dest = |msg: &str| parse_processing_line(msg).map(|dp| dp.to);
    assert_eq!(
        dest("Processing Anonymous <anonymous>->5550001234 in context public").as_deref(),
        Some("5550001234"),
    );
    assert_eq!(
        dest("Processing 5550009999 <5550009999>->5550001234 in context public").as_deref(),
        Some("5550001234"),
    );
    assert_eq!(
        dest("Processing Jane Doe <5550009999>->5550001234 in context internal").as_deref(),
        Some("5550001234"),
    );
    // Hostile caller_id_name containing `->` must not be mistaken for the boundary.
    assert_eq!(
        dest("Processing Weird -> Name <5550009999>->5550001234 in context internal").as_deref(),
        Some("5550001234"),
    );
    // Feature-context destination is non-numeric but still parsed.
    assert_eq!(
        dest("Processing Jane Doe <5550009999>->start_recording in context features").as_deref(),
        Some("start_recording"),
    );
}

#[test]
fn initial_destination_first_wins() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Processing Jane Doe <5550009999>->5550001234 in context public",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Jane Doe <5550009999>->5550001234 in context transit",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Jane Doe <5550009999>->start_recording in context features",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Jane Doe <5550009999>->check_end_call in context features",
        ),
    ];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        state.initial_destination.as_deref(),
        Some("5550001234"),
        "initial_destination keeps the dialed number from the first Processing line"
    );
    assert_eq!(
        state.dialplan_to.as_deref(),
        Some("check_end_call"),
        "dialplan_to is last-wins and gets clobbered by feature-context routing"
    );
}

#[test]
fn empty_caller_id_name_still_yields_the_number() {
    // What FreeSWITCH emits when `caller_id_name` is empty: the format string's
    // space before `<` survives, so the head reads as a nameless bracketed number.
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing  <5551234567>->5559876543 in context public",
    )];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.initial_caller_number.as_deref(), Some("5551234567"));
    assert_eq!(state.initial_caller_name, None);
}

#[test]
fn empty_brackets_name_no_number() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing Jane Doe <>->5559876543 in context public",
    )];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.initial_caller_number, None);
    assert_eq!(state.initial_caller_name.as_deref(), Some("Jane Doe"));
}

#[test]
fn bracketless_head_claims_no_caller_number() {
    // No producer emits this shape, and the field span surface refuses to label
    // such a head a caller number — the state fields answer the same way.
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing 5551234567->5559876543 in context public",
    )];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.dialplan_from.as_deref(), Some("5551234567"));
    assert_eq!(state.initial_caller_number, None);
    assert_eq!(state.initial_caller_name, None);
}

#[test]
fn initial_caller_first_wins() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Processing Jane Doe <5550009999>->5550001234 in context public",
        ),
        full_line(
            UUID1,
            TS2,
            "Processing Transfer Target <5550007777>->start_recording in context features",
        ),
    ];
    let tracker = track(lines);

    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(
        state.initial_caller_number.as_deref(),
        Some("5550009999"),
        "a transfer must not restate the caller as the transfer target's"
    );
    assert_eq!(state.initial_caller_name.as_deref(), Some("Jane Doe"));
    assert_eq!(
        state.dialplan_from.as_deref(),
        Some("Transfer Target <5550007777>"),
        "dialplan_from is last-wins and does move"
    );
}

#[test]
fn caller_and_callee_ladders() {
    let dialplan_only = vec![full_line(
        UUID1,
        TS1,
        "Processing Jane Doe <5550009999>->5550001234 in context public",
    )];
    let tracker = track(dialplan_only);
    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.caller_number(), Some("5550009999"));
    assert_eq!(state.callee_number(), Some("5550001234"));

    let with_sip_user = vec![
        full_line(
            UUID1,
            TS1,
            "Processing Jane Doe <5550009999>->5550001234 in context public",
        ),
        format!("{UUID1} variable_sip_from_user: [5550008888]"),
        format!("{UUID1} variable_sip_to_user: [5550002222]"),
    ];
    let tracker = track(with_sip_user);
    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.caller_number(), Some("5550008888"));
    assert_eq!(state.callee_number(), Some("5550002222"));

    let with_dump = vec![
        full_line(
            UUID1,
            TS1,
            "Processing Jane Doe <5550009999>->5550001234 in context public",
        ),
        format!("{UUID1} variable_sip_from_user: [5550008888]"),
        format!("{UUID1} variable_sip_to_user: [5550002222]"),
        full_line(UUID1, TS2, "CHANNEL_DATA:"),
        format!("{UUID1} Caller-Caller-ID-Number: [5550001111]"),
        format!("{UUID1} Caller-Destination-Number: [5550003333]"),
    ];
    let tracker = track(with_dump);
    let state = tracker.sessions().get(UUID1).unwrap();
    assert_eq!(state.caller_number(), Some("5550001111"));
    assert_eq!(state.callee_number(), Some("5550003333"));
}
