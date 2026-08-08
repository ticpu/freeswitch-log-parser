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
fn attached_processing_line_updates_context() {
    // Format C continuation: a `Processing ...` line attached under a
    // primary entry must update dialplan context like the primary path.
    let lines = vec![
        full_line(UUID1, TS1, "Ring-Ready sofia/internal-v4/sos!"),
        format!("{UUID1} Processing Extension 1263 <1263>->start_recording in context recordings"),
    ];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream);
    let _: Vec<_> = tracker.by_ref().collect();

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
fn processing_line_extension_format() {
    let lines = vec![full_line(
        UUID1,
        TS1,
        "Processing Extension 1263 <1263>->start_recording in context recordings",
    )];
    let entries = collect_enriched(lines);
    let session = entries[0].session.as_ref().unwrap();
    assert_eq!(session.initial_context.as_deref(), Some("recordings"));
    assert_eq!(
        session.dialplan_from.as_deref(),
        Some("Extension 1263 <1263>")
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
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream);
    let _: Vec<_> = tracker.by_ref().collect();

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
