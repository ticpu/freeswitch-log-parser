//! [`ParseStats`] counters, unclassified tracking tiers, and the line
//! accounting invariant.

use super::*;

/// Crash padding leaves a real log line with a leading NUL. It is not the
/// segment sentinel, and must reach the counters like any other line.
#[test]
fn a_nul_prefixed_line_is_not_a_segment_boundary() {
    let lines = vec![
        full_line(UUID1, TS1, "before padding"),
        "\u{0}2025-01-15 10:30:46.000000 95.97% [DEBUG] sofia.c:100 after padding".to_string(),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    assert_eq!(stream.stats().lines_processed, 2);
    assert_eq!(stream.stats().unaccounted_lines(), 0);
    assert!(
        entries.iter().any(|e| e.message.contains("after padding")),
        "the padded line's content must survive, got {:?}",
        entries.iter().map(|e| &e.message).collect::<Vec<_>>()
    );
}

// --- New: ParseStats tests ---

#[test]
fn stats_lines_processed() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        full_line(UUID1, TS2, "Second"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_eq!(stream.stats().lines_processed, 3);
}

#[test]
fn stats_unclassified_orphan() {
    let lines = vec![
        "variable_foo: [bar]".to_string(),
        full_line(UUID1, TS1, "After orphan"),
    ];
    let mut stream =
        LogStream::new(lines.into_iter()).unclassified_tracking(UnclassifiedTracking::TrackLines);
    let _: Vec<_> = stream.by_ref().collect();
    assert_eq!(stream.stats().lines_unclassified, 1);
    assert_eq!(stream.stats().unclassified_lines.len(), 1);
    assert_eq!(
        stream.stats().unclassified_lines[0].reason,
        UnclassifiedReason::OrphanContinuation,
    );
}

#[test]
fn stats_capture_data() {
    let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
    let mut stream =
        LogStream::new(lines.into_iter()).unclassified_tracking(UnclassifiedTracking::CaptureData);
    let _: Vec<_> = stream.by_ref().collect();
    assert_eq!(stream.stats().unclassified_lines.len(), 1);
    assert_eq!(
        stream.stats().unclassified_lines[0].data.as_deref(),
        Some("orphan line"),
    );
}

#[test]
fn stats_count_only_no_allocation() {
    let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_eq!(stream.stats().lines_unclassified, 1);
    assert!(stream.stats().unclassified_lines.is_empty());
}

#[test]
fn line_number_tracking() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        full_line(UUID2, TS2, "Third"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries[0].line_number, 1);
    assert_eq!(entries[1].line_number, 3);
}

#[test]
fn drain_unclassified() {
    let lines = vec![
        "orphan1".to_string(),
        "orphan2".to_string(),
        full_line(UUID1, TS1, "After"),
    ];
    let mut stream =
        LogStream::new(lines.into_iter()).unclassified_tracking(UnclassifiedTracking::TrackLines);
    let _: Vec<_> = stream.by_ref().collect();
    let drained = stream.drain_unclassified();
    assert_eq!(drained.len(), 1);
    assert!(stream.stats().unclassified_lines.is_empty());
    assert_eq!(stream.stats().lines_unclassified, 1);
}

// --- Line accounting tests ---

fn assert_accounting(stream: &LogStream<impl Iterator<Item = String>>) {
    let stats = stream.stats();
    assert_eq!(
        stats.unaccounted_lines(),
        0,
        "line accounting invariant violated: \
         processed={} + split={} != in_entries={} + empty_orphan={}",
        stats.lines_processed,
        stats.lines_split,
        stats.lines_in_entries,
        stats.lines_empty_orphan,
    );
}

#[test]
fn accounting_full_lines() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        full_line(UUID2, TS2, "Second"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(stream.stats().lines_in_entries, 2);
    assert_accounting(&stream);
}

#[test]
fn accounting_with_attached() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        "variable_foo: [bar]".to_string(),
        full_line(UUID2, TS2, "Next"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    // Entry 1: 1 primary + 2 attached = 3 lines
    // Entry 2: 1 primary = 1 line
    assert_eq!(stream.stats().lines_in_entries, 4);
    assert_accounting(&stream);
}

#[test]
fn accounting_system_line() {
    let lines = vec![format!(
        "{TS1} 95.97% [NOTICE] mod_logfile.c:217 New log started."
    )];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_eq!(stream.stats().lines_in_entries, 1);
    assert_accounting(&stream);
}

#[test]
fn accounting_empty_orphan() {
    let lines = vec![
        String::new(),
        "   ".to_string(),
        full_line(UUID1, TS1, "After"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(stream.stats().lines_empty_orphan, 2);
    assert_accounting(&stream);
}

#[test]
fn accounting_empty_attached() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        String::new(),
        "continuation".to_string(),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].attached.len(), 2);
    assert_eq!(stream.stats().lines_empty_orphan, 0);
    assert_eq!(stream.stats().lines_in_entries, 3);
    assert_accounting(&stream);
}

#[test]
fn accounting_orphan_continuation() {
    let lines = vec!["orphan line".to_string(), full_line(UUID1, TS1, "After")];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_accounting(&stream);
}

#[test]
fn accounting_codec_merging() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
        ),
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1] is saved as a match",
        ),
        full_line(UUID2, TS2, "Next"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_accounting(&stream);
}

#[test]
fn accounting_truncated_line() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("varia{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let _: Vec<_> = stream.by_ref().collect();
    assert_accounting(&stream);
}

#[test]
fn accounting_long_line_collision_split() {
    // One write spanning the CHANNEL_DATA line and the bare continuation under
    // it, cut on the continuation with the next record glued on.
    let opener = full_line(UUID1, TS1, "CHANNEL_DATA:");
    let line = cut_write_after(
        opener.len() + 1,
        "variable_sip_multipart: [",
        &format!("{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"),
    );
    let lines = vec![opener, line];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    // The CHANNEL_DATA entry should have the truncated variable as attached
    assert_eq!(entries[0].message, "CHANNEL_DATA:");

    // The collision should have been split out as a separate entry
    let split_entry = entries.iter().find(|e| e.uuid.as_deref() == Some(UUID2));
    assert!(
        split_entry.is_some(),
        "collision UUID should produce a separate entry"
    );

    assert_eq!(stream.stats().lines_split, 1);
    assert_accounting(&stream);
}
