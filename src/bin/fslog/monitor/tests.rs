//! Behavioral tests for the monitor — timestamp arithmetic, row lifecycle,
//! and the fixture-backed dump.

use freeswitch_log_parser::CallDirection;

use super::model::{AppState, CallEvent, CallFields, ContextFilter, LegState, ReaderMsg};
use super::reader::{apply_update, drain_session_removals, gc_ended};
use super::time::{call_duration, format_age, format_duration, log_age, parse_timestamp_secs};
use super::*;

#[test]
fn parse_timestamp_basic() {
    let secs = parse_timestamp_secs("2025-01-15 10:30:45.123456").unwrap();
    assert_eq!(secs % 86400, 10 * 3600 + 30 * 60 + 45);
}

#[test]
fn parse_timestamp_midnight() {
    let secs = parse_timestamp_secs("2025-06-01 00:00:00.000000").unwrap();
    assert_eq!(secs % 86400, 0);
}

#[test]
fn parse_timestamp_too_short() {
    assert!(parse_timestamp_secs("2025-01-15").is_none());
    assert!(parse_timestamp_secs("").is_none());
}

#[test]
fn log_age_same_timestamp() {
    let d = log_age("2025-01-15 10:30:45.123456", "2025-01-15 10:30:45.999999");
    assert_eq!(d, Duration::ZERO);
}

#[test]
fn log_age_one_minute() {
    let d = log_age("2025-01-15 10:30:00.000000", "2025-01-15 10:31:00.000000");
    assert_eq!(d, Duration::from_secs(60));
}

#[test]
fn log_age_across_midnight() {
    let d = log_age("2025-01-15 23:59:00.000000", "2025-01-16 00:01:00.000000");
    assert_eq!(d, Duration::from_secs(120));
}

#[test]
fn log_age_across_month() {
    let d = log_age("2025-01-31 23:00:00.000000", "2025-02-01 01:00:00.000000");
    assert_eq!(d, Duration::from_secs(7200));
}

#[test]
fn log_age_reversed_returns_zero() {
    let d = log_age("2025-01-15 10:31:00.000000", "2025-01-15 10:30:00.000000");
    assert_eq!(d, Duration::ZERO);
}

#[test]
fn format_duration_seconds() {
    assert_eq!(format_duration(Duration::from_secs(5)), "0:05");
    assert_eq!(format_duration(Duration::from_secs(59)), "0:59");
}

#[test]
fn format_duration_minutes() {
    assert_eq!(format_duration(Duration::from_secs(60)), "1:00");
    assert_eq!(format_duration(Duration::from_secs(754)), "12:34");
}

#[test]
fn format_duration_hours() {
    assert_eq!(format_duration(Duration::from_secs(3600)), "1:00:00");
    assert_eq!(format_duration(Duration::from_secs(3661)), "1:01:01");
}

#[test]
fn format_age_minutes() {
    assert_eq!(format_age(Duration::from_secs(0)), "0m");
    assert_eq!(format_age(Duration::from_secs(59)), "0m");
    assert_eq!(format_age(Duration::from_secs(1800)), "30m");
    assert_eq!(format_age(Duration::from_secs(3599)), "59m");
}

#[test]
fn format_age_hours() {
    assert_eq!(format_age(Duration::from_secs(3600)), "1h");
    assert_eq!(format_age(Duration::from_secs(7200)), "2h");
    assert_eq!(format_age(Duration::from_secs(86399)), "23h");
}

#[test]
fn format_age_days() {
    assert_eq!(format_age(Duration::from_secs(86400)), "1d");
    assert_eq!(format_age(Duration::from_secs(259200)), "3d");
}

fn state_short(raw: &str) -> String {
    LegState::parse(raw).short()
}

#[test]
fn format_state_cs_prefix() {
    assert_eq!(state_short("CS_EXECUTE"), "EXECUTE");
    assert_eq!(state_short("CS_ROUTING"), "ROUTING");
    assert_eq!(state_short("CS_HANGUP"), "HANGUP");
    assert_eq!(state_short("CS_DESTROY"), "DESTROY");
}

#[test]
fn format_state_abbreviations() {
    assert_eq!(state_short("CS_EXCHANGE_MEDIA"), "MEDIA");
    assert_eq!(state_short("CS_CONSUME_MEDIA"), "CONSUME");
    assert_eq!(state_short("CS_SOFT_EXECUTE"), "SOFTEX");
    assert_eq!(state_short("CS_REPORTING"), "REPORT");
}

#[test]
fn format_state_unknown_passthrough() {
    assert_eq!(state_short("SOMETHING_ELSE"), "SOMETHING_ELSE");
}

#[test]
fn context_filter_exclude() {
    let f = ContextFilter::parse("-recordings,-default");
    assert!(!f.matches(Some("recordings")));
    assert!(!f.matches(Some("default")));
    assert!(f.matches(Some("public")));
    assert!(f.matches(None));
}

#[test]
fn context_filter_include() {
    let f = ContextFilter::parse("public,private");
    assert!(f.matches(Some("public")));
    assert!(f.matches(Some("private")));
    assert!(!f.matches(Some("recordings")));
    assert!(!f.matches(None));
}

#[test]
fn context_filter_none() {
    let f = ContextFilter::parse("");
    assert!(f.matches(Some("anything")));
    assert!(f.matches(None));
}

fn make_state() -> AppState {
    AppState::new(
        PathBuf::from("."),
        ContextFilter::None,
        Vec::new(),
        Duration::from_secs(3600),
    )
}

#[test]
fn gc_ended_requests_session_removal_after_linger() {
    let (tx, rx) = mpsc::channel();
    let mut state = make_state();
    state.remove_tx = Some(tx);
    state.linger = Duration::ZERO;
    apply_update(
        &mut state,
        make_update("aaaa", "2025-01-15 10:30:45.000000", false),
    );
    apply_update(
        &mut state,
        make_update("aaaa", "2025-01-15 10:30:50.000000", true),
    );
    gc_ended(&mut state);
    assert!(state.calls.is_empty());
    assert_eq!(rx.try_recv().ok().as_deref(), Some("aaaa"));
}

#[test]
fn hangup_without_row_requests_session_removal() {
    let (tx, rx) = mpsc::channel();
    let mut state = make_state();
    state.remove_tx = Some(tx);
    // Hangup for a call whose New Channel was never seen: no row exists,
    // none will linger, so the session must be freed immediately.
    apply_update(
        &mut state,
        make_update("dddd", "2025-01-15 10:30:45.000000", true),
    );
    assert!(state.calls.is_empty());
    assert_eq!(rx.try_recv().ok().as_deref(), Some("dddd"));
}

#[test]
fn drain_session_removals_drops_tracker_state() {
    let uuid = "11111111-2222-3333-4444-555555555555";
    let lines = vec![format!(
        "{uuid} 2025-01-15 10:30:45.123456 95.00% [DEBUG] test.c:1 hello"
    )];
    let stream = LogStream::new(lines.into_iter());
    let mut tracker = SessionTracker::new(stream);
    while tracker.next().is_some() {}
    assert!(tracker.sessions().contains_key(uuid));

    let (tx, rx) = mpsc::channel();
    tx.send(uuid.to_string()).unwrap();
    drain_session_removals(&mut tracker, &rx);
    assert!(!tracker.sessions().contains_key(uuid));
}

fn make_update(uuid: &str, ts: &str, is_hangup: bool) -> ReaderMsg {
    ReaderMsg {
        uuid: uuid.to_string(),
        timestamp: ts.to_string(),
        fields: CallFields {
            channel_state: Some(LegState::parse("CS_EXECUTE")),
            context: Some("public".to_string()),
            direction: Some(CallDirection::Inbound),
            caller: Some("1234".to_string()),
            callee: Some("5678".to_string()),
            ..CallFields::default()
        },
        event: Some(if is_hangup {
            CallEvent::Hangup
        } else {
            CallEvent::NewChannel
        }),
    }
}

// A call first seen in a terminal state (its New Channel was never
// observed) must not produce a row.
#[test]
fn no_row_for_call_first_seen_in_terminal_state() {
    let mut state = make_state();
    // First message is a state change to CS_HANGUP (not a Hangup event per
    // current rules)
    let msg = ReaderMsg {
        uuid: "aaaa".to_string(),
        timestamp: "2025-01-15 10:30:45.000000".to_string(),
        fields: CallFields {
            channel_state: Some(LegState::parse("CS_HANGUP")),
            ..CallFields::default()
        },
        event: None,
    };
    apply_update(&mut state, msg);
    // Then CS_DESTROY arrives
    let msg = ReaderMsg {
        uuid: "aaaa".to_string(),
        timestamp: "2025-01-15 10:30:45.000000".to_string(),
        fields: CallFields {
            channel_state: Some(LegState::parse("CS_DESTROY")),
            ..CallFields::default()
        },
        event: Some(CallEvent::Hangup),
    };
    apply_update(&mut state, msg);
    assert!(
        state.calls.is_empty(),
        "call first seen in CS_HANGUP should not produce a row (duration would be 0:00)"
    );
}

// Continuation lines at the start of a new file segment must not inherit
// the previous segment's last timestamp.
#[test]
fn timestamp_not_contaminated_across_file_segments() {
    use freeswitch_log_parser::LogStream;

    let uuid = "f2cb66d4-aaaa-bbbb-cccc-dddddddddddd";
    // Segment 1 (rotated file): ends with a timestamped line for a different UUID
    let seg1_lines: Vec<String> = vec![
        format!(
            "eeeeeeee-1111-2222-3333-444444444444 2025-01-15 23:58:03.000000 95.00% [DEBUG] test.c:1 Last line in rotated file"
        ),
    ];
    // Segment 2 (current file): starts with UUID-continuation lines (no timestamp)
    // followed by a full timestamped line
    let seg2_lines: Vec<String> = vec![
        format!("{uuid} CHANNEL_DATA:"),
        format!("{uuid} Channel-State: [CS_EXECUTE]"),
        format!(
            "{uuid} 2025-01-16 08:37:12.000000 95.00% [DEBUG] test.c:1 First real line in new file"
        ),
    ];

    let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = vec![
        ("rotated.log".to_string(), Box::new(seg1_lines.into_iter())),
        (
            "freeswitch.log".to_string(),
            Box::new(seg2_lines.into_iter()),
        ),
    ];

    let (chain, _) = freeswitch_log_parser::TrackedChain::new(segments);
    let stream = LogStream::new(chain);
    let entries: Vec<_> = stream.collect();

    // The CHANNEL_DATA entry's timestamp must not come from the rotated
    // file's last line.
    let cd_entry = entries
        .iter()
        .find(|e| e.uuid == uuid)
        .expect("should find entry for test UUID");

    assert_ne!(
        cd_entry.timestamp, "2025-01-15 23:58:03.000000",
        "continuation lines in new file segment must not inherit timestamp from previous file"
    );
}

// A call seen only in the rotated file must not grow its duration against
// timestamps from the current file.
#[test]
fn call_from_previous_file_not_seen_again_gets_bounded_age() {
    let mut state = make_state();
    // Call appears during rotated file processing
    apply_update(
        &mut state,
        make_update("bbbb", "2025-01-15 23:58:02.000000", false),
    );
    // latest_log_ts advances as we process the current file (different calls)
    apply_update(
        &mut state,
        make_update("cccc", "2025-01-16 09:06:41.000000", false),
    );

    let row = state
        .calls
        .iter()
        .find(|r| r.uuid == "bbbb")
        .expect("should have row for bbbb");
    let dur = call_duration(row);

    // The call was only seen at 23:58:02. 9+ hours of duration is wrong —
    // it should not exceed the call's actual log span.
    assert!(
        dur < Duration::from_secs(3600),
        "call from rotated file not seen in current file should not grow duration against \
         latest_log_ts (got {dur:?}, expected < 1h)"
    );
}

// --dump must build rows from the same segment data as the TUI: every row
// gets a parseable log_start.
#[test]
fn fixture_dump_all_calls_have_valid_timestamps() {
    use std::path::Path;

    let dir = Path::new("tests/fixtures");
    let path = dir.join("freeswitch.log");
    if !path.exists() {
        return; // skip if fixtures not available
    }

    let state = process_log(dir, &path, ContextFilter::None)
        .expect("process_log should succeed on fixtures");

    let bad: Vec<_> = state
        .calls
        .iter()
        .filter(|r| parse_timestamp_secs(&r.log_start).is_none())
        .map(|r| &r.uuid)
        .collect();

    assert!(
        bad.is_empty(),
        "all calls should have parseable log_start timestamps: {bad:?}"
    );
}

// Fixture check: cross-segment timestamp inheritance must not inflate a
// call's duration.
#[test]
fn fixture_no_cross_file_timestamp_inflation() {
    use std::path::Path;

    let dir = Path::new("tests/fixtures");
    let path = dir.join("freeswitch.log");
    if !path.exists() {
        return;
    }

    let state = process_log(dir, &path, ContextFilter::None)
        .expect("process_log should succeed on fixtures");

    let row = state.calls.iter().find(|r| r.uuid.starts_with("f2cb66d4"));

    if let Some(row) = row {
        let dur = call_duration(row);
        assert!(
            dur < Duration::from_secs(300),
            "f2cb66d4 duration should be ~19s (actual call duration), \
             not {dur:?} (inflated by timestamp from previous file segment)"
        );
    }
}

// Fixture check: rotated-file-only calls keep a bounded duration.
#[test]
fn fixture_rotated_only_calls_bounded_duration() {
    use std::path::Path;

    let dir = Path::new("tests/fixtures");
    let path = dir.join("freeswitch.log");
    if !path.exists() {
        return;
    }

    let state = process_log(dir, &path, ContextFilter::None)
        .expect("process_log should succeed on fixtures");

    for prefix in &["031193dc", "0a962643"] {
        if let Some(row) = state.calls.iter().find(|r| r.uuid.starts_with(prefix)) {
            let dur = call_duration(row);
            assert!(
                dur < Duration::from_secs(300),
                "{prefix} duration should be ~1s (only seen in rotated file), \
                 not {dur:?} (inflated by latest_log_ts from current file)"
            );
        }
    }
}
