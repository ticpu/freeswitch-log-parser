//! Behavioral tests for entry rendering and filtering.

use freeswitch_log_parser::{AttachedLines, Block, LogEntry, LogLevel, MessageKind};

use super::color::{uuid_truecolor, BRIGHT_GREEN, RED, RESET};
use super::*;

fn entry(uuid: &str, message: &str, attached: &[&str]) -> LogEntry {
    let mut a = AttachedLines::new();
    for l in attached {
        a.push(l).expect("fits");
    }
    LogEntry {
        uuid: (!uuid.is_empty()).then(|| uuid.to_string()),
        attached: a,
        ..LogEntry::synthetic(message)
    }
}

const PEER: &str = "11111111-2222-3333-4444-555555555555";

fn printer(color: ColorMode, show_blocks: bool) -> EntryPrinter {
    EntryPrinter {
        color,
        show_blocks,
        show_session: false,
        show_filename: false,
        show_line_numbers: false,
    }
}

fn render(printer: &EntryPrinter, entry: &LogEntry) -> String {
    let mut out: Vec<u8> = Vec::new();
    printer.print_entry(&mut out, entry, None, None).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn attached_lines_inline_under_blocks() {
    let e = entry(
        "u",
        "Dialplan: parsing",
        &["Regex (PASS) x =~ /y/", "Action set"],
    );
    let out = render(&printer(ColorMode::Never, true), &e);
    assert!(out.contains("Regex (PASS) x =~ /y/"), "{out}");
    assert!(out.contains("Action set"), "{out}");
    assert!(!out.contains("attached lines"), "{out}");
}

const CHAN: &str = "sofia/internal/1262@pbx.example.test:5062";

#[test]
fn the_channel_heads_the_block_and_every_body_line_is_data() {
    let uuid = "9865d278-537b-4d4a-af91-f836729f78f2";
    let e = entry(
        uuid,
        &format!("Dialplan: {CHAN} parsing [default->unloop] continue=false"),
        &[format!("{uuid} Dialplan: {CHAN} Regex (PASS) [unloop] break=on-false").as_str()],
    );
    let out = render(&printer(ColorMode::Never, true), &e);
    let lines: Vec<&str> = out.lines().collect();

    assert!(lines[0].ends_with(&format!("Dialplan: {CHAN}")), "{out}");
    assert_eq!(lines[1].trim(), "parsing [default->unloop] continue=false");
    assert_eq!(lines[2].trim(), "Regex (PASS) [unloop] break=on-false");
}

#[test]
fn a_dialplan_line_with_no_body_keeps_its_data() {
    // Splitting a lone line would put its data on a continuation row of its own.
    let e = entry(
        "u",
        &format!("Dialplan: {CHAN} Absolute Condition [global]"),
        &[],
    );
    let out = render(&printer(ColorMode::Never, true), &e);
    assert!(
        out.trim_end().ends_with("Absolute Condition [global]"),
        "{out}"
    );
}

#[test]
fn a_foreign_uuid_in_a_body_line_survives() {
    // Only the entry's own UUID is redundant; any other one is a real value.
    let e = entry(
        "u",
        &format!("Dialplan: {CHAN} parsing [a->b] continue=true"),
        &[format!("u Dialplan: {CHAN} Regex (FAIL) ${{hdr}}({PEER}) =~ /^$/").as_str()],
    );
    let out = render(&printer(ColorMode::Never, true), &e);
    assert!(out.contains(PEER), "{out}");
    assert!(!out.contains(&format!("Dialplan: {CHAN} Regex")), "{out}");
}

#[test]
fn a_non_dialplan_continuation_only_loses_its_uuid() {
    let e = entry(
        "u",
        "msg",
        &["u EXECUTE [depth=0] sofia/internal/1001 bridge(sofia/gateway/gw/5551234)"],
    );
    let out = render(&printer(ColorMode::Never, false), &e);
    assert!(
        out.contains("  EXECUTE [depth=0] sofia/internal/1001 bridge(sofia/gateway/gw/5551234)"),
        "{out}"
    );
}

#[test]
fn attached_lines_collapse_without_blocks() {
    let e = entry("u", "Dialplan: parsing", &["one", "two"]);
    let out = render(&printer(ColorMode::Never, false), &e);
    assert!(out.contains("(2 attached lines)"), "{out}");
}

#[test]
fn lone_attached_line_always_inline() {
    let e = entry("u", "msg", &["the only continuation"]);
    let out = render(&printer(ColorMode::Never, false), &e);
    assert!(out.contains("the only continuation"), "{out}");
}

fn channel_data_entry() -> LogEntry {
    let mut e = entry(
        "u",
        "CHANNEL_DATA:",
        &["Channel-Name: [x]", "variable_a: [b]"],
    );
    e.block = Some(Block::ChannelData {
        fields: vec![("Channel-Name".into(), "x".into())],
        variables: vec![("variable_a".into(), "b".into())],
    });
    e
}

#[test]
fn an_expanded_block_does_not_also_count_its_raw_lines() {
    let out = render(&printer(ColorMode::Never, true), &channel_data_entry());
    assert!(out.contains("field  Channel-Name: x"), "{out}");
    assert!(!out.contains("attached lines"), "{out}");
}

#[test]
fn without_blocks_the_count_is_the_only_signal() {
    let out = render(&printer(ColorMode::Never, false), &channel_data_entry());
    assert!(out.contains("(2 attached lines)"), "{out}");
}

#[test]
fn a_marker_prints_as_a_rule_not_empty_columns() {
    let mut e = entry("", "freeswitch.log.1.xz", &[]);
    e.message_kind = MessageKind::FileChange;
    let out = render(&printer(ColorMode::Never, true), &e);
    assert_eq!(out, "── freeswitch.log.1.xz\n");
}

#[test]
fn embedded_uuid_gets_its_own_color() {
    let e = entry("aaaa", &format!("Peer UUID: {PEER}"), &[]);
    let out = render(&printer(ColorMode::Always, false), &e);
    let (r, g, b) = uuid_truecolor(PEER);
    assert!(
        out.contains(&format!("\x1b[38;2;{r};{g};{b}m{PEER}")),
        "{out}"
    );
}

#[test]
fn embedded_uuid_left_alone_without_color() {
    let e = entry("aaaa", &format!("Peer UUID: {PEER}"), &[]);
    let out = render(&printer(ColorMode::Never, false), &e);
    assert!(out.contains(&format!("Peer UUID: {PEER}")), "{out}");
    assert!(!out.contains("\x1b["), "{out}");
}

#[test]
fn pass_and_fail_are_colored_in_attached_lines() {
    let e = entry(
        "u",
        "Dialplan: parsing",
        &["Regex (PASS) a", "Regex (FAIL) b"],
    );
    let out = render(&printer(ColorMode::Always, true), &e);
    assert!(
        out.contains(&format!("{BRIGHT_GREEN}(PASS){RESET}")),
        "{out}"
    );
    assert!(out.contains(&format!("{RED}(FAIL){RESET}")), "{out}");
}

#[test]
fn long_variable_values_are_not_truncated() {
    let long = "x".repeat(500);
    let mut e = entry("u", "CHANNEL_DATA:", &[]);
    e.block = Some(Block::ChannelData {
        fields: Vec::new(),
        variables: vec![("variable_sip_multipart".to_string(), long.clone())],
    });
    let out = render(&printer(ColorMode::Never, true), &e);
    assert!(out.contains(&long), "{out}");
    assert!(!out.contains("..."), "{out}");
}

pub fn filter(p: FilterParams) -> FilterConfig {
    FilterConfig::new(FilterParams {
        uuid_strict: true,
        ..p
    })
    .unwrap()
}

#[test]
fn uuid_or_matches_any_needle() {
    let f = filter(FilterParams {
        uuid: vec!["aaaa".into(), "bbbb".into()],
        ..Default::default()
    });
    assert!(f.matches(&entry("xx-bbbb-yy", "msg", &[])));
    assert!(f.matches(&entry("aaaa-0000", "msg", &[])));
    assert!(!f.matches(&entry("cccc-0000", "msg", &[])));
}

#[test]
fn uuid_match_is_case_insensitive() {
    let f = filter(FilterParams {
        uuid: vec!["AAAABBBB".into()],
        ..Default::default()
    });
    assert!(f.matches(&entry("aaaabbbb-2222-3333-4444-555555555555", "msg", &[])));
}

#[test]
fn uuid_strict_ignores_message_body() {
    let mut f = filter(FilterParams {
        uuid: vec!["dead".into()],
        ..Default::default()
    });
    // strict: only the uuid field counts, not the message text
    assert!(!f.matches(&entry("0000", "peer dead leg", &[])));
    f.uuid_strict = false;
    assert!(f.matches(&entry("0000", "peer dead leg", &[])));
}

#[test]
fn fgrep_into_blocks_only_with_match_blocks() {
    let mut f = filter(FilterParams {
        fgrep: Some("m=audio".into()),
        ..Default::default()
    });
    let e = entry("u", "Remote SDP:", &["v=0", "m=audio 5004 RTP/AVP 0"]);
    assert!(!f.matches(&e));
    f.match_blocks = true;
    assert!(f.matches(&e));
}

#[test]
fn fgrep_is_case_insensitive() {
    let f = filter(FilterParams {
        fgrep: Some("RECEIVING INVITE".into()),
        ..Default::default()
    });
    assert!(f.matches(&entry("u", "receiving invite from 192.0.2.1", &[])));
}

#[test]
fn category_matches_any_of_several() {
    let f = filter(FilterParams {
        category: vec!["execute".into(), "dialplan".into()],
        ..Default::default()
    });
    let mut e = entry("u", "msg", &[]);
    e.message_kind = MessageKind::Dialplan {
        channel: "sofia/internal/1001".to_string(),
        detail: "parsing".to_string(),
    };
    assert!(f.matches(&e));
    e.message_kind = MessageKind::General;
    assert!(!f.matches(&e));
}

#[test]
fn for_discovery_clears_category_and_loosens() {
    let f = filter(FilterParams {
        category: vec!["execute".into()],
        uuid: vec!["seed".into()],
        ..Default::default()
    });
    let d = f.for_discovery();
    assert!(d.category.is_empty());
    assert!(!d.uuid_strict);
    assert!(d.match_blocks);
    // seed found in message body survives discovery despite category mismatch
    assert!(d.matches(&entry("0000", "found seed here", &[])));
}

fn codec_entry(names: &[&str], matched: &[&str]) -> LogEntry {
    let offer = |name: &str| {
        freeswitch_log_parser::CodecOffer::parse(
            freeswitch_log_parser::CodecMedia::Audio,
            &format!("{name}:0:8000:20:64000:1"),
        )
        .expect("token parses")
    };
    let mut e = entry("u", "Audio Codec Compare", &[]);
    e.block = Some(Block::CodecNegotiation {
        media: freeswitch_log_parser::CodecMedia::Audio,
        comparisons: names.iter().map(|n| (offer(n), offer("PCMU"))).collect(),
        matched: matched.iter().map(|n| offer(n)).collect(),
        near_matched: Vec::new(),
    });
    e
}

#[test]
fn codec_filter_matches_offers_and_matches() {
    let f = filter(FilterParams {
        codec: vec!["opus".into()],
        ..Default::default()
    });
    assert!(f.matches(&codec_entry(&["opus"], &[])), "a remote offer");
    assert!(f.matches(&codec_entry(&["G722"], &["opus"])), "the winner");
    assert!(!f.matches(&codec_entry(&["G722"], &["G722"])));
}

#[test]
fn codec_filter_is_case_insensitive() {
    let f = filter(FilterParams {
        codec: vec!["OPUS".into()],
        ..Default::default()
    });
    assert!(f.matches(&codec_entry(&["opus"], &[])));
}

/// A live audio stream, a held video one, and a stream carrying no payload type.
#[cfg(feature = "sdp")]
fn sdp_entry() -> LogEntry {
    let body = [
        "v=0",
        "o=- 1 1 IN IP4 192.0.2.10",
        "s=-",
        "c=IN IP4 192.0.2.10",
        "t=0 0",
        "m=audio 30000 RTP/AVP 0 101",
        "a=rtpmap:0 PCMU/8000",
        "a=rtpmap:101 telephone-event/8000",
        "a=fmtp:101 0-16",
        "m=video 0 RTP/AVP 99",
        "a=rtpmap:99 H264/90000",
        "m=application 5000 UDP/DTLS/SCTP webrtc-datachannel",
    ];
    let mut e = entry("u", "Remote SDP:", &[]);
    e.block = Some(Block::Sdp {
        direction: freeswitch_log_parser::SdpDirection::Remote,
        body: body.iter().map(|l| l.to_string()).collect(),
    });
    e
}

#[cfg(feature = "sdp")]
#[test]
fn sdp_summary_names_the_streams_that_carry_no_codec() {
    let out = render(&printer(ColorMode::Never, true), &sdp_entry());
    assert!(
        out.contains("PCMU/8000, 101 telephone-event/8000 0-16"),
        "{out}"
    );
    assert!(
        out.contains("held m=video port 0, skipped m=application/UDP/DTLS/SCTP"),
        "{out}"
    );
}

#[cfg(feature = "sdp")]
#[test]
fn codec_filter_matches_an_offer_on_a_held_stream() {
    let f = filter(FilterParams {
        codec: vec!["h264".into()],
        ..Default::default()
    });
    assert!(f.matches(&sdp_entry()));
}

#[test]
fn codec_filter_ignores_entries_without_media_blocks() {
    let f = filter(FilterParams {
        codec: vec!["opus".into()],
        ..Default::default()
    });
    assert!(!f.matches(&entry("u", "opus appears only in the text", &[])));
}

const CALL: &str = "aaaaaaaa-1111-1111-1111-111111111111";

fn hidden(f: &FilterConfig, e: &LogEntry) -> Option<Hidden> {
    match f.verdict(e) {
        Verdict::Hidden(h) => Some(h),
        _ => None,
    }
}

fn grep(pattern: &str) -> Option<regex::Regex> {
    Some(regex::Regex::new(pattern).expect("test pattern compiles"))
}

#[test]
fn a_pattern_in_the_uuid_column_is_counted() {
    let f = filter(FilterParams {
        grep: grep(CALL),
        ..Default::default()
    });
    assert_eq!(
        hidden(&f, &entry(CALL, "Activating RTCP", &[])),
        Some(Hidden::PatternInUuid)
    );
}

#[test]
fn the_uuid_column_probe_ignores_case() {
    let f = filter(FilterParams {
        grep: grep(&CALL.to_uppercase()),
        ..Default::default()
    });
    assert_eq!(
        hidden(&f, &entry(CALL, "Activating RTCP", &[])),
        Some(Hidden::PatternInUuid)
    );
}

#[test]
fn a_pattern_in_an_attached_line_is_counted_until_match_blocks() {
    let mut f = filter(FilterParams {
        fgrep: Some("m=audio".into()),
        ..Default::default()
    });
    let e = entry("u", "Remote SDP:", &["v=0", "m=audio 5004 RTP/AVP 0"]);
    assert_eq!(hidden(&f, &e), Some(Hidden::PatternInBlocks));
    f.match_blocks = true;
    assert_eq!(hidden(&f, &e), None, "the flag is already in effect");
}

#[test]
fn the_uuid_column_wins_over_the_attached_bucket() {
    let f = filter(FilterParams {
        fgrep: Some(CALL.into()),
        ..Default::default()
    });
    // An attached line naming the channel's own UUID is the common shape;
    // overlapping buckets would count it twice.
    let e = entry(CALL, "CHANNEL_DATA:", &[&format!("Unique-ID: [{CALL}]")]);
    assert_eq!(hidden(&f, &e), Some(Hidden::PatternInUuid));
}

#[test]
fn a_rejection_on_another_predicate_advertises_nothing() {
    let f = filter(FilterParams {
        grep: grep(CALL),
        min_level: Some(LogLevel::Err),
        ..Default::default()
    });
    let mut e = entry(CALL, "Activating RTCP", &[]);
    e.level = Some(LogLevel::Debug);
    assert_eq!(hidden(&f, &e), None);
}

#[test]
fn conjunct_patterns_widen_together_or_not_at_all() {
    let f = filter(FilterParams {
        fgrep: Some("hangup".into()),
        grep: grep(CALL),
        ..Default::default()
    });
    // Only --grep reaches the UUID column, so no single scope admits this.
    assert_eq!(hidden(&f, &entry(CALL, "Activating RTCP", &[])), None);
}

#[test]
fn a_uuid_named_in_the_body_is_counted() {
    let f = filter(FilterParams {
        uuid: vec![CALL.into()],
        ..Default::default()
    });
    assert_eq!(
        hidden(&f, &entry("bbbb", &format!("Bridging to {CALL}"), &[])),
        Some(Hidden::UuidInBody)
    );
    assert_eq!(hidden(&f, &entry("bbbb", "unrelated", &[])), None);
}

#[test]
fn a_uuid_inside_a_pattern_names_the_command() {
    let f = filter(FilterParams {
        grep: grep(&format!("Hangup on {CALL}")),
        ..Default::default()
    });
    assert_eq!(f.suggested_uuid(), Some(CALL));
}

#[test]
fn no_command_for_a_uuid_already_being_filtered_on() {
    let f = filter(FilterParams {
        uuid: vec![CALL.to_uppercase()],
        fgrep: Some(CALL.into()),
        ..Default::default()
    });
    assert_eq!(f.suggested_uuid(), None);
    let plain = filter(FilterParams {
        fgrep: Some("receiving invite".into()),
        ..Default::default()
    });
    assert_eq!(plain.suggested_uuid(), None, "no uuid in the pattern");
}
