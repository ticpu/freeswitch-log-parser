//! Behavioral tests for the field-span API — location, ordering, and rewrite
//! resolution.

use std::ops::Range;

use super::processing::ProcessingParts;
use super::*;

fn parts(msg: &str) -> ProcessingParts {
    processing_parts(msg).expect("should parse")
}

/// The `(kind, text)` pairs a message yields, in span order.
fn spans(msg: &str) -> Vec<(FieldKind, &str)> {
    message_fields(msg)
        .into_iter()
        .map(|f| (f.kind, &msg[f.range]))
        .collect()
}

#[test]
fn bracketed_shape_keeps_number_in_head() {
    let msg = "Processing ACME <15555550100>->1263 in context public";
    let p = parts(msg);
    assert_eq!(&msg[p.head], "ACME <15555550100>");
    assert_eq!(&msg[p.dest], "1263");
    assert_eq!(&msg[p.context], "public");
}

#[test]
fn name_containing_arrow_and_angle_survives_anchoring() {
    let msg = "Processing a->b <c <15555550100>->1263 in context public";
    let p = parts(msg);
    assert_eq!(&msg[p.head], "a->b <c <15555550100>");
    assert_eq!(&msg[p.dest], "1263");
}

#[test]
fn bare_shape_falls_back_to_last_arrow() {
    let msg = "Processing 15555550100->1263 in context public";
    let p = parts(msg);
    assert_eq!(&msg[p.head], "15555550100");
    assert_eq!(&msg[p.dest], "1263");
}

#[test]
fn multibyte_name_keeps_spans_on_char_boundaries() {
    let msg = "Processing Jérôme <15555550100>->1263 in context public";
    let p = parts(msg);
    assert_eq!(&msg[p.head], "Jérôme <15555550100>");
    assert_eq!(&msg[p.dest], "1263");
}

#[test]
fn context_stops_at_first_whitespace() {
    let msg = "Processing ACME <15555550100>->1263 in context public extra";
    let p = parts(msg);
    assert_eq!(&msg[p.context], "public");
}

#[test]
fn rightmost_in_context_wins() {
    let msg = "Processing a in context b <15555550100>->1263 in context public";
    let p = parts(msg);
    assert_eq!(&msg[p.context], "public");
    assert_eq!(&msg[p.head], "a in context b <15555550100>");
}

#[test]
fn padded_context_marker_keeps_span_on_the_token() {
    let msg = "Processing 15555550100->1263 in context \tpublic";
    let p = parts(msg);
    assert_eq!(&msg[p.context], "public");
}

/// Padding shifts the span end back into the token's last character, so a
/// trailing multi-byte character is what turns the misalignment into a panic.
#[test]
fn padded_multibyte_context_stays_on_char_boundaries() {
    let msg = "Processing 15555550100->1263 in context  café";
    let p = parts(msg);
    assert_eq!(&msg[p.context], "café");
}

#[test]
fn no_context_marker_yields_none() {
    assert!(processing_parts("Processing ACME <15555550100>->1263").is_none());
}

#[test]
fn processing_splits_name_and_number() {
    let msg = "Processing ACME <15555550100>->1263 in context public";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::CallerIdName, "ACME"),
            (FieldKind::CallerIdNumber, "15555550100"),
            (FieldKind::DestinationNumber, "1263"),
        ]
    );
}

#[test]
fn processing_numeric_display_name_is_still_a_name() {
    let msg = "Processing 1263 <1263>->start_recording in context recordings";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::CallerIdName, "1263"),
            (FieldKind::CallerIdNumber, "1263"),
            (FieldKind::DestinationNumber, "start_recording"),
        ]
    );
}

#[test]
fn processing_empty_name_yields_no_name_span() {
    let msg = "Processing  <15555550100>->1263 in context public";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::CallerIdNumber, "15555550100"),
            (FieldKind::DestinationNumber, "1263"),
        ]
    );
}

#[test]
fn processing_bare_shape_emits_only_destination() {
    let msg = "Processing 15555550100->1263 in context public";
    assert_eq!(spans(msg), [(FieldKind::DestinationNumber, "1263")]);
}

#[test]
fn execute_emits_channel_and_its_host() {
    let msg = "EXECUTE [depth=0] sofia/internal/+15555550100@192.0.2.1 answer";
    assert_eq!(
        spans(msg),
        [
            (
                FieldKind::ChannelName,
                "sofia/internal/+15555550100@192.0.2.1"
            ),
            (FieldKind::IpAddr, "192.0.2.1"),
        ]
    );
}

#[test]
fn execute_without_channel_emits_nothing() {
    assert_eq!(spans("Execute [depth=2] set(RECORD_STEREO=true)"), []);
}

#[test]
fn dialplan_emits_channel() {
    let msg = "Dialplan: sofia/internal/1263@192.0.2.1 parsing [public->global] continue=true";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.1"),
        ]
    );
}

#[test]
fn set_emits_channel_but_export_does_not() {
    let msg = "SET sofia/internal/1263@192.0.2.1 [ngcs_bridge]=[host.example.test]";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.1"),
        ]
    );
    assert_eq!(spans("EXPORT (export_vars) [originate_timeout]=[3600]"), []);
}

#[test]
fn bracketed_ipv6_channel_host_excludes_brackets() {
    let msg = "SET sofia/internal-v6/1263@[2001:db8:2220:198::10] [x]=[y]";
    assert_eq!(
        spans(msg),
        [
            (
                FieldKind::ChannelName,
                "sofia/internal-v6/1263@[2001:db8:2220:198::10]"
            ),
            (FieldKind::IpAddr, "2001:db8:2220:198::10"),
        ]
    );
}

#[test]
fn channel_host_with_port_strips_it() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1:5060 answer";
    assert_eq!(spans(msg)[1], (FieldKind::IpAddr, "192.0.2.1"));
}

#[test]
fn hostname_channel_host_is_not_an_address() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@host.example.test answer";
    assert_eq!(
        spans(msg),
        [(
            FieldKind::ChannelName,
            "sofia/internal/1263@host.example.test"
        )]
    );
}

#[test]
fn receiving_invite_emits_call_id_and_source() {
    let msg = "sofia/internal/1263@192.0.2.1 receiving invite from 192.0.2.10:47215 version: 1.10.13 call-id: 00112233-4455-6677-8899-aabbccddeeff";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.10"),
            (FieldKind::CallId, "00112233-4455-6677-8899-aabbccddeeff"),
        ]
    );
}

#[test]
fn call_id_that_is_a_uuid_suppresses_the_generic_span() {
    let msg = "sofia/internal/sos sending invite call-id: ffeeddcc-bbaa-9988-7766-554433221100";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::ChannelName, "sofia/internal/sos"),
            (FieldKind::CallId, "ffeeddcc-bbaa-9988-7766-554433221100"),
        ]
    );
}

#[test]
fn null_call_id_emits_nothing() {
    let msg = "sofia/telus/15555550101 sending invite call-id: (null)";
    assert_eq!(
        spans(msg),
        [(FieldKind::ChannelName, "sofia/telus/15555550101")]
    );
}

#[test]
fn sending_invite_has_no_source_address() {
    let msg = "sofia/telus/15555550101 sending invite version: 1.10.13 64bit";
    assert_eq!(
        spans(msg),
        [(FieldKind::ChannelName, "sofia/telus/15555550101")]
    );
}

#[test]
fn paren_channel_state_line_emits_channel() {
    let msg = "(sofia/internal-v4/sos) Callstate Change RINGING -> ACTIVE";
    assert_eq!(
        spans(msg),
        [(FieldKind::ChannelName, "sofia/internal-v4/sos")]
    );
}

#[test]
fn hangup_and_new_channel_emit_channel() {
    let hangup = "Hangup sofia/internal/1263@192.0.2.1 [CS_CONSUME_MEDIA] [NORMAL_CLEARING]";
    assert_eq!(spans(hangup)[0].1, "sofia/internal/1263@192.0.2.1");

    let new = "New Channel sofia/internal/1263@192.0.2.1 [00112233-4455-6677-8899-aabbccddeeff]";
    assert_eq!(
        spans(new),
        [
            (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.1"),
            (FieldKind::Uuid, "00112233-4455-6677-8899-aabbccddeeff"),
        ]
    );
}

#[test]
fn channel_data_caller_fields_map_to_their_kinds() {
    assert_eq!(
        spans("Caller-Caller-ID-Number: [15555550100]"),
        [(FieldKind::CallerIdNumber, "15555550100")]
    );
    assert_eq!(
        spans("Caller-Caller-ID-Name: [ACME INC]"),
        [(FieldKind::CallerIdName, "ACME INC")]
    );
    assert_eq!(
        spans("Caller-Destination-Number: [1263]"),
        [(FieldKind::DestinationNumber, "1263")]
    );
    assert_eq!(
        spans("Channel-Name: [sofia/internal/1263@192.0.2.1]"),
        [
            (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
            (FieldKind::IpAddr, "192.0.2.1"),
        ]
    );
}

#[test]
fn unmapped_channel_field_emits_nothing() {
    assert_eq!(spans("Channel-State: [CS_EXECUTE]"), []);
}

#[test]
fn unique_id_value_keeps_its_uuid_span() {
    let msg = "Unique-ID: [00112233-4455-6677-8899-aabbccddeeff]";
    assert_eq!(
        spans(msg),
        [(FieldKind::Uuid, "00112233-4455-6677-8899-aabbccddeeff")]
    );
}

#[test]
fn multibyte_name_shifts_later_spans() {
    let msg = "Processing Jérôme <15555550100>->1263 in context public";
    assert_eq!(
        spans(msg),
        [
            (FieldKind::CallerIdName, "Jérôme"),
            (FieldKind::CallerIdNumber, "15555550100"),
            (FieldKind::DestinationNumber, "1263"),
        ]
    );
    for f in message_fields(msg) {
        assert!(msg.is_char_boundary(f.range.start) && msg.is_char_boundary(f.range.end));
    }
}

#[test]
fn spans_are_ordered_container_first() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer";
    let fields = message_fields(msg);
    assert_eq!(fields[0].kind, FieldKind::ChannelName);
    assert!(fields[0].range.start <= fields[1].range.start);
    assert!(fields[1].range.end <= fields[0].range.end);
}

#[test]
fn general_message_emits_nothing() {
    assert_eq!(spans("Activating RTCP PORT 4001"), []);
}

const UUID1: &str = "00112233-4455-6677-8899-aabbccddeeff";

fn entry_from(lines: &[String]) -> crate::stream::LogEntry {
    crate::stream::LogStream::new(lines.iter().cloned())
        .next()
        .expect("one entry")
}

fn text_at<'a>(entry: &'a crate::stream::LogEntry, f: &Field) -> &'a str {
    match f.at {
        FieldLocation::Message => &entry.message[f.range.clone()],
        FieldLocation::Attached(i) => &entry.attached.get(i).expect("line")[f.range.clone()],
    }
}

#[test]
fn attached_spans_index_the_raw_line_including_its_prefix() {
    let lines = vec![
        format!(
            "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] mod_dptools.c:1999 CHANNEL_DATA:"
        ),
        format!("{UUID1} Caller-Caller-ID-Number: [15555550100]"),
    ];
    let entry = entry_from(&lines);
    let fields = entry.fields();

    // The prefix UUID of the attached line is located, and the caller-id
    // span sits past it in the same coordinate system.
    let attached: Vec<_> = fields
        .iter()
        .filter(|f| f.at == FieldLocation::Attached(0))
        .collect();
    assert_eq!(attached[0].kind, FieldKind::Uuid);
    assert_eq!(text_at(&entry, attached[0]), UUID1);
    assert_eq!(attached[1].kind, FieldKind::CallerIdNumber);
    assert_eq!(text_at(&entry, attached[1]), "15555550100");
    assert!(attached[1].range.start > UUID1.len());
}

#[test]
fn message_and_attached_locations_stay_separate() {
    let lines = vec![
        format!(
            "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] mod_dptools.c:1999 CHANNEL_DATA:"
        ),
        format!("{UUID1} Channel-Name: [sofia/internal/1263@192.0.2.1]"),
    ];
    let entry = entry_from(&lines);
    for f in entry.fields() {
        let text = text_at(&entry, &f);
        assert!(!text.is_empty());
        match f.kind {
            FieldKind::Uuid => assert!(crate::uuid::is_uuid(text)),
            FieldKind::ChannelName => assert_eq!(text, "sofia/internal/1263@192.0.2.1"),
            FieldKind::IpAddr => assert_eq!(text, "192.0.2.1"),
            other => panic!("unexpected kind {other}"),
        }
    }
}

#[test]
fn bare_continuation_has_no_prefix_to_skip() {
    let lines = vec![
        format!(
            "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] mod_dptools.c:1999 CHANNEL_DATA:"
        ),
        format!("{UUID1} variable_sip_full_from: [x"),
        "Caller-Destination-Number: [1263]".to_string(),
    ];
    let entry = entry_from(&lines);
    let f = entry
        .fields()
        .into_iter()
        .find(|f| f.kind == FieldKind::DestinationNumber)
        .expect("destination span");
    assert_eq!(f.at, FieldLocation::Attached(1));
    assert_eq!(text_at(&entry, &f), "1263");
}

fn field(kind: FieldKind, range: Range<usize>) -> Field {
    Field {
        kind,
        at: FieldLocation::Message,
        range,
    }
}

#[test]
fn identity_callback_returns_the_input() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer";
    let out = apply_fields(msg, message_fields(msg).iter(), |_, _| None).expect("no error");
    assert_eq!(out, msg);
}

#[test]
fn outer_replacement_absorbs_the_one_inside_it() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer";
    let out = apply_fields(msg, message_fields(msg).iter(), |f, _| {
        Some(format!("<{}>", f.kind))
    })
    .expect("nesting is not a conflict");
    assert_eq!(out, "EXECUTE [depth=0] <channel-name> answer");
}

#[test]
fn inner_replacement_applies_when_the_outer_is_left_alone() {
    let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer";
    let out = apply_fields(msg, message_fields(msg).iter(), |f, _| {
        (f.kind == FieldKind::IpAddr).then(|| "<ip>".to_string())
    })
    .expect("no error");
    assert_eq!(out, "EXECUTE [depth=0] sofia/internal/1263@<ip> answer");
}

#[test]
fn partial_overlap_between_replacements_is_an_error() {
    let text = "abcdefgh";
    let fields = [
        field(FieldKind::ChannelName, 0..5),
        field(FieldKind::CallId, 3..8),
    ];
    let err = apply_fields(text, fields.iter(), |_, _| Some("x".to_string()))
        .expect_err("partial overlap");
    assert!(matches!(err, RenderError::OverlappingSpans { .. }));
}

#[test]
fn span_splitting_a_character_is_an_error_not_a_panic() {
    let msg = "Processing Jérôme <15555550100>->1263 in context public";
    // One byte into the é.
    let fields = [field(FieldKind::CallerIdName, 11..13)];
    let err = apply_fields(msg, fields.iter(), |_, _| Some("x".to_string())).expect_err("boundary");
    assert!(matches!(err, RenderError::NotOnCharBoundary { .. }));
}

#[test]
fn out_of_bounds_span_is_an_error() {
    let err = apply_fields("short", [field(FieldKind::Uuid, 0..99)].iter(), |_, _| {
        Some("x".to_string())
    })
    .expect_err("out of bounds");
    assert!(matches!(err, RenderError::OutOfBounds { .. }));
}

#[test]
fn a_span_is_validated_even_when_it_is_not_replaced() {
    let err = apply_fields("short", [field(FieldKind::Uuid, 0..99)].iter(), |_, _| None)
        .expect_err("validated regardless of the callback");
    assert!(matches!(err, RenderError::OutOfBounds { .. }));
}

#[test]
fn render_with_rewrites_message_and_attached_separately() {
    let lines = vec![
        format!(
            "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] mod_dptools.c:1999 CHANNEL_DATA:"
        ),
        format!("{UUID1} Caller-Caller-ID-Number: [15555550100]"),
    ];
    let entry = entry_from(&lines);
    let out = entry
        .render_with(|f, _| (f.kind == FieldKind::CallerIdNumber).then(|| "<tel>".to_string()))
        .expect("no error");
    assert_eq!(out.message, entry.message);
    assert_eq!(
        out.attached[0],
        format!("{UUID1} Caller-Caller-ID-Number: [<tel>]")
    );
}

#[test]
fn render_with_replacing_every_field_keeps_the_uuid_prefix_addressable() {
    let lines = vec![
        format!(
            "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] mod_dptools.c:1999 CHANNEL_DATA:"
        ),
        format!("{UUID1} Channel-Name: [sofia/internal/1263@192.0.2.1]"),
    ];
    let entry = entry_from(&lines);
    let out = entry
        .render_with(|f, _| Some(format!("<{}>", f.kind)))
        .expect("no error");
    assert_eq!(out.attached[0], "<uuid> Channel-Name: [<channel-name>]");
}

#[test]
fn entry_without_attached_lines_yields_message_spans_only() {
    let lines = vec![format!(
        "{UUID1} 2026-02-01 10:00:00.000000 95.97% [DEBUG] switch_core_session.c:2907 \
         EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer"
    )];
    let entry = entry_from(&lines);
    let fields = entry.fields();
    assert!(fields.iter().all(|f| f.at == FieldLocation::Message));
    assert_eq!(fields[0].kind, FieldKind::ChannelName);
}
