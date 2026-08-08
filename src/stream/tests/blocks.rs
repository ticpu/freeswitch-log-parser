//! CHANNEL_DATA and SDP block detection, and multi-line value reassembly.

use freeswitch_types::variables::SofiaVariable;
use freeswitch_types::ChannelVariable;

use super::*;

// --- New: Block detection tests ---

#[test]
fn channel_data_block_fields_and_variables() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        format!("{UUID1} Unique-ID: [{UUID1}]"),
        "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
        "variable_direction: [inbound]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].message_kind, MessageKind::ChannelData);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 3);
            assert_eq!(
                fields[0],
                (
                    "Channel-Name".to_string(),
                    "sofia/internal/+15550001234@192.0.2.1".to_string()
                )
            );
            assert_eq!(
                fields[1],
                ("Channel-State".to_string(), "CS_EXECUTE".to_string())
            );
            assert_eq!(fields[2], ("Unique-ID".to_string(), UUID1.to_string()));
            assert_eq!(variables.len(), 2);
            assert_eq!(
                variables[0],
                (
                    "variable_sip_call_id".to_string(),
                    "test123@192.0.2.1".to_string()
                )
            );
            assert_eq!(
                variables[1],
                ("variable_direction".to_string(), "inbound".to_string())
            );
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
}

#[test]
fn channel_data_multiline_variable_reassembly() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        "variable_switch_r_sdp: [v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        "s=-".to_string(),
        "c=IN IP4 192.0.2.1".to_string(),
        "m=audio 47758 RTP/AVP 0 101".to_string(),
        "a=rtpmap:0 PCMU/8000".to_string(),
        "]".to_string(),
        "variable_direction: [inbound]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 1);
            assert_eq!(variables.len(), 2);
            assert_eq!(variables[0].0, "variable_switch_r_sdp");
            assert!(variables[0].1.starts_with("v=0\n"));
            assert!(variables[0].1.contains("m=audio 47758 RTP/AVP 0 101"));
            assert!(!variables[0].1.ends_with(']'));
            assert_eq!(
                variables[1],
                ("variable_direction".to_string(), "inbound".to_string())
            );
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
    assert_eq!(entries[0].attached.len(), 9);
}

#[test]
fn sdp_block_detection() {
    let lines = vec![
        full_line(UUID1, TS1, "Local SDP:"),
        "v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        "s=-".to_string(),
        "c=IN IP4 192.0.2.1".to_string(),
        "m=audio 10000 RTP/AVP 0".to_string(),
        "a=rtpmap:0 PCMU/8000".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    match &entries[0].message_kind {
        MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Local),
        other => panic!("expected SdpMarker, got {other:?}"),
    }
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::Sdp { direction, body } => {
            assert_eq!(*direction, SdpDirection::Local);
            assert_eq!(body.len(), 6);
            assert_eq!(body[0], "v=0");
            assert_eq!(body[5], "a=rtpmap:0 PCMU/8000");
        }
        other => panic!("expected Sdp block, got {other:?}"),
    }
}

#[test]
fn sdp_block_terminated_by_primary_line() {
    let lines = vec![
        full_line(UUID1, TS1, "Remote SDP:"),
        "v=0".to_string(),
        "m=audio 10000 RTP/AVP 0".to_string(),
        full_line(UUID1, TS2, "Next event"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 2);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::Sdp { direction, body } => {
            assert_eq!(*direction, SdpDirection::Remote);
            assert_eq!(body.len(), 2);
        }
        other => panic!("expected Sdp block, got {other:?}"),
    }
    assert!(entries[1].block.is_none());
}

#[test]
fn sdp_from_uuid_continuation() {
    let lines = vec![
        format!("{UUID1} Local SDP:"),
        format!("{UUID1} v=0"),
        format!("{UUID1} o=FreeSWITCH 1234 5678 IN IP4 192.0.2.1"),
        format!("{UUID1} s=FreeSWITCH"),
        format!("{UUID1} c=IN IP4 192.0.2.1"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::Sdp { direction, body } => {
            assert_eq!(*direction, SdpDirection::Local);
            assert_eq!(body.len(), 4);
            assert_eq!(body[0], "v=0");
        }
        other => panic!("expected Sdp block, got {other:?}"),
    }
}

#[test]
fn channel_data_interrupted_by_different_uuid() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID2} Dialplan: sofia/internal/+15559999999@192.0.2.1 parsing [public]"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 2);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, .. } => {
            assert_eq!(fields.len(), 1);
        }
        other => panic!("expected ChannelData, got {other:?}"),
    }
}

#[test]
fn no_block_for_non_block_message() {
    let lines = vec![full_line(UUID1, TS1, "some random freeswitch log message")];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].block.is_none());
    assert_eq!(entries[0].message_kind, MessageKind::General);
}

#[test]
fn message_kind_on_execute() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(foo=bar)"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 2);
    match &entries[1].message_kind {
        MessageKind::Execute {
            application,
            arguments,
            ..
        } => {
            assert_eq!(application, "set");
            assert_eq!(arguments, "foo=bar");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn block_accessors_hide_the_variable_prefix() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/1000@192.0.2.1]"),
        "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    let block = entries[0].block.as_ref().expect("should have block");

    assert_eq!(
        block.field("Channel-Name"),
        Some("sofia/internal/1000@192.0.2.1")
    );
    assert_eq!(block.field("Channel-State"), None);
    assert_eq!(
        block.variable(SofiaVariable::SipCallId),
        Some("test123@192.0.2.1"),
        "the caller never spells the variable_ prefix a dump stores"
    );
    assert_eq!(block.variable(ChannelVariable::Direction), None);
}

/// The closing `]` is one delimiter, not a run of them — a value whose own last
/// character is `]` keeps it.
#[test]
fn channel_data_multiline_variable_keeps_a_trailing_bracket() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        "variable_json_payload: [{".to_string(),
        r#""targets":[1,2]]"#.to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { variables, .. } => {
            assert_eq!(variables[0].1, "{\n\"targets\":[1,2]");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
}

#[test]
fn channel_data_multiline_variable_spans_many_lines() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        "variable_switch_r_sdp: [v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        "s=-".to_string(),
        "c=IN IP4 192.0.2.1".to_string(),
        "t=0 0".to_string(),
        "m=audio 47758 RTP/AVP 0 8 101".to_string(),
        "a=rtpmap:0 PCMU/8000".to_string(),
        "a=rtpmap:8 PCMA/8000".to_string(),
        "a=rtpmap:101 telephone-event/8000".to_string(),
        "a=fmtp:101 0-16".to_string(),
        "]".to_string(),
        "variable_direction: [inbound]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 1);
            assert_eq!(variables.len(), 2);
            assert_eq!(variables[0].0, "variable_switch_r_sdp");
            let sdp = &variables[0].1;
            assert!(sdp.starts_with("v=0\n"));
            assert!(sdp.contains("a=fmtp:101 0-16"));
            assert!(!sdp.ends_with(']'));
            assert_eq!(variables[1].0, "variable_direction");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
}

#[test]
fn sdp_from_verto_update_media() {
    let lines = vec![
        full_line(UUID1, TS1, "updateMedia: Local SDP"),
        "v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        "m=audio 10000 RTP/AVP 0".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    match &entries[0].message_kind {
        MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Local),
        other => panic!("expected SdpMarker, got {other:?}"),
    }
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::Sdp { direction, body } => {
            assert_eq!(*direction, SdpDirection::Local);
            assert_eq!(body.len(), 3);
        }
        other => panic!("expected Sdp block, got {other:?}"),
    }
}

#[test]
fn duplicate_sdp_marker() {
    let lines = vec![
        full_line(UUID1, TS1, "Duplicate SDP"),
        "v=0".to_string(),
        "m=audio 10000 RTP/AVP 0".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    match &entries[0].message_kind {
        MessageKind::SdpMarker { direction } => assert_eq!(*direction, SdpDirection::Unknown),
        other => panic!("expected SdpMarker, got {other:?}"),
    }
    assert!(entries[0].block.is_some());
}
