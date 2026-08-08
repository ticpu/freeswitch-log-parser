//! Behavioral tests for [`classify_message`] — one per line shape it recognizes.

use super::*;

#[test]
fn execute_full() {
    let msg = "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/ng_a1b2c3d4/city/ST GEORGES)";
    let kind = classify_message(msg);
    assert_eq!(
        kind,
        MessageKind::Execute {
            depth: 0,
            channel: "sofia/internal/+15550001234@192.0.2.1".to_string(),
            application: "db".to_string(),
            arguments: "insert/ng_a1b2c3d4/city/ST GEORGES".to_string(),
        }
    );
}

#[test]
fn execute_nested_depth() {
    let msg = "EXECUTE [depth=2] sofia/internal/+15550001234@192.0.2.1 set(x=y)";
    match classify_message(msg) {
        MessageKind::Execute {
            depth,
            application,
            arguments,
            ..
        } => {
            assert_eq!(depth, 2);
            assert_eq!(application, "set");
            assert_eq!(arguments, "x=y");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn execute_no_arguments() {
    let msg = "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 answer";
    match classify_message(msg) {
        MessageKind::Execute {
            application,
            arguments,
            ..
        } => {
            assert_eq!(application, "answer");
            assert_eq!(arguments, "");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn execute_export_with_vars() {
    let msg =
        "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)";
    match classify_message(msg) {
        MessageKind::Execute {
            application,
            arguments,
            ..
        } => {
            assert_eq!(application, "export");
            assert_eq!(arguments, "originate_timeout=3600");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn dialplan_parsing() {
    let msg =
        "Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public->global] continue=true";
    match classify_message(msg) {
        MessageKind::Dialplan { channel, detail } => {
            assert_eq!(channel, "sofia/internal/+15550001234@192.0.2.1");
            assert_eq!(detail, "parsing [public->global] continue=true");
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn dialplan_regex() {
    let msg = "Dialplan: sofia/internal/+15550001234@192.0.2.1 Regex (PASS) [global_routing] destination_number(18001234567) =~ /^1?(\\d{10})$/ break=on-false";
    match classify_message(msg) {
        MessageKind::Dialplan { channel, detail } => {
            assert_eq!(channel, "sofia/internal/+15550001234@192.0.2.1");
            assert!(detail.starts_with("Regex (PASS)"));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn dialplan_action() {
    let msg = "Dialplan: sofia/internal/+15550001234@192.0.2.1 Action set(call_direction=inbound)";
    match classify_message(msg) {
        MessageKind::Dialplan { detail, .. } => {
            assert!(detail.starts_with("Action "));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn channel_data_marker() {
    assert_eq!(classify_message("CHANNEL_DATA:"), MessageKind::ChannelData);
}

#[test]
fn channel_data_in_message() {
    assert_eq!(
        classify_message("New CHANNEL_DATA arrived"),
        MessageKind::ChannelData,
    );
}

#[test]
fn channel_field_with_brackets() {
    let msg = "Channel-State: [CS_EXECUTE]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Channel-State");
            assert_eq!(value, "CS_EXECUTE");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn channel_field_name() {
    let msg = "Channel-Name: [sofia/internal/+15550001234@192.0.2.1]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Channel-Name");
            assert_eq!(value, "sofia/internal/+15550001234@192.0.2.1");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn variable_single_line() {
    let msg = "variable_sip_call_id: [test123@192.0.2.1]";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_sip_call_id");
            assert_eq!(value, "test123@192.0.2.1");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn variable_multi_line_start() {
    let msg = "variable_switch_r_sdp: [v=0";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_switch_r_sdp");
            assert_eq!(value, "v=0");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn sdp_local() {
    assert_eq!(
        classify_message("Local SDP:"),
        MessageKind::SdpMarker {
            direction: SdpDirection::Local
        },
    );
}

#[test]
fn sdp_remote() {
    assert_eq!(
        classify_message("Remote SDP:"),
        MessageKind::SdpMarker {
            direction: SdpDirection::Remote
        },
    );
}

#[test]
fn sdp_in_longer_message() {
    match classify_message("Setting Local SDP for call") {
        MessageKind::SdpMarker { direction } => {
            assert_eq!(direction, SdpDirection::Local);
        }
        other => panic!("expected SdpMarker, got {other:?}"),
    }
}

#[test]
fn sdp_unknown_direction() {
    assert_eq!(
        classify_message("Patched SDP:"),
        MessageKind::SdpMarker {
            direction: SdpDirection::Unknown
        },
    );
}

#[test]
fn ring_sdp_is_local_ring() {
    assert_eq!(
        classify_message("Ring SDP:"),
        MessageKind::SdpMarker {
            direction: SdpDirection::LocalRing
        },
    );
}

#[test]
fn state_change() {
    let msg = "State Change CS_INIT -> CS_ROUTING";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert_eq!(detail, msg);
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn core_session_set_variable() {
    match classify_message("CoreSession::setVariable(X-City, ST GEORGES)") {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_X-City");
            assert_eq!(value, "ST GEORGES");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn general_empty() {
    assert_eq!(classify_message(""), MessageKind::General);
}

#[test]
fn hangup_is_channel_lifecycle() {
    match classify_message(
        "Hangup sofia/internal/+15550001234@192.0.2.1 [CS_CONSUME_MEDIA] [NORMAL_CLEARING]",
    ) {
        MessageKind::ChannelLifecycle { .. } => {}
        other => panic!("expected ChannelLifecycle, got {other:?}"),
    }
}

#[test]
fn channel_field_no_brackets() {
    let msg = "Channel-Presence-ID: 1234@192.0.2.1";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Channel-Presence-ID");
            assert_eq!(value, "1234@192.0.2.1");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn variable_no_brackets() {
    let msg = "variable_direction: inbound";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_direction");
            assert_eq!(value, "inbound");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

// --- New: Extended patterns found in production ---

#[test]
fn execute_lowercase() {
    let msg = "Execute [depth=2] set(RECORD_STEREO=true)";
    match classify_message(msg) {
        MessageKind::Execute {
            depth,
            application,
            arguments,
            ..
        } => {
            assert_eq!(depth, 2);
            assert_eq!(application, "set");
            assert_eq!(arguments, "RECORD_STEREO=true");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn execute_lowercase_db() {
    let msg = "Execute [depth=1] db(insert/ng_${originating_leg_uuid}/record_leg/${uuid})";
    match classify_message(msg) {
        MessageKind::Execute { application, .. } => {
            assert_eq!(application, "db");
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn set_variable_message() {
    let msg = "SET sofia/internal-v6/1263@[2001:db8:2220:198::10] [ngcs_bridge_sip_req_uri]=[conf-factory-app.qc.core.ng.example.test]";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_ngcs_bridge_sip_req_uri");
            assert_eq!(value, "conf-factory-app.qc.core.ng.example.test");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn export_variable_message() {
    let msg =
        "EXPORT (export_vars) (REMOTE ONLY) [sip_from_uri]=[sip:psap1.qc.psap.ng.example.test]";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_sip_from_uri");
            assert_eq!(value, "sip:psap1.qc.psap.ng.example.test");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn export_simple_variable() {
    let msg = "EXPORT (export_vars) [originate_timeout]=[3600]";
    match classify_message(msg) {
        MessageKind::Variable { name, value } => {
            assert_eq!(name, "variable_originate_timeout");
            assert_eq!(value, "3600");
        }
        other => panic!("expected Variable, got {other:?}"),
    }
}

#[test]
fn processing_in_context() {
    let msg = "Processing Extension 1263 <1263>->start_recording in context recordings";
    match classify_message(msg) {
        MessageKind::Dialplan { detail, .. } => {
            assert!(detail.contains("start_recording"));
            assert!(detail.contains("recordings"));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn caller_field_as_channel_field() {
    let msg = "Caller-Username: [+15550001234]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Caller-Username");
            assert_eq!(value, "+15550001234");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn answer_state_as_channel_field() {
    let msg = "Answer-State: [ringing]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Answer-State");
            assert_eq!(value, "ringing");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn unique_id_as_channel_field() {
    let msg = "Unique-ID: [a1b2c3d4-e5f6-7890-abcd-ef1234567890]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Unique-ID");
            assert_eq!(value, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn call_direction_as_channel_field() {
    let msg = "Call-Direction: [inbound]";
    match classify_message(msg) {
        MessageKind::ChannelField { name, value } => {
            assert_eq!(name, "Call-Direction");
            assert_eq!(value, "inbound");
        }
        other => panic!("expected ChannelField, got {other:?}"),
    }
}

#[test]
fn callstate_change() {
    let msg = "(sofia/internal-v4/sos) Callstate Change RINGING -> ACTIVE";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert!(detail.contains("RINGING -> ACTIVE"));
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn action_is_pre_dialplan_lifecycle() {
    match classify_message("action(1:3pcc_force_dialplan:1:set_tflag) success") {
        MessageKind::ChannelLifecycle { .. } => {}
        other => panic!("expected ChannelLifecycle, got {other:?}"),
    }
}

#[test]
fn channel_answered_is_lifecycle() {
    match classify_message("Channel [sofia/internal] has been answered") {
        MessageKind::ChannelLifecycle { .. } => {}
        other => panic!("expected ChannelLifecycle, got {other:?}"),
    }
}

#[test]
fn chatplan_regex() {
    let msg = "Chatplan: sofia/internal/+15550001234@192.0.2.1 Regex (PASS) [global_routing] destination_number(18001234567) =~ /^1?(\\d{10})$/ break=on-false";
    match classify_message(msg) {
        MessageKind::Dialplan { channel, detail } => {
            assert_eq!(channel, "sofia/internal/+15550001234@192.0.2.1");
            assert!(detail.starts_with("Regex (PASS)"));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn chatplan_action() {
    let msg = "Chatplan: sofia/internal/+15550001234@192.0.2.1 Action set(call_direction=inbound)";
    match classify_message(msg) {
        MessageKind::Dialplan { detail, .. } => {
            assert!(detail.starts_with("Action "));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn chatplan_anti_action() {
    let msg = "Chatplan: sofia/internal/+15550001234@192.0.2.1 ANTI-Action log(WARNING no match)";
    match classify_message(msg) {
        MessageKind::Dialplan { detail, .. } => {
            assert!(detail.starts_with("ANTI-Action "));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn standard_execute_is_state_change() {
    let msg = "sofia/internal/+15550001234@192.0.2.1 Standard EXECUTE";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert_eq!(detail, "Standard EXECUTE");
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn sofia_execute_is_state_change() {
    let msg = "sofia/internal/+15550001234@192.0.2.1 SOFIA EXECUTE";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert_eq!(detail, "SOFIA EXECUTE");
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn rtc_execute_is_state_change() {
    let msg = "sofia/internal/+15550001234@192.0.2.1 RTC EXECUTE";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert_eq!(detail, "RTC EXECUTE");
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn standard_soft_execute_is_state_change() {
    let msg = "sofia/internal/+15550001234@192.0.2.1 Standard SOFT_EXECUTE";
    match classify_message(msg) {
        MessageKind::StateChange { detail } => {
            assert_eq!(detail, "Standard SOFT_EXECUTE");
        }
        other => panic!("expected StateChange, got {other:?}"),
    }
}

#[test]
fn dialplan_recursive_conditions() {
    let msg = "Processing recursive conditions level:1 [default] require-nested=true";
    match classify_message(msg) {
        MessageKind::Dialplan { detail, .. } => {
            assert!(detail.contains("recursive conditions"));
        }
        other => panic!("expected Dialplan, got {other:?}"),
    }
}

#[test]
fn sdp_duplicate_marker() {
    let msg = "Duplicate SDP";
    match classify_message(msg) {
        MessageKind::SdpMarker { direction } => {
            assert_eq!(direction, SdpDirection::Unknown);
        }
        other => panic!("expected SdpMarker, got {other:?}"),
    }
}

#[test]
fn sdp_verto_update_media() {
    match classify_message("updateMedia: Local SDP") {
        MessageKind::SdpMarker { direction } => {
            assert_eq!(direction, SdpDirection::Local);
        }
        other => panic!("expected SdpMarker, got {other:?}"),
    }
}

#[test]
fn receiving_invite_routes_to_sip_invite_with_call_id() {
    let msg = "sofia/internal/1212@host.example:5062 receiving invite from 192.0.2.10:47215 version: 1.10.13-dev git abc 2026-01-01 00:00:00Z 64bit call-id: 00112233-4455-6677-8899-aabbccddeeff";
    match classify_message(msg) {
        MessageKind::SipInvite {
            direction,
            profile,
            call_id,
        } => {
            assert_eq!(direction, SipInviteDirection::Receiving);
            assert_eq!(profile, "internal");
            assert_eq!(
                call_id.as_deref(),
                Some("00112233-4455-6677-8899-aabbccddeeff")
            );
        }
        other => panic!("expected SipInvite, got {other:?}"),
    }
}

#[test]
fn sending_invite_routes_to_sip_invite() {
    let msg = "sofia/internalv6/ngcs_create_conference sending invite call-id: ffeeddcc-bbaa-9988-7766-554433221100";
    match classify_message(msg) {
        MessageKind::SipInvite {
            direction,
            profile,
            call_id,
        } => {
            assert_eq!(direction, SipInviteDirection::Sending);
            assert_eq!(profile, "internalv6");
            assert_eq!(
                call_id.as_deref(),
                Some("ffeeddcc-bbaa-9988-7766-554433221100")
            );
        }
        other => panic!("expected SipInvite, got {other:?}"),
    }
}

#[test]
fn sending_invite_null_call_id_yields_none() {
    let msg = "sofia/telus/15555550100 sending invite call-id: (null)";
    match classify_message(msg) {
        MessageKind::SipInvite {
            direction,
            profile,
            call_id,
        } => {
            assert_eq!(direction, SipInviteDirection::Sending);
            assert_eq!(profile, "telus");
            assert_eq!(call_id, None);
        }
        other => panic!("expected SipInvite, got {other:?}"),
    }
}

#[test]
fn sending_invite_version_only_yields_none() {
    // The DEBUG follow-up from sofia_glue.c:1676 — no call-id field.
    let msg = "sofia/telus/15555550100 sending invite version: 1.10.13-dev git abc 2026-01-01 00:00:00Z 64bit";
    match classify_message(msg) {
        MessageKind::SipInvite {
            direction, call_id, ..
        } => {
            assert_eq!(direction, SipInviteDirection::Sending);
            assert_eq!(call_id, None);
        }
        other => panic!("expected SipInvite, got {other:?}"),
    }
}

#[test]
fn call_id_with_at_host_port_preserved() {
    let msg = "sofia/voipms/15555550101@198.51.100.52 receiving invite from 198.51.100.52:5060 version: 1.10.13-dev git abc 2026-01-01 00:00:00Z 64bit call-id: 00deadbeef00abc123def4567890abcd@198.51.100.52:5060";
    match classify_message(msg) {
        MessageKind::SipInvite { call_id, .. } => {
            assert_eq!(
                call_id.as_deref(),
                Some("00deadbeef00abc123def4567890abcd@198.51.100.52:5060")
            );
        }
        other => panic!("expected SipInvite, got {other:?}"),
    }
}

#[test]
fn non_invite_sofia_lifecycle_still_channel_lifecycle() {
    let msg = "sofia/internal/1212@host.example:5062 receiving refer";
    match classify_message(msg) {
        MessageKind::ChannelLifecycle { .. } => {}
        other => panic!("expected ChannelLifecycle, got {other:?}"),
    }
}

// --- DTMF tests ---

#[test]
fn dtmf_channel_digit() {
    let msg = "RECV DTMF 1:2080";
    match classify_message(msg) {
        MessageKind::Dtmf {
            source,
            digit,
            duration_ms,
        } => {
            assert_eq!(source, DtmfSource::Channel);
            assert_eq!(digit, '1');
            assert_eq!(duration_ms, Some(2080));
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_rtp_digit() {
    let msg = "RTP RECV DTMF 5:1440";
    match classify_message(msg) {
        MessageKind::Dtmf {
            source,
            digit,
            duration_ms,
        } => {
            assert_eq!(source, DtmfSource::Rtp);
            assert_eq!(digit, '5');
            assert_eq!(duration_ms, Some(1440));
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_sip_info() {
    let msg = "INFO DTMF(7)";
    match classify_message(msg) {
        MessageKind::Dtmf {
            source,
            digit,
            duration_ms,
        } => {
            assert_eq!(source, DtmfSource::SipInfo);
            assert_eq!(digit, '7');
            assert_eq!(duration_ms, None);
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_star() {
    let msg = "RECV DTMF *:2080";
    match classify_message(msg) {
        MessageKind::Dtmf { digit, .. } => {
            assert_eq!(digit, '*');
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_hash() {
    let msg = "RECV DTMF #:560";
    match classify_message(msg) {
        MessageKind::Dtmf { digit, .. } => {
            assert_eq!(digit, '#');
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_flash() {
    let msg = "RECV DTMF F:2080";
    match classify_message(msg) {
        MessageKind::Dtmf { digit, .. } => {
            assert_eq!(digit, 'F');
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_letter_a() {
    let msg = "RTP RECV DTMF A:1360";
    match classify_message(msg) {
        MessageKind::Dtmf { digit, .. } => {
            assert_eq!(digit, 'A');
        }
        other => panic!("expected Dtmf, got {other:?}"),
    }
}

#[test]
fn dtmf_invalid_digit_falls_through() {
    let msg = "RECV DTMF X:1000";
    assert_eq!(classify_message(msg), MessageKind::General);
}

#[test]
fn dtmf_malformed_no_colon_falls_through() {
    let msg = "RECV DTMF 1";
    assert_eq!(classify_message(msg), MessageKind::General);
}

#[test]
fn dtmf_malformed_no_duration_falls_through() {
    let msg = "RECV DTMF 1:";
    assert_eq!(classify_message(msg), MessageKind::General);
}

#[test]
fn dtmf_display_with_duration() {
    let kind = MessageKind::Dtmf {
        source: DtmfSource::Channel,
        digit: '5',
        duration_ms: Some(1440),
    };
    assert_eq!(format!("{kind}"), "dtmf(channel:5:1440ms)");
}

#[test]
fn dtmf_display_without_duration() {
    let kind = MessageKind::Dtmf {
        source: DtmfSource::SipInfo,
        digit: '9',
        duration_ms: None,
    };
    assert_eq!(format!("{kind}"), "dtmf(sip-info:9)");
}

#[test]
fn dtmf_label() {
    let kind = MessageKind::Dtmf {
        source: DtmfSource::Rtp,
        digit: '0',
        duration_ms: Some(2000),
    };
    assert_eq!(kind.label(), "dtmf");
}
