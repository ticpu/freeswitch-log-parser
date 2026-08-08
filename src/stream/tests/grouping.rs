//! Continuation grouping — UUID and timestamp inheritance, and the
//! boundaries at which a buffered entry is yielded.

use super::*;

// --- Existing behavior tests (preserved) ---

#[test]
fn inherits_uuid_for_bare_continuation() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        "variable_foo: [bar]".to_string(),
        "variable_baz: [qux]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[0].attached.len(), 2);
    assert_eq!(entries[0].attached.get(0), Some("variable_foo: [bar]"));
    assert_eq!(entries[0].attached.get(1), Some("variable_baz: [qux]"));
}

#[test]
fn inherits_timestamp_for_uuid_continuation() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("{UUID2} Channel-State: [CS_EXECUTE]"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].timestamp, TS1);
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID2));
    assert_eq!(entries[1].timestamp, TS1);
}

#[test]
fn new_full_line_yields_previous() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        full_line(UUID2, TS2, "Second"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let first = stream.next().unwrap();
    assert_eq!(first.uuid.as_deref(), Some(UUID1));
    assert_eq!(first.message, "First");
    let second = stream.next().unwrap();
    assert_eq!(second.uuid.as_deref(), Some(UUID2));
    assert_eq!(second.message, "Second");
    assert!(stream.next().is_none());
}

#[test]
fn channel_data_collected_as_attached() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID1} Unique-ID: [{UUID1}]"),
        "variable_sip_call_id: [test123@192.0.2.1]".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].message, "CHANNEL_DATA:");
    assert_eq!(entries[0].attached.len(), 3);
}

#[test]
fn sdp_body_collected_as_attached() {
    let lines = vec![
        full_line(UUID1, TS1, "Local SDP:"),
        "v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        "s=-".to_string(),
        "c=IN IP4 192.0.2.1".to_string(),
        "m=audio 10000 RTP/AVP 0".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].attached.len(), 5);
}

#[test]
fn truncated_starts_new_entry() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("varia{UUID2} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 set(x=y)"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let first = stream.next().unwrap();
    assert_eq!(first.uuid.as_deref(), Some(UUID1));
    assert_eq!(first.message, "First");
    let second = stream.next().unwrap();
    assert_eq!(second.uuid.as_deref(), Some(UUID2));
    assert_eq!(second.kind, LineKind::Truncated);
}

#[test]
fn empty_lines_in_attached() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        String::new(),
        "continuation".to_string(),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].attached.len(), 2);
    assert_eq!(entries[0].attached.get(0), Some(""));
    assert_eq!(entries[0].attached.get(1), Some("continuation"));
}

#[test]
fn system_line_no_uuid() {
    let lines = vec![format!(
        "{TS1} 95.97% [INFO] mod_event_socket.c:1772 Event Socket command"
    )];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].uuid, None);
    assert_eq!(entries[0].kind, LineKind::System);
}

#[test]
fn final_entry_on_exhaustion() {
    let lines = vec![full_line(UUID1, TS1, "Only entry")];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].message, "Only entry");
}

#[test]
fn consecutive_full_lines() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        full_line(UUID1, TS2, "Second"),
        full_line(UUID2, TS1, "Third"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 3);
    for entry in &entries {
        assert!(entry.attached.is_empty());
    }
}

#[test]
fn execute_after_channel_data_same_uuid() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        format!("{UUID1} variable_sip_call_id: [test@192.0.2.1]"),
        "variable_foo: [bar]".to_string(),
        String::new(),
        String::new(),
        format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)"),
        full_line(UUID1, TS2, "EXPORT (export_vars) [originate_timeout]=[3600]"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].message, "CHANNEL_DATA:");
    assert_eq!(entries[0].attached.len(), 5);
    assert_eq!(
        entries[1].message,
        "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)"
    );
    assert_eq!(entries[1].kind, LineKind::UuidContinuation);
    assert_eq!(
        entries[2].message,
        "EXPORT (export_vars) [originate_timeout]=[3600]"
    );
}

#[test]
fn execute_between_full_lines_same_uuid() {
    let lines = vec![
        full_line(UUID1, TS1, "CoreSession::setVariable(X-Example-City, TESTVILLE)"),
        format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/ng_{UUID1}/city/TESTVILLE)"),
        full_line(UUID1, TS2, "CoreSession::setVariable(X-Example-Region, TSV)"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries[0].message,
        "CoreSession::setVariable(X-Example-City, TESTVILLE)"
    );
    assert!(entries[0].attached.is_empty());
    assert!(entries[1].message.starts_with("EXECUTE "));
    assert_eq!(entries[1].kind, LineKind::UuidContinuation);
    assert_eq!(
        entries[2].message,
        "CoreSession::setVariable(X-Example-Region, TSV)"
    );
}

#[test]
fn multiple_execute_between_full_lines() {
    let lines = vec![
        full_line(UUID1, TS1, "CoreSession::setVariable(ngcs_call_id, urn:emergency:uid:callid:test)"),
        format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/ng_{UUID1}/call_id/urn:emergency:uid:callid:test)"),
        format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 db(insert/callid_codecs/urn:emergency:uid:callid:test/PCMU@8000h)"),
        full_line(UUID1, TS2, "CoreSession::setVariable(ngcs_short_call_id, test)"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 4);
    assert!(entries[0].attached.is_empty());
    assert!(entries[1].message.contains("call_id"));
    assert!(entries[2].message.contains("callid_codecs"));
    assert_eq!(
        entries[3].message,
        "CoreSession::setVariable(ngcs_short_call_id, test)"
    );
}

#[test]
fn uuid_continuation_different_uuid_yields() {
    let lines = vec![
        full_line(UUID1, TS1, "First"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
        format!("{UUID2} Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]"),
    ];
    let mut stream = LogStream::new(lines.into_iter());
    let first = stream.next().unwrap();
    assert_eq!(first.uuid.as_deref(), Some(UUID1));
    assert_eq!(first.attached.len(), 1);
    let second = stream.next().unwrap();
    assert_eq!(second.uuid.as_deref(), Some(UUID2));
    assert_eq!(
        second.message,
        "Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public]"
    );
}

#[test]
fn system_line_uuid_continuation_not_absorbed() {
    // After the bug fix, a UUID continuation should NOT be absorbed
    // by a pending system line (empty UUID).
    let lines = vec![
        format!("{TS1} 95.97% [INFO] mod_event_socket.c:1772 Event Socket command"),
        format!("{UUID1} Channel-State: [CS_EXECUTE]"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(
        entries.len(),
        2,
        "UUID continuation should not be absorbed by system entry"
    );
    assert_eq!(entries[0].uuid, None);
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
}

#[test]
fn system_line_with_embedded_uuid_gets_entry_uuid() {
    // System lines (Format B) where switch_cpp.cpp logs the UUID at the
    // start of the message body should produce entries with the correct UUID.
    let lines = vec![
        format!("{TS1} 95.97% [DEBUG] switch_cpp.cpp:1466 {UUID1} DAA-LOG WaveManager originate"),
        format!(
            "{TS1} 95.97% [WARNING] switch_cpp.cpp:1466 {UUID1} DAA-LOG Failed to create session"
        ),
        full_line(UUID1, TS2, "State Change CS_EXECUTE -> CS_HIBERNATE"),
    ];

    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    assert_eq!(entries.len(), 3);
    // Both System lines should have the UUID extracted from the message
    assert_eq!(entries[0].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[0].kind, LineKind::System);
    assert_eq!(entries[0].message, "DAA-LOG WaveManager originate");

    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[1].kind, LineKind::System);
    assert_eq!(entries[1].message, "DAA-LOG Failed to create session");

    // Full line still works normally
    assert_eq!(entries[2].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[2].kind, LineKind::Full);
    assert_accounting(&stream);
}
