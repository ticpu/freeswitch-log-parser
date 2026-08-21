//! Truncated-buffer collisions — splitting a physical line that holds more
//! than one record, and the state a mid-block UUID drop leaves behind.

use super::*;

// BUG 1: When LogStream processes a TrackedChain of multiple file segments,
// last_timestamp from the previous segment bleeds into continuation lines
// at the start of the next segment. This causes entries to get timestamps
// from a completely different file (potentially hours earlier).
//
// Reproduces: f2cb66d4 getting timestamp 23:58:03 from the rotated file
// when freeswitch.log starts with its continuation lines.
#[test]
fn continuation_lines_at_file_boundary_must_not_inherit_previous_timestamp() {
    use crate::TrackedChain;

    let uuid_a = "aaaaaaaa-1111-2222-3333-444444444444";
    let uuid_b = "bbbbbbbb-1111-2222-3333-444444444444";
    let ts_old = "2025-01-15 23:58:03.000000";
    let ts_new = "2025-01-16 08:37:12.000000";

    let seg1: Vec<String> = vec![format!(
        "{uuid_a} {ts_old} 95.00% [DEBUG] test.c:1 Last line in rotated file"
    )];

    // Segment 2 starts with UUID-continuation lines (Format C: UUID + message, no timestamp)
    // followed by a real timestamped line
    let seg2: Vec<String> = vec![
        format!("{uuid_b} CHANNEL_DATA:"),
        format!("{uuid_b} Channel-State: [CS_EXECUTE]"),
        format!("{uuid_b} {ts_new} 95.00% [DEBUG] test.c:1 First timestamped line in new file"),
    ];

    let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = vec![
        ("rotated.log".to_string(), Box::new(seg1.into_iter())),
        ("freeswitch.log".to_string(), Box::new(seg2.into_iter())),
    ];

    let (chain, _) = TrackedChain::new(segments);
    let entries: Vec<_> = LogStream::new(chain).collect();

    let b_entry = entries
        .iter()
        .find(|e| e.uuid.as_deref() == Some(uuid_b))
        .expect("should find entry for uuid_b");

    // The CHANNEL_DATA entry for uuid_b must NOT have the timestamp from
    // segment 1 — it should either have the new file's first real timestamp
    // or be empty (indicating unknown).
    assert_ne!(
        b_entry.timestamp, ts_old,
        "continuation lines in a new file segment inherited timestamp \
         '{ts_old}' from the previous segment — timestamps must not bleed \
         across file boundaries"
    );
}

#[test]
fn no_split_on_short_lines() {
    // Lines within the payload limit should never be split,
    // even if they happen to contain a UUID-like pattern.
    let line = format!("variable_call_uuid: [{UUID2}]");
    let lines = vec![full_line(UUID1, TS1, "CHANNEL_DATA:"), line];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(stream.stats().lines_split, 0);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_splits_system_lines() {
    let line = format!(
        "{TS1} 98.03% [INFO] mod_event_socket.c:1752 Event Socket Command from ::1:42864: api sofia jsonstatus{TS2} 97.93% [INFO] mod_event_socket.c:1752 Event Socket Command from ::1:42898: api fsctl pause_check"
    );
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].message,
        "Event Socket Command from ::1:42864: api sofia jsonstatus"
    );
    assert_eq!(
        entries[1].message,
        "Event Socket Command from ::1:42898: api fsctl pause_check"
    );
    assert_eq!(stream.stats().lines_split, 1);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_splits_three_entries() {
    let ts3 = "2025-01-15 10:30:47.345678";
    let line = format!(
        "{TS1} 95.00% [INFO] mod.c:1 first{TS2} 96.00% [INFO] mod.c:1 second{ts3} 97.00% [INFO] mod.c:1 third"
    );
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].message, "first");
    assert_eq!(entries[1].message, "second");
    assert_eq!(entries[2].message, "third");
    assert_eq!(stream.stats().lines_split, 2);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_oversize_write_contention() {
    // Production case: write contention concatenates dozens of short
    // Event Socket entries into one physical line. Timestamps appear at
    // offsets ~150 bytes apart, none of them on a write boundary — these
    // are verbatim-path records, which answer to no budget. All must
    // still split out.
    let entry = |n: usize| {
        format!(
            "{TS1} 98.77% [INFO] mod_event_socket.c:1754 Event Socket Command from ::1:42864: api db select/ngcs_sip_call_id/entry-{n:04}"
        )
    };
    let count: u64 = 20;
    let line: String = (0..count).map(|n| entry(n as usize)).collect();
    assert!(
        line.len() > super::WRITE_LIMIT,
        "the fixture should outrun a write's whole budget, got {}",
        line.len()
    );

    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len() as u64, count);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(
            e.message,
            format!(
                "Event Socket Command from ::1:42864: api db select/ngcs_sip_call_id/entry-{i:04}"
            )
        );
    }
    assert_eq!(stream.stats().lines_split, count - 1);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_with_uuid_prefix() {
    // System line collides with Full line (UUID + timestamp)
    let line =
        format!("{TS1} 95.00% [INFO] mod.c:1 first{UUID1} {TS2} 96.00% [DEBUG] sofia.c:100 second");
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].message, "first");
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[1].message, "second");
    assert_eq!(stream.stats().lines_split, 1);
    assert_accounting(&stream);
}

// Headers from older/eSInet FS builds omit the idle percentage:
// "TIMESTAMP [LEVEL] source:line" directly. Collisions still split.

#[test]
fn timestamp_collision_no_idle_pct_system() {
    let line = format!(
        "{TS1} [WARNING] sofia_presence.c:4546 Session does not exist, aborting REFER.{TS2} [WARNING] sofia_presence.c:4546 Session does not exist, aborting REFER."
    );
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].message,
        "Session does not exist, aborting REFER."
    );
    assert_eq!(
        entries[1].message,
        "Session does not exist, aborting REFER."
    );
    assert_eq!(stream.stats().lines_split, 1);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_no_idle_pct_uuid_suffix() {
    // Fixture shape: no-idle System WARNING whose un-terminated message
    // runs directly (no space) into a Full NOTICE line (UUID + timestamp).
    let line = format!(
        "{TS1} [WARNING] sofia_presence.c:4546 Session does not exist, aborting REFER.{UUID1} {TS2} [NOTICE] sofia.c:1114 Hangup sofia/internal/sos@192.0.2.10:5080 [CS_EXCHANGE_MEDIA] [NORMAL_CLEARING]"
    );
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].uuid, None);
    assert_eq!(
        entries[0].message,
        "Session does not exist, aborting REFER."
    );
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[1].level, Some(LogLevel::Notice));
    assert_eq!(
        entries[1].message,
        "Hangup sofia/internal/sos@192.0.2.10:5080 [CS_EXCHANGE_MEDIA] [NORMAL_CLEARING]"
    );
    assert_eq!(stream.stats().lines_split, 1);
    assert_accounting(&stream);
}

#[test]
fn timestamp_collision_no_idle_pct_run_on() {
    // Dozens of un-terminated REFER warnings pile onto one physical line.
    let count: u64 = 15;
    let line: String = (0..count)
        .map(|n| {
            format!(
                "2024-04-02 10:31:{:02}.945614 [WARNING] sofia_presence.c:4546 Session does not exist, aborting REFER.",
                n + 10
            )
        })
        .collect();
    let mut stream = LogStream::new(std::iter::once(line));
    let entries: Vec<_> = stream.by_ref().collect();
    assert_eq!(entries.len() as u64, count);
    for e in &entries {
        assert_eq!(e.message, "Session does not exist, aborting REFER.");
    }
    assert_eq!(stream.stats().lines_split, count - 1);
    assert_accounting(&stream);
}

/// The cut lands mid-value and the collided suffix is the *next* variable, so
/// reassembly must stop rather than join it — a join loses that variable.
#[test]
fn a_cut_value_does_not_swallow_the_next_variable() {
    let collision_line = cut_write(
        &format!("{UUID1} variable_long_xml: ["),
        &format!("{UUID1} variable_direction: [inbound]"),
    );

    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        collision_line,
        full_line(UUID1, TS2, "Next log entry"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();

    match entries[0].block.as_ref().expect("should have block") {
        Block::ChannelData { variables, .. } => {
            assert_eq!(variables.len(), 2);
            assert_eq!(variables[0].0, "variable_long_xml");
            assert!(
                !variables[0].1.contains("variable_direction"),
                "the cut value swallowed the next variable"
            );
            assert_eq!(
                variables[1],
                ("variable_direction".to_string(), "inbound".to_string())
            );
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
    assert!(entries[0]
        .warnings
        .contains(&ParseWarning::TruncatedVariable {
            name: "variable_long_xml".to_string()
        }));
}

/// A value the buffer cut has to be recognisable from the span a redactor is
/// about to rewrite, without matching the warning list by variable name.
#[test]
fn a_cut_value_span_reports_truncated() {
    use crate::fields::{FieldKind, FieldLocation};

    let head = format!("{UUID1} variable_sip_h_X-Trace: [<http://192.0.2.9/t?id=");
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Caller-Caller-ID-Number: [15555550100]"),
        cut_write(&head, &format!("{UUID1} variable_direction: [inbound]")),
        full_line(UUID1, TS2, "Next log entry"),
    ];
    let entry = LogStream::new(lines.into_iter()).next().expect("entry");

    assert_eq!(entry.cut_texts, vec![FieldLocation::Attached(1)]);

    let fields = entry.fields();
    let cut = fields
        .iter()
        .find(|f| f.at == FieldLocation::Attached(1) && f.kind == FieldKind::VariableValue)
        .expect("the cut value is spanned");
    assert!(entry.is_truncated(cut));

    // Every other span survived whole — including the session UUID sharing the
    // cut line, which stops long before the cut.
    for f in fields.iter().filter(|f| *f != cut) {
        assert!(!entry.is_truncated(f), "{f:?} reported truncated");
    }
}

/// Two variables cut in one entry — the case a name-keyed correlation cannot
/// separate, since both warnings and both spans belong to the same entry.
#[test]
fn each_cut_line_of_an_entry_answers_for_itself() {
    use crate::fields::{FieldKind, FieldLocation};

    let cut_line = |name: &str| {
        cut_write(
            &format!("{UUID1} variable_{name}: ["),
            &format!("{UUID1} variable_direction: [inbound]"),
        )
    };
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        cut_line("sip_h_X-First"),
        cut_line("sip_h_X-Second"),
        full_line(UUID1, TS2, "Next log entry"),
    ];
    let entry = LogStream::new(lines.into_iter()).next().expect("entry");

    assert_eq!(
        entry.cut_texts,
        vec![FieldLocation::Attached(0), FieldLocation::Attached(2)]
    );

    let truncated: Vec<_> = entry
        .fields()
        .into_iter()
        .filter(|f| entry.is_truncated(f))
        .collect();
    assert_eq!(truncated.len(), 2);
    for f in &truncated {
        assert_eq!(f.kind, FieldKind::VariableValue);
    }
}

/// The cut chunk carries another session's UUID, so it opens an entry instead of
/// joining one and the cut lands on the message rather than an attached line.
#[test]
fn a_cut_primary_line_reports_its_message_truncated() {
    use crate::fields::{FieldKind, FieldLocation};

    let head = format!("{UUID2} variable_sip_h_X-Trace: [<http://192.0.2.9/t?id=");
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Caller-Caller-ID-Number: [15555550100]"),
        cut_write(&head, &format!("{UUID2} variable_direction: [inbound]")),
        full_line(UUID1, TS2, "Next log entry"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();

    let cut_entry = &entries[1];
    assert_eq!(cut_entry.uuid.as_deref(), Some(UUID2));
    assert_eq!(cut_entry.cut_texts, vec![FieldLocation::Message]);

    let value = cut_entry
        .fields()
        .into_iter()
        .find(|f| f.at == FieldLocation::Message && f.kind == FieldKind::VariableValue)
        .expect("the cut value is spanned");
    assert!(cut_entry.is_truncated(&value));
    assert!(entries[0].cut_texts.is_empty());
}

#[test]
fn truncated_collision_in_channel_data_variable() {
    // A CHANNEL_DATA block where a variable value exceeds the 2048-byte
    // mod_logfile buffer, causing a truncated collision (Format E).
    // The variable_long_xml value opens with [ but the buffer truncation
    // causes a UUID+EXECUTE to collide on the same physical line before
    // the closing ].
    let collision_line = cut_write(
        &format!("{UUID1} variable_long_xml: ["),
        &format!("{UUID1} EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(foo=bar)"),
    );

    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID1} variable_direction: [inbound]"),
        collision_line,
        full_line(UUID1, TS2, "Next log entry"),
    ];

    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();

    // Entry 0: CHANNEL_DATA with the variables
    assert_eq!(entries[0].message, "CHANNEL_DATA:");
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 1, "should have Channel-Name field");
            assert_eq!(fields[0].0, "Channel-Name");
            assert_eq!(
                variables.len(),
                2,
                "should have direction + unclosed long_xml"
            );
            assert_eq!(variables[0].0, "variable_direction");
            assert_eq!(variables[0].1, "inbound");
            assert_eq!(variables[1].0, "variable_long_xml");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::OversizeLine { .. })),
        "expected buffer overflow warning, got: {:?}",
        entries[0].warnings
    );
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::UnclosedVariable { .. })),
        "expected unclosed variable warning, got: {:?}",
        entries[0].warnings
    );

    // Entry 1: the split EXECUTE line
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
    assert!(
        entries[1].message.starts_with("EXECUTE "),
        "split entry should be EXECUTE, got: {}",
        entries[1].message
    );

    // Entry 2: the next full log line
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2].message, "Next log entry");
}

#[test]
fn channel_data_uuid_drops_mid_block() {
    // Production scenario: mod_logfile stops prepending the UUID mid-way
    // through a CHANNEL_DATA dump. The first few variable lines carry the
    // UUID prefix (UuidContinuation), then the remaining lines arrive as
    // bare continuations. All should be accumulated into the same block.
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} variable_max_forwards: [69]"),
        format!("{UUID1} variable_presence_id: [1251@[2001:db8::10]]"),
        format!("{UUID1} variable_sip_h_X-Custom-ID: [c4da84eb-88a7-40b2-b90d-e5bc2a0f634e]"),
        // UUID drops — bare continuations for the rest
        "variable_sip_h_X-Call-Info: [<urn:test:callid:20260316>;purpose=emergency-CallId]"
            .to_string(),
        "variable_ep_codec_string: [mod_opus.opus@48000h@20i@2c]".to_string(),
        "variable_remote_media_ip: [2001:db8::10]".to_string(),
        "variable_remote_media_port: [9952]".to_string(),
        "variable_rtp_use_codec_name: [opus]".to_string(),
        full_line(UUID1, TS2, "Next entry"),
    ];

    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].message, "CHANNEL_DATA:");
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 0);
            assert_eq!(variables.len(), 8);
            // UUID-prefixed variables
            assert_eq!(variables[0].0, "variable_max_forwards");
            assert_eq!(variables[0].1, "69");
            assert_eq!(variables[1].0, "variable_presence_id");
            assert_eq!(variables[1].1, "1251@[2001:db8::10]");
            assert_eq!(variables[2].0, "variable_sip_h_X-Custom-ID");
            // Bare variables (UUID dropped)
            assert_eq!(variables[3].0, "variable_sip_h_X-Call-Info");
            assert!(variables[3].1.contains("emergency-CallId"));
            assert_eq!(variables[4].0, "variable_ep_codec_string");
            assert_eq!(variables[7].0, "variable_rtp_use_codec_name");
            assert_eq!(variables[7].1, "opus");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
    assert_eq!(entries[0].attached.len(), 8);
    assert_eq!(entries[1].message, "Next entry");
    assert_accounting(&stream);
}

#[test]
fn channel_data_uuid_drops_with_multiline_variable() {
    // UUID drops mid-block AND a multi-line variable (SDP body embedded
    // in variable_switch_r_sdp) spans many bare continuation lines.
    // The \r characters are real — SDP uses \r\n per RFC 4566, and
    // mod_logfile splits on \n leaving \r in the content.
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} variable_max_forwards: [69]"),
        format!("{UUID1} variable_sip_h_X-Custom-ID: [c4da84eb-88a7-40b2-b90d-e5bc2a0f634e]"),
        // UUID drops
        "variable_switch_r_sdp: [v=0\r".to_string(),
        "o=FreeSWITCH 1773663549 1773663550 IN IP6 2001:db8::10\r".to_string(),
        "s=FreeSWITCH\r".to_string(),
        "c=IN IP6 2001:db8::10\r".to_string(),
        "t=0 0\r".to_string(),
        "m=audio 9952 RTP/AVP 102 101 13\r".to_string(),
        "a=rtpmap:102 opus/48000/2\r".to_string(),
        "a=ptime:20\r".to_string(),
        "]".to_string(),
        "variable_ep_codec_string: [mod_opus.opus@48000h@20i@2c]".to_string(),
        "variable_direction: [inbound]".to_string(),
        full_line(UUID1, TS2, "Next entry"),
    ];

    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    assert_eq!(entries.len(), 2);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 0);
            assert_eq!(variables.len(), 5);
            assert_eq!(variables[0].0, "variable_max_forwards");
            assert_eq!(variables[1].0, "variable_sip_h_X-Custom-ID");
            // Multi-line SDP variable reassembled from bare continuations
            assert_eq!(variables[2].0, "variable_switch_r_sdp");
            let sdp = &variables[2].1;
            assert!(
                sdp.starts_with("v=0\n"),
                "each line's CR is trimmed before reassembly, got: {sdp:?}"
            );
            assert!(sdp.contains("m=audio 9952 RTP/AVP 102 101 13\n"));
            assert!(sdp.contains("a=ptime:20\n"));
            assert!(!sdp.ends_with(']'), "closing bracket should be stripped");
            // Post-SDP bare variables
            assert_eq!(variables[3].0, "variable_ep_codec_string");
            assert_eq!(variables[4].0, "variable_direction");
            assert_eq!(variables[4].1, "inbound");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }
    // 2 UUID continuations + 9 SDP lines (open + 7 content + close) + 2 bare = 13
    assert_eq!(entries[0].attached.len(), 13);
    assert_accounting(&stream);
}

#[test]
fn channel_data_bare_variable_collision_with_execute() {
    // Production collision: bare variable_call_uuid line on same physical
    // line as a UUID EXECUTE. The UUID appears at byte 20 ("variable_call_uuid: "
    // is 20 chars), within find_uuid_in's 50-byte scan window, so Layer 1
    // classifies it as Truncated — extracting the UUID and EXECUTE message.
    // The CHANNEL_DATA block loses variable_call_uuid (eaten as truncation
    // prefix) but correctly recovers the EXECUTE as a separate entry.
    let collision = format!(
        "variable_call_uuid: {UUID1} EXECUTE [depth=0] \
         sofia/internal-v6/1251@[2001:db8::10] export(nolocal:test_var=value)"
    );

    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} variable_max_forwards: [69]"),
        // UUID drops — bare continuations
        "variable_DP_MATCH: [ARRAY::create_conference|:create_conference]".to_string(),
        collision,
        // Full line resumes normal logging
        full_line(
            UUID1,
            TS2,
            "EXPORT (export_vars) (REMOTE ONLY) [test_var]=[value]",
        ),
    ];

    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    // Entry 0: CHANNEL_DATA — variable_call_uuid lost to truncation prefix
    assert_eq!(entries.len(), 3);
    let block = entries[0].block.as_ref().expect("should have block");
    match block {
        Block::ChannelData { fields, variables } => {
            assert_eq!(fields.len(), 0);
            assert_eq!(variables.len(), 2);
            assert_eq!(variables[0].0, "variable_max_forwards");
            assert_eq!(variables[1].0, "variable_DP_MATCH");
        }
        other => panic!("expected ChannelData block, got {other:?}"),
    }

    // Entry 1: EXECUTE recovered from the Truncated classification
    assert_eq!(entries[1].uuid.as_deref(), Some(UUID1));
    assert_eq!(entries[1].kind, LineKind::Truncated);
    assert!(
        entries[1].message.starts_with("EXECUTE "),
        "truncated line should yield EXECUTE, got: {}",
        entries[1].message
    );

    // Entry 2: normal EXPORT line
    assert_eq!(entries[2].message_kind.label(), "variable");
    assert_accounting(&stream);
}

/// A cut line that starts its own entry belongs to that entry, not to whichever
/// entry happened to be open when it arrived.
#[test]
fn a_cut_primary_line_warns_on_its_own_entry() {
    // Nothing recognisable after the boundary, so the write is cut with its
    // remainder lost and the line stays whole.
    let lines = vec![
        full_line(UUID1, TS1, "an ordinary earlier entry"),
        cut_write(&full_line(UUID2, TS2, "Ring-Ready "), ""),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();

    assert_eq!(entries.len(), 2);
    assert!(
        entries[0].warnings.is_empty(),
        "the earlier entry did not produce the oversize line, got: {:?}",
        entries[0].warnings
    );
    assert!(
        entries[1]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::OversizeLine { .. })),
        "expected the oversize warning on the entry the line opened, got: {:?}",
        entries[1].warnings
    );
}

/// `mod_logfile` formats through its fixed buffer only when it prepends a
/// session UUID. A record written verbatim is intact however long it runs, so
/// its length is not evidence of anything.
#[test]
fn a_verbatim_line_past_the_buffer_is_not_a_cut() {
    let body = "x".repeat(11_000);
    let lines = vec![format!(
        "{TS1} 95.97% [DEBUG] mod_oreka.c:121 Oreka SIP Packet {body}"
    )];
    let mut stream = LogStream::new(lines.into_iter());
    let entries: Vec<_> = stream.by_ref().collect();

    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].warnings.is_empty(),
        "a verbatim record has no write buffer to overrun, got: {:?}",
        entries[0].warnings
    );
    assert_eq!(stream.stats().lines_split, 0);
    assert_accounting(&stream);
}

/// The longest line the prepend path can write intact, one byte short of the
/// buffer's reach. Anything at or past `WRITE_LIMIT` lost its newline.
#[test]
fn a_prepended_line_at_the_intact_maximum_is_not_a_cut() {
    let overhead = full_line(UUID1, TS1, "").len();
    let line = full_line(UUID1, TS1, &"x".repeat(WRITE_LIMIT - 1 - overhead));
    assert_eq!(line.len(), WRITE_LIMIT - 1);

    let entries: Vec<_> = LogStream::new(vec![line].into_iter()).collect();
    assert!(
        entries[0].warnings.is_empty(),
        "an intact record must not be reported as cut, got: {:?}",
        entries[0].warnings
    );
}

/// One byte further the newline no longer fits, which is the cut itself.
#[test]
fn a_prepended_line_filling_the_buffer_is_a_cut() {
    let overhead = full_line(UUID1, TS1, "").len();
    let line = full_line(UUID1, TS1, &"x".repeat(WRITE_LIMIT - overhead));
    assert_eq!(line.len(), WRITE_LIMIT);

    let entries: Vec<_> = LogStream::new(vec![line].into_iter()).collect();
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::OversizeLine { bytes } if *bytes == WRITE_LIMIT)),
        "expected the cut reported at its physical length, got: {:?}",
        entries[0].warnings
    );
}
