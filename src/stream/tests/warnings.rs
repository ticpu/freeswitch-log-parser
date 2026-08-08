//! [`ParseWarning`] kinds, and the excerpt truncation that must not split a
//! multi-byte character.

use super::*;

#[test]
fn warning_on_unclosed_multiline_variable() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        "variable_switch_r_sdp: [v=0".to_string(),
        "o=- 1234 5678 IN IP4 192.0.2.1".to_string(),
        full_line(UUID2, TS2, "Next entry"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 2);
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::UnclosedVariable { .. })),
        "expected unclosed variable warning, got: {:?}",
        entries[0].warnings
    );
}

#[test]
fn warning_on_unparseable_channel_data_line() {
    let lines = vec![
        full_line(UUID1, TS1, "CHANNEL_DATA:"),
        format!("{UUID1} Channel-Name: [sofia/internal/+15550001234@192.0.2.1]"),
        format!("{UUID1} this is not a valid field line"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::UnparseableChannelData { .. })),
        "expected unparseable warning, got: {:?}",
        entries[0].warnings
    );
}

#[test]
fn warning_on_unexpected_codec_continuation() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
        ),
        format!("{UUID1} some unexpected continuation line"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::UnexpectedCodecContinuation { .. })),
        "expected codec warning, got: {:?}",
        entries[0].warnings
    );
}

// --- Multi-byte content straddling the 80-byte warning truncation ---

#[test]
fn multibyte_at_warning_truncation_unrecognized_codec() {
    // 'é' occupies bytes 79-80 of the message: truncating at 80 splits it.
    let msg = format!(
        "Audio Codec Compare {}é tail beyond eighty bytes",
        "x".repeat(59)
    );
    assert!(!msg.is_char_boundary(80));
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
        ),
        full_line(UUID1, TS1, &msg),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let line = entries[0]
        .warnings
        .iter()
        .find_map(|w| match w {
            ParseWarning::UnrecognizedCodecLine { line, .. } => Some(line),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected codec warning, got: {:?}", entries[0].warnings));
    assert!(
        line.len() < WARNING_EXCERPT_LEN,
        "expected char-boundary back-off below {WARNING_EXCERPT_LEN} bytes, got {} bytes: {line:?}",
        line.len()
    );
    assert!(
        !line.contains("tail beyond eighty bytes"),
        "expected the tail to be truncated away, got: {line:?}"
    );
}

#[test]
fn multibyte_at_warning_truncation_channel_data() {
    let bare = format!(
        "{}é tail beyond eighty bytes with no field separator",
        "x".repeat(79)
    );
    assert!(!bare.is_char_boundary(80));
    let lines = vec![full_line(UUID1, TS1, "CHANNEL_DATA:"), bare];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let line = entries[0]
        .warnings
        .iter()
        .find_map(|w| match w {
            ParseWarning::UnparseableChannelData { line } => Some(line),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "expected unparseable warning, got: {:?}",
                entries[0].warnings
            )
        });
    assert!(
        line.len() < WARNING_EXCERPT_LEN,
        "expected char-boundary back-off below {WARNING_EXCERPT_LEN} bytes, got {} bytes: {line:?}",
        line.len()
    );
    assert!(
        !line.contains("tail beyond eighty bytes"),
        "expected the tail to be truncated away, got: {line:?}"
    );
}

#[test]
fn multibyte_at_warning_truncation_codec_continuation() {
    let cont = format!("{}é tail beyond eighty bytes", "x".repeat(79));
    assert!(!cont.is_char_boundary(80));
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
        ),
        format!("{UUID1} {cont}"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 1);
    let line = entries[0]
        .warnings
        .iter()
        .find_map(|w| match w {
            ParseWarning::UnexpectedCodecContinuation { line } => Some(line),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "expected codec continuation warning, got: {:?}",
                entries[0].warnings
            )
        });
    assert!(
        line.len() < WARNING_EXCERPT_LEN,
        "expected char-boundary back-off below {WARNING_EXCERPT_LEN} bytes, got {} bytes: {line:?}",
        line.len()
    );
    assert!(
        !line.contains("tail beyond eighty bytes"),
        "expected the tail to be truncated away, got: {line:?}"
    );
}
