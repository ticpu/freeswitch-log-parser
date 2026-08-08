//! Typed codec offers parsed off a negotiation run.

use super::*;

fn codec_block(entry: &LogEntry) -> (&CodecMedia, &Vec<CodecOffer>, &Vec<CodecOffer>) {
    match &entry.block {
        Some(Block::CodecNegotiation {
            media,
            matched,
            near_matched,
            ..
        }) => (media, matched, near_matched),
        other => panic!("expected a codec block, got {other:?}"),
    }
}

#[cfg(feature = "sdp")]
#[test]
fn sdp_body_parses_into_typed_codecs() {
    // Shaped like sofia.c:7634's output, RFC 5737/3849 addresses. The body
    // keeps the CRLF that reaches the log, which the parser must tolerate.
    let lines = vec![
        full_line(UUID1, TS1, "Remote SDP:"),
        format!("{UUID1} v=0\r"),
        format!("{UUID1} o=FreeSWITCH 1 1 IN IP4 192.0.2.10\r"),
        format!("{UUID1} s=FreeSWITCH\r"),
        format!("{UUID1} c=IN IP4 192.0.2.10\r"),
        format!("{UUID1} t=0 0\r"),
        format!("{UUID1} m=audio 9938 RTP/AVP 102 101\r"),
        format!("{UUID1} a=rtpmap:102 opus/48000/2\r"),
        format!("{UUID1} a=rtpmap:101 telephone-event/48000\r"),
        format!("{UUID1} a=ptime:20\r"),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    let codecs = entries[0]
        .block
        .as_ref()
        .expect("sdp block")
        .sdp_codecs()
        .expect("an sdp block yields Some")
        .expect("body parses");

    let audio: Vec<&str> = codecs.audio().map(|c| c.name()).collect();
    assert_eq!(audio, ["opus"], "telephone-event is surfaced separately");
    let payloads: Vec<_> = codecs.non_codec_payloads().collect();
    assert_eq!(payloads.len(), 1);
    assert_eq!(
        payloads[0].kind,
        freeswitch_types::sdp::NonCodecKind::TelephoneEvent
    );
    assert_eq!(payloads[0].payload_type, 101);
    assert_eq!(payloads[0].clock_rate, 48000);
    let opus = codecs.audio().next().unwrap();
    assert_eq!(opus.payload_type(), 102);
    assert_eq!(opus.clock_rate(), 48000);
    assert_eq!(opus.channels(), Some(2));
    assert_eq!(opus.ptime(), Some(20));
}

#[cfg(feature = "sdp")]
#[test]
fn only_sdp_blocks_yield_codecs() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:116:16000:20:0:1]/[opus:116:16000:20:0:1]",
        ),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert!(entries[0].block.as_ref().unwrap().sdp_codecs().is_none());
}

#[test]
fn video_negotiation_has_its_own_arity() {
    let lines = vec![
        full_line(UUID1, TS1, "Video Codec Compare [H263:34]/[H264:97]"),
        full_line(
            UUID1,
            TS1,
            "Video Codec Compare [H263:34] +++ is saved as a match",
        ),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    let (media, matched, _) = codec_block(&entries[0]);
    assert_eq!(*media, CodecMedia::Video);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].name, "H263");
    assert_eq!(matched[0].payload_type, 34);
    assert_eq!(matched[0].clock_rate, None);
    assert!(entries[0].warnings.is_empty(), "{:?}", entries[0].warnings);
}

#[test]
fn audio_and_video_runs_do_not_merge() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[PCMU:0:8000:20:64000:1]",
        ),
        full_line(UUID1, TS1, "Video Codec Compare [H263:34]/[H264:97]"),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert_eq!(entries.len(), 3, "same UUID, different media, two blocks");
    assert_eq!(*codec_block(&entries[0]).0, CodecMedia::Audio);
    assert_eq!(*codec_block(&entries[1]).0, CodecMedia::Video);
}

#[test]
fn near_match_verdicts_are_data_not_warnings() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:116:48000:20:0:1]/[opus:116:48000:20:0:1]",
        ),
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [opus:116:48000:20:0:1] is saved as a near-match",
        ),
        // switch_core_media.c:5575 — seven fields, and the codec is dropped.
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:8000:20:64000:1] was not saved as a near-match. Too many. Ignoring.",
        ),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    let (_, matched, near_matched) = codec_block(&entries[0]);
    assert!(matched.is_empty());
    assert_eq!(near_matched.len(), 1, "the dropped one is not kept");
    assert_eq!(near_matched[0].name, "opus");
    assert!(entries[0].warnings.is_empty(), "{:?}", entries[0].warnings);
}

#[test]
fn a_malformed_codec_token_still_warns() {
    let lines = vec![
        full_line(
            UUID1,
            TS1,
            "Audio Codec Compare [PCMU:0:8000:20:64000:1]/[nope]",
        ),
        full_line(UUID2, TS2, "Next"),
    ];
    let entries: Vec<_> = LogStream::new(lines.into_iter()).collect();
    assert!(
        entries[0]
            .warnings
            .iter()
            .any(|w| matches!(w, ParseWarning::UnrecognizedCodecLine { .. })),
        "got: {:?}",
        entries[0].warnings
    );
}
