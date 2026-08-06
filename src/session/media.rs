//! Per-session codec outcome.
//!
//! FreeSWITCH logs the read side of the audio engine and nothing about the
//! write side at DEBUG, so only the read direction is modelled — a `write_codec`
//! field would be a guess.

use crate::codec::{CodecMedia, CodecOffer};
use crate::message::MessageKind;
use crate::stream::{Block, LogEntry};

/// What one media type's negotiation produced for a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaCodecs {
    /// Last codec FreeSWITCH saved as a match.
    pub negotiated: Option<CodecOffer>,
    /// Distinct codecs the far end offered, in first-seen order.
    pub offered: Vec<CodecOffer>,
}

impl MediaCodecs {
    fn offer(&mut self, codec: &CodecOffer) {
        if !self.offered.contains(codec) {
            self.offered.push(codec.clone());
        }
    }
}

/// Codecs a session negotiated, by media type and by direction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMedia {
    pub audio: MediaCodecs,
    pub video: MediaCodecs,
    /// `Original read codec set to <name>:<pt>` — `switch_core_codec.c:132`.
    /// Carries no rate or ptime, so those stay `None`.
    pub read_codec: Option<CodecOffer>,
    /// `Set Codec <chan> <name>/<rate> <ptime> ms …` — `switch_core_media.c:3739`,
    /// reporting the audio engine's read implementation. No payload type.
    pub active_audio: Option<CodecOffer>,
}

impl SessionMedia {
    pub(crate) fn update_from_entry(&mut self, entry: &LogEntry) {
        if let Some(Block::CodecNegotiation {
            media,
            comparisons,
            matched,
            ..
        }) = &entry.block
        {
            let side = match media {
                CodecMedia::Video => &mut self.video,
                _ => &mut self.audio,
            };
            for (offered, _local) in comparisons {
                side.offer(offered);
            }
            if let Some(last) = matched.last() {
                side.negotiated = Some(last.clone());
            }
        }

        // Both live under MessageKind::Media, which keeps the whole message.
        if let MessageKind::Media { detail } = &entry.message_kind {
            if let Some(codec) = parse_original_read_codec(detail) {
                self.read_codec = Some(codec);
            }
            if let Some(codec) = parse_set_codec(detail) {
                self.active_audio = Some(codec);
            }
        }
    }
}

/// `<chan> Original read codec set to <name>:<payload>`
fn parse_original_read_codec(msg: &str) -> Option<CodecOffer> {
    let rest = msg.split_once("Original read codec set to ")?.1;
    let (name, payload) = rest.trim().split_once(':')?;
    if name.is_empty() {
        return None;
    }
    Some(CodecOffer {
        name: name.to_string(),
        payload_type: payload.parse().ok()?,
        clock_rate: None,
        ptime: None,
        bitrate: None,
        channels: None,
    })
}

/// `Set Codec <chan> <name>/<rate> <ptime> ms <samples> samples <bits> bits <channels> channels`
fn parse_set_codec(msg: &str) -> Option<CodecOffer> {
    let rest = msg.strip_prefix("Set Codec ")?;
    let (_channel, rest) = rest.split_once(' ')?;
    let mut fields = rest.split(' ');
    let (name, rate) = fields.next()?.split_once('/')?;
    if name.is_empty() {
        return None;
    }
    let ptime = fields.next()?.parse().ok()?;
    // The payload type is absent from this line; 0 would claim PCMU.
    let mut codec = CodecOffer {
        name: name.to_string(),
        payload_type: 0,
        clock_rate: rate.parse().ok(),
        ptime: Some(ptime),
        bitrate: None,
        channels: None,
    };
    let tail: Vec<&str> = fields.collect();
    for pair in tail.windows(2) {
        match pair {
            [value, "bits"] => codec.bitrate = value.parse().ok(),
            [value, "channels"] => codec.channels = value.parse().ok(),
            _ => {}
        }
    }
    Some(codec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_read_codec_carries_only_name_and_payload() {
        let c =
            parse_original_read_codec("sofia/softphone/1213 Original read codec set to opus:116")
                .expect("parsed");
        assert_eq!(c.name, "opus");
        assert_eq!(c.payload_type, 116);
        assert_eq!(c.clock_rate, None);
        assert_eq!(c.ptime, None);
    }

    #[test]
    fn set_codec_carries_rate_ptime_bitrate_and_channels() {
        let c = parse_set_codec(
            "Set Codec sofia/softphone/1213 opus/16000 20 ms 320 samples 0 bits 1 channels",
        )
        .expect("parsed");
        assert_eq!(c.name, "opus");
        assert_eq!(c.clock_rate, Some(16000));
        assert_eq!(c.ptime, Some(20));
        assert_eq!(c.bitrate, Some(0));
        assert_eq!(c.channels, Some(1));
    }

    #[test]
    fn set_codec_reads_a_bitrate_that_is_not_zero() {
        let c = parse_set_codec(
            "Set Codec sofia/softphone/1213 PCMU/8000 20 ms 160 samples 64000 bits 1 channels",
        )
        .expect("parsed");
        assert_eq!(c.bitrate, Some(64000));
    }

    #[test]
    fn unrelated_media_lines_are_not_codecs() {
        assert!(parse_set_codec("Set telephone-event payload to 101@48000").is_none());
        assert!(parse_original_read_codec("Activating RTCP PORT 4001").is_none());
    }
}
