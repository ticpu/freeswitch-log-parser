//! DTMF event lines from the RTP layer, the channel layer, and SIP INFO.

use super::kind::{DtmfSource, MessageKind};

fn is_valid_dtmf_digit(c: char) -> bool {
    matches!(c, '0'..='9' | '*' | '#' | 'A'..='D' | 'F')
}

pub(super) fn parse_dtmf(msg: &str) -> Option<MessageKind> {
    // RTP RECV DTMF x:y
    if let Some(rest) = msg.strip_prefix("RTP RECV DTMF ") {
        let colon = rest.find(':')?;
        if colon != 1 {
            return None;
        }
        let digit = rest.chars().next()?;
        if !is_valid_dtmf_digit(digit) {
            return None;
        }
        let duration_ms = rest[colon + 1..].parse::<u32>().ok()?;
        return Some(MessageKind::Dtmf {
            source: DtmfSource::Rtp,
            digit,
            duration_ms: Some(duration_ms),
        });
    }

    // RECV DTMF x:y
    if let Some(rest) = msg.strip_prefix("RECV DTMF ") {
        let colon = rest.find(':')?;
        if colon != 1 {
            return None;
        }
        let digit = rest.chars().next()?;
        if !is_valid_dtmf_digit(digit) {
            return None;
        }
        let duration_ms = rest[colon + 1..].parse::<u32>().ok()?;
        return Some(MessageKind::Dtmf {
            source: DtmfSource::Channel,
            digit,
            duration_ms: Some(duration_ms),
        });
    }

    // INFO DTMF(x)
    if let Some(rest) = msg.strip_prefix("INFO DTMF(") {
        let close = rest.find(')')?;
        if close != 1 {
            return None;
        }
        let digit = rest.chars().next()?;
        if !is_valid_dtmf_digit(digit) {
            return None;
        }
        return Some(MessageKind::Dtmf {
            source: DtmfSource::SipInfo,
            digit,
            duration_ms: None,
        });
    }

    None
}
