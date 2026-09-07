//! SDP direction and the media-message prefixes.

use super::kind::{MessageKind, SdpDirection};

pub(super) fn detect_sdp_direction(msg: &str) -> Option<SdpDirection> {
    if msg.contains("Ring SDP") {
        Some(SdpDirection::LocalRing)
    } else if msg.contains("Local SDP") || msg.contains("local-sdp") {
        Some(SdpDirection::Local)
    } else if msg.contains("Remote SDP") || msg.contains("remote-sdp") {
        Some(SdpDirection::Remote)
    } else if msg.ends_with(" SDP:") || msg.ends_with(" SDP") {
        Some(SdpDirection::Unknown)
    } else {
        None
    }
}
pub(super) fn detect_media(msg: &str) -> Option<MessageKind> {
    let media_prefixes = [
        "AUDIO RTP ",
        "VIDEO RTP ",
        "Activating ",
        "RTCP ",
        "Starting timer",
        "Record session",
        "Correct audio",
        "No silence detection",
        "Audio params",
        "Codec ",
        "Attaching BUG",
        "Removing BUG",
        "rtcp_stats_init",
        "Send middle packet",
        "Send end packet",
        "Send first packet",
        "START_RECORDING",
        "Stop recording",
        "Engaging Write Buffer",
        "rtcp_stats:",
        "Setting RTCP",
        "Setting BUG Codec",
        "Set ",
        "Original read codec set to",
        "Forcing crypto_mode",
        "Parsing global variables",
        "Parsing session specific variables",
    ];
    media_prefixes
        .iter()
        .any(|prefix| msg.starts_with(prefix))
        .then(|| MessageKind::Media {
            detail: msg.to_string(),
        })
}
