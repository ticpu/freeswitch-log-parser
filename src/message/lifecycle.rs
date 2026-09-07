//! Channel lifecycle lines and the sofia-prefixed shapes that carry a SIP INVITE.

use super::kind::{LifecycleEvent, MessageKind, SipInviteDirection};
use super::media::detect_media;
use super::parts::set_export_parts;
use super::varname::VarName;

/// The originating leg's success line, whose channel name can itself hold a
/// UUID — so the peer is read from after the marker, never scanned for.
pub(super) fn originate_success(msg: &str) -> Option<MessageKind> {
    let rest = msg.strip_prefix("Originate Resulted in Success: ")?;
    let inner = rest.strip_prefix('[')?;
    let close = inner.find(']')?;
    let peer_uuid = inner[close..]
        .split_once("Peer UUID: ")
        .map(|(_, u)| u.trim().to_string());
    Some(MessageKind::OriginateSuccess {
        channel: inner[..close].to_string(),
        peer_uuid,
    })
}

/// A lifecycle message with its step resolved from the text.
pub(crate) fn channel_lifecycle(detail: &str) -> MessageKind {
    let event = if detail.starts_with("New Channel ") {
        LifecycleEvent::NewChannel
    } else if detail.starts_with("Hangup ") {
        LifecycleEvent::Hangup
    } else if detail.starts_with("Close Channel ") || detail.starts_with("destroy/unlink") {
        LifecycleEvent::Destroy
    } else if detail.contains("has been answered") {
        LifecycleEvent::Answered
    } else {
        LifecycleEvent::Other
    };
    MessageKind::ChannelLifecycle {
        event,
        detail: detail.to_string(),
    }
}

/// Whether what follows a channel name is one of the core `[name]=[value]`
/// narrations. Only the shape is matched here; [`set_export_parts`] slices it.
pub(crate) fn is_channel_variable_narration(rest: &str) -> bool {
    rest.starts_with("EXPORTING[") || rest.starts_with("setting variable [")
}

pub(super) fn classify_channel_prefixed(channel_part: &str, rest: &str) -> MessageKind {
    // Ahead of the lifecycle fallback, which would swallow the one line that
    // correlates a SIP call-id to this channel.
    if let Some(direction) = sip_invite_direction(rest) {
        let profile = extract_sofia_profile(channel_part).unwrap_or_default();
        let call_id = extract_call_id(rest);
        return MessageKind::SipInvite {
            direction,
            profile,
            call_id,
        };
    }

    // Variable narrations that put the channel name first. Ahead of the media
    // and lifecycle fallbacks, which would otherwise claim them.
    if is_channel_variable_narration(rest) {
        if let Some(parts) = set_export_parts(rest) {
            return MessageKind::Variable {
                name: VarName::new(parts.name),
                value: parts.value.to_string(),
            };
        }
    }

    // SOFIA STATE / Standard STATE / RTC STATE
    if rest.starts_with("SOFIA ") || rest.starts_with("Standard ") || rest.starts_with("RTC ") {
        return MessageKind::StateChange {
            detail: rest.to_string(),
        };
    }

    if let Some(kind) = detect_media(rest) {
        return kind;
    }

    // Channel-prefixed lifecycle: destroy/unlink, REFER, CANCEL, BYE, etc.
    channel_lifecycle(rest)
}

pub(crate) fn sip_invite_direction(rest: &str) -> Option<SipInviteDirection> {
    if rest.starts_with("receiving invite") {
        Some(SipInviteDirection::Receiving)
    } else if rest.starts_with("sending invite") {
        Some(SipInviteDirection::Sending)
    } else {
        None
    }
}

fn extract_sofia_profile(channel_part: &str) -> Option<String> {
    let after = channel_part.strip_prefix("sofia/")?;
    let end = after.find('/').unwrap_or(after.len());
    if end == 0 {
        None
    } else {
        Some(after[..end].to_string())
    }
}

pub(crate) fn call_id_token(rest: &str) -> Option<&str> {
    let after = rest.split_once("call-id: ")?.1;
    let token = after.split_whitespace().next()?;
    if token == "(null)" {
        None
    } else {
        Some(token)
    }
}

fn extract_call_id(rest: &str) -> Option<String> {
    call_id_token(rest).map(str::to_string)
}
pub(super) fn detect_channel_lifecycle(msg: &str) -> Option<MessageKind> {
    let lifecycle_prefixes = [
        "New Channel ",
        "Close Channel ",
        "Hangup ",
        "Ring-Ready ",
        "Ring Ready ",
        "Pre-Answer ",
        "Sending early media",
        "Sending BYE",
        "Sending CANCEL",
        "Channel is hung up",
        "Call appears",
        "Found channel",
        "3PCC ",
        "Subscribed to 3PCC",
        "New log started",
        "Received a ",
        "Session ",
        "BRIDGE ",
        "Originate ",
        "USAGE:",
        "Split into",
        "Part ",
        "Responding to INVITE",
        "Redirecting to",
        "subscribing to",
        "Queue digit delay",
        "Channel ",
    ];
    if lifecycle_prefixes.iter().any(|p| msg.starts_with(p)) {
        return Some(channel_lifecycle(msg));
    }

    if msg.starts_with("Application ") && msg.contains("Requires media") {
        return Some(channel_lifecycle(msg));
    }

    None
}
