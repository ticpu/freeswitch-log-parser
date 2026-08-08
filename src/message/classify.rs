//! The classification dispatcher — the ordered prefix checks that map a
//! message to its [`MessageKind`], and the shape-specific constructors.

use crate::codec::CodecMedia;

use super::dtmf::parse_dtmf;
use super::kind::MessageKind;
use super::lifecycle::{classify_channel_prefixed, detect_channel_lifecycle};
use super::media::{detect_media, detect_sdp_direction};
use super::parts::{
    dialplan_parts, execute_parts, parse_bracketed_value, set_export_parts, strip_channel_prefix,
};

fn parse_execute(msg: &str) -> MessageKind {
    let parts = execute_parts(msg);
    MessageKind::Execute {
        depth: parts.depth,
        channel: parts.channel.to_string(),
        application: parts.application.to_string(),
        arguments: parts.arguments.to_string(),
    }
}
fn parse_dialplan(msg: &str) -> MessageKind {
    let (channel, detail) = dialplan_parts(msg);
    MessageKind::Dialplan {
        channel: channel.to_string(),
        detail: detail.to_string(),
    }
}
/// Classify a log message's text into a [`MessageKind`].
///
/// Pure function — no state, no allocation beyond the returned enum. Works on
/// the `message` field from [`RawLine`](crate::RawLine) or any raw message string.
pub fn classify_message(msg: &str) -> MessageKind {
    if msg.starts_with("EXECUTE ") || msg.starts_with("Execute ") {
        return parse_execute(msg);
    }

    if msg.starts_with("RECV DTMF ")
        || msg.starts_with("RTP RECV DTMF ")
        || msg.starts_with("INFO DTMF(")
    {
        if let Some(dtmf) = parse_dtmf(msg) {
            return dtmf;
        }
    }

    if msg.starts_with("Dialplan: ") || msg.starts_with("Chatplan: ") {
        return parse_dialplan(msg);
    }

    if msg.starts_with("Processing ")
        && (msg.contains(" in context ") || msg.contains("recursive conditions"))
    {
        return parse_dialplan_processing(msg);
    }

    if msg.contains("CHANNEL_DATA") {
        return MessageKind::ChannelData;
    }

    if msg.starts_with("variable_") {
        if let Some((name, value)) = parse_bracketed_value(msg, 0) {
            return MessageKind::Variable {
                name: name.to_string(),
                value: value.to_string(),
            };
        }
    }

    if let Some(direction) = detect_sdp_direction(msg) {
        return MessageKind::SdpMarker { direction };
    }

    if msg.contains("State Change") || msg.contains("Callstate Change") {
        return MessageKind::StateChange {
            detail: msg.to_string(),
        };
    }

    // `set()` logs its verb first, and the stack variants share the shape.
    if msg.starts_with("SET ")
        || msg.starts_with("EXPORT ")
        || msg.starts_with("PUSH ")
        || msg.starts_with("UNSHIFT ")
    {
        if let Some(sv) = parse_set_or_export(msg) {
            return sv;
        }
    }

    if msg.starts_with("Audio Codec Compare ") {
        return MessageKind::CodecNegotiation {
            media: CodecMedia::Audio,
        };
    }

    if msg.starts_with("Video Codec Compare ") {
        return MessageKind::CodecNegotiation {
            media: CodecMedia::Video,
        };
    }

    if msg.starts_with("CoreSession::setVariable(") {
        return parse_core_session_set_variable(msg);
    }

    if msg.starts_with("UNSET ") {
        return parse_unset(msg);
    }

    // Pre-dialplan set action: "set variable name=value"
    if let Some(rest) = msg.strip_prefix("set variable ") {
        if let Some((name, value)) = rest.split_once('=') {
            return MessageKind::Variable {
                name: format!("variable_{name}"),
                value: value.to_string(),
            };
        }
    }

    if msg.starts_with("Transfer ") {
        return MessageKind::Dialplan {
            channel: String::new(),
            detail: msg.to_string(),
        };
    }

    // (channel) State STATE — parenthesized channel state
    if msg.starts_with('(') {
        if msg.contains(") State ") {
            return MessageKind::StateChange {
                detail: msg.to_string(),
            };
        }
        return MessageKind::ChannelLifecycle {
            detail: msg.to_string(),
        };
    }

    // SOFIA STATE (no channel prefix) — e.g. "SOFIA EXCHANGE_MEDIA"
    if msg.starts_with("SOFIA ") {
        return MessageKind::StateChange {
            detail: msg.to_string(),
        };
    }

    // Pre-dialplan: checking condition / action results from sofia_pre_dialplan.c
    if msg.starts_with("checking condition") || msg.starts_with("action(") {
        return MessageKind::ChannelLifecycle {
            detail: msg.to_string(),
        };
    }

    if msg.starts_with("Event Socket Command") {
        return MessageKind::EventSocket {
            detail: msg.to_string(),
        };
    }

    // Media patterns (no channel prefix)
    if let Some(kind) = detect_media(msg) {
        return kind;
    }

    // Channel lifecycle patterns (no channel prefix)
    if let Some(kind) = detect_channel_lifecycle(msg) {
        return kind;
    }

    // Channel-prefixed messages: sofia/..., loopback/... prefix
    if let Some((channel_part, rest)) = strip_channel_prefix(msg) {
        return classify_channel_prefixed(channel_part, rest);
    }

    // Channel-* fields and other Key: [value] patterns from CHANNEL_DATA dumps
    // Must come after more specific checks to avoid false positives
    if let Some((name, value)) = parse_bracketed_value(msg, 0) {
        let name_bytes = name.as_bytes();
        if !name_bytes.is_empty()
            && !name.contains(' ')
            && name_bytes[0].is_ascii_alphabetic()
            && (name.contains('-') || name.starts_with("Channel-"))
        {
            return MessageKind::ChannelField {
                name: name.to_string(),
                value: value.to_string(),
            };
        }
    }

    MessageKind::General
}
fn parse_core_session_set_variable(msg: &str) -> MessageKind {
    let rest = &msg["CoreSession::setVariable(".len()..];
    if let Some(end) = rest.strip_suffix(')') {
        if let Some(comma) = end.find(", ") {
            return MessageKind::Variable {
                name: format!("variable_{}", &end[..comma]),
                value: end[comma + 2..].to_string(),
            };
        }
    }
    MessageKind::Variable {
        name: String::new(),
        value: msg.to_string(),
    }
}

fn parse_unset(msg: &str) -> MessageKind {
    let rest = &msg["UNSET ".len()..];
    let name = if let Some(inner) = rest.strip_prefix('[') {
        inner.strip_suffix(']').unwrap_or(inner)
    } else {
        rest
    };
    MessageKind::Variable {
        name: format!("variable_{name}"),
        value: String::new(),
    }
}

fn parse_dialplan_processing(msg: &str) -> MessageKind {
    let rest = &msg["Processing ".len()..];
    MessageKind::Dialplan {
        channel: String::new(),
        detail: rest.to_string(),
    }
}
fn parse_set_or_export(msg: &str) -> Option<MessageKind> {
    let parts = set_export_parts(msg)?;
    Some(MessageKind::Variable {
        name: format!("variable_{}", parts.name),
        value: parts.value.to_string(),
    })
}
