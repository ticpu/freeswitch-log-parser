use std::fmt;

/// Which end of a call an SDP body belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpDirection {
    Local,
    /// Local SDP sent in a 180/183 early media response.
    LocalRing,
    Remote,
    /// SDP reference that doesn't specify local or remote.
    Unknown,
}

/// Direction of a sofia SIP INVITE log line.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipInviteDirection {
    /// `sofia/X/Y receiving invite ...` — inbound INVITE on a sofia profile.
    Receiving,
    /// `sofia/X/Y sending invite ...` — outbound INVITE on a sofia profile.
    Sending,
}

impl fmt::Display for SdpDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpDirection::Local => f.pad("local"),
            SdpDirection::LocalRing => f.pad("local-ring"),
            SdpDirection::Remote => f.pad("remote"),
            SdpDirection::Unknown => f.pad("unknown"),
        }
    }
}

/// Semantic classification of a log message's content.
///
/// `Display` includes variant-specific detail (e.g. `execute(set)`, `var(sip_call_id)`)
/// while [`label()`](MessageKind::label) returns just the category string.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    /// Dialplan application execution trace (`EXECUTE [depth=N] channel app(args)`).
    Execute {
        depth: u32,
        channel: String,
        application: String,
        arguments: String,
    },
    /// Dialplan processing output — regex matching, actions, context routing.
    Dialplan { channel: String, detail: String },
    /// Start of a CHANNEL_DATA variable dump block.
    ChannelData,
    /// A `Channel-*` or similar hyphenated field from a CHANNEL_DATA dump.
    ChannelField { name: String, value: String },
    /// A `variable_*` field — from dumps, `SET`, `EXPORT`, `set()`, or `CoreSession::setVariable`.
    Variable { name: String, value: String },
    /// Start of an SDP body block (`Local SDP:`, `Remote SDP:`).
    SdpMarker { direction: SdpDirection },
    /// Channel state transition (`State Change`, `Callstate Change`, `SOFIA` state).
    StateChange { detail: String },
    /// `Audio Codec Compare` lines during codec negotiation.
    CodecNegotiation,
    /// RTP, RTCP, recording, and other media-related messages.
    Media { detail: String },
    /// Channel lifecycle events — new/close/hangup, bridge, ring, REFER, CANCEL, BYE.
    ChannelLifecycle { detail: String },
    /// Sofia logged a SIP INVITE on this channel — the line is one of:
    /// - `sofia/<profile>/<endpoint> receiving invite from <ip>:<port> ... call-id: <id>`
    /// - `sofia/<profile>/<endpoint> sending invite [version: ...] [call-id: <id>]`
    ///
    /// Always emitted by sofia for every inbound and outbound call regardless
    /// of dialplan — the canonical primitive for `sip_call_id ↔ channel_uuid`
    /// correlation. The line's leading UUID is on [`crate::LogEntry::uuid`].
    SipInvite {
        direction: SipInviteDirection,
        /// The sofia profile name (segment between `sofia/` and the next `/`).
        profile: String,
        /// SIP `Call-ID` from the log line. `None` when sofia logs `(null)`
        /// (typical for outbound at pre-routing time — a later log entry on
        /// the same UUID will carry the actual id) or when the line carries
        /// no `call-id:` field (the version-only DEBUG follow-up for sending).
        call_id: Option<String>,
    },
    /// Event socket commands from `mod_event_socket`.
    EventSocket { detail: String },
    /// Anything not matching a more specific pattern.
    General,
    /// Synthetic marker emitted at log file boundaries (never from `classify_message`).
    FileChange,
    /// Synthetic marker emitted at date boundaries (never from `classify_message`).
    DateChange,
}

impl MessageKind {
    /// Exhaustive list of all category label strings, in declaration order.
    pub const ALL_LABELS: &[&str] = &[
        "execute",
        "dialplan",
        "channel-data",
        "channel-field",
        "variable",
        "sdp-marker",
        "state-change",
        "codec-negotiation",
        "media",
        "channel-lifecycle",
        "sip-invite",
        "event-socket",
        "general",
        "file-change",
        "date-change",
    ];

    /// Returns the bare category string without variant-specific data.
    pub fn label(&self) -> &'static str {
        match self {
            MessageKind::Execute { .. } => "execute",
            MessageKind::Dialplan { .. } => "dialplan",
            MessageKind::ChannelData => "channel-data",
            MessageKind::ChannelField { .. } => "channel-field",
            MessageKind::Variable { .. } => "variable",
            MessageKind::SdpMarker { .. } => "sdp-marker",
            MessageKind::StateChange { .. } => "state-change",
            MessageKind::CodecNegotiation => "codec-negotiation",
            MessageKind::Media { .. } => "media",
            MessageKind::ChannelLifecycle { .. } => "channel-lifecycle",
            MessageKind::SipInvite { .. } => "sip-invite",
            MessageKind::EventSocket { .. } => "event-socket",
            MessageKind::General => "general",
            MessageKind::FileChange => "file-change",
            MessageKind::DateChange => "date-change",
        }
    }
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageKind::Execute { application, .. } => write!(f, "execute({})", application),
            MessageKind::Dialplan { .. } => f.pad("dialplan"),
            MessageKind::ChannelData => f.pad("channel-data"),
            MessageKind::ChannelField { name, .. } => write!(f, "field({})", name),
            MessageKind::Variable { name, .. } => write!(f, "var({})", name),
            MessageKind::SdpMarker { direction } => write!(f, "sdp({})", direction),
            MessageKind::StateChange { .. } => f.pad("state-change"),
            MessageKind::CodecNegotiation => f.pad("codec-negotiation"),
            MessageKind::Media { .. } => f.pad("media"),
            MessageKind::ChannelLifecycle { .. } => f.pad("channel-lifecycle"),
            MessageKind::SipInvite { .. } => f.pad("sip-invite"),
            MessageKind::EventSocket { .. } => f.pad("event-socket"),
            MessageKind::General => f.pad("general"),
            MessageKind::FileChange => f.pad("file-change"),
            MessageKind::DateChange => f.pad("date-change"),
        }
    }
}

fn parse_execute(msg: &str) -> MessageKind {
    let rest = &msg["EXECUTE ".len()..];

    let depth = if rest.starts_with("[depth=") {
        let end = rest.find(']').unwrap_or(0);
        if end > 7 {
            rest[7..end].parse::<u32>().unwrap_or(0)
        } else {
            0
        }
    } else {
        return MessageKind::Execute {
            depth: 0,
            channel: String::new(),
            application: String::new(),
            arguments: rest.to_string(),
        };
    };

    let after_bracket = rest.find("] ").map(|p| &rest[p + 2..]).unwrap_or("");

    // Lowercase "Execute [depth=N] app(args)" has no channel.
    // Uppercase "EXECUTE [depth=N] channel app(args)" has channel before app.
    // Detect by checking if first token contains '(' (app) or '/' (channel path).
    let (channel, app_part) = match after_bracket.find(' ') {
        Some(p) => {
            let first_token = &after_bracket[..p];
            if first_token.contains('/') {
                (first_token, &after_bracket[p + 1..])
            } else {
                ("", after_bracket)
            }
        }
        None => ("", after_bracket),
    };

    let (application, arguments) = match app_part.find('(') {
        Some(p) => {
            let app = &app_part[..p];
            let args = if app_part.ends_with(')') {
                &app_part[p + 1..app_part.len() - 1]
            } else {
                &app_part[p + 1..]
            };
            (app, args)
        }
        None => (app_part, ""),
    };

    MessageKind::Execute {
        depth,
        channel: channel.to_string(),
        application: application.to_string(),
        arguments: arguments.to_string(),
    }
}

fn parse_dialplan(msg: &str) -> MessageKind {
    let prefix_len = if msg.starts_with("Chatplan: ") {
        "Chatplan: ".len()
    } else {
        "Dialplan: ".len()
    };
    let rest = &msg[prefix_len..];
    let (channel, detail) = match rest.find(' ') {
        Some(p) => (&rest[..p], &rest[p + 1..]),
        None => (rest, ""),
    };
    MessageKind::Dialplan {
        channel: channel.to_string(),
        detail: detail.to_string(),
    }
}

fn parse_bracketed_value(s: &str, prefix_len: usize) -> Option<(&str, &str)> {
    let after_prefix = &s[prefix_len..];
    let colon = after_prefix.find(": ")?;
    let name = &after_prefix[..colon];
    let value_part = &after_prefix[colon + 2..];
    if let Some(inner) = value_part.strip_prefix('[') {
        if let Some(stripped) = inner.strip_suffix(']') {
            Some((name, stripped))
        } else {
            Some((name, inner))
        }
    } else {
        Some((name, value_part))
    }
}

fn detect_sdp_direction(msg: &str) -> Option<SdpDirection> {
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

/// Classify a log message's text into a [`MessageKind`].
///
/// Pure function — no state, no allocation beyond the returned enum. Works on
/// the `message` field from [`RawLine`](crate::RawLine) or any raw message string.
pub fn classify_message(msg: &str) -> MessageKind {
    if msg.starts_with("EXECUTE ") || msg.starts_with("Execute ") {
        return parse_execute(msg);
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

    if msg.starts_with("SET ") || msg.starts_with("EXPORT ") {
        if let Some(sv) = parse_set_or_export(msg) {
            return sv;
        }
    }

    if msg.starts_with("Audio Codec Compare ") {
        return MessageKind::CodecNegotiation;
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

fn strip_channel_prefix(msg: &str) -> Option<(&str, &str)> {
    if !msg.starts_with("sofia/") && !msg.starts_with("loopback/") {
        return None;
    }
    let bytes = msg.as_bytes();
    let mut i = 0;
    let mut bracket_depth: u32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => bracket_depth += 1,
            b']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
            }
            b' ' if bracket_depth == 0 => {
                return Some((&msg[..i], &msg[i + 1..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn classify_channel_prefixed(channel_part: &str, rest: &str) -> MessageKind {
    // Sofia INVITE lines — typed extraction of (direction, profile, call-id).
    // Must run before the ChannelLifecycle fallback; sofia always logs these
    // for every inbound and outbound call regardless of dialplan, making them
    // the canonical primitive for sip_call_id ↔ channel_uuid correlation.
    if let Some(direction) = sip_invite_direction(rest) {
        let profile = extract_sofia_profile(channel_part).unwrap_or_default();
        let call_id = extract_call_id(rest);
        return MessageKind::SipInvite {
            direction,
            profile,
            call_id,
        };
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
    MessageKind::ChannelLifecycle {
        detail: rest.to_string(),
    }
}

fn sip_invite_direction(rest: &str) -> Option<SipInviteDirection> {
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

fn extract_call_id(rest: &str) -> Option<String> {
    let after = rest.split_once("call-id: ")?.1;
    let token = after.split_whitespace().next()?;
    if token == "(null)" {
        None
    } else {
        Some(token.to_string())
    }
}

fn detect_media(msg: &str) -> Option<MessageKind> {
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
    ];
    for prefix in &media_prefixes {
        if msg.starts_with(prefix) {
            return Some(MessageKind::Media {
                detail: msg.to_string(),
            });
        }
    }

    if msg.starts_with("Setting RTCP") || msg.starts_with("Setting BUG Codec") {
        return Some(MessageKind::Media {
            detail: msg.to_string(),
        });
    }

    if msg.starts_with("Set ") {
        return Some(MessageKind::Media {
            detail: msg.to_string(),
        });
    }

    if msg.starts_with("Original read codec set to")
        || msg.starts_with("Forcing crypto_mode")
        || msg.starts_with("Parsing global variables")
        || msg.starts_with("Parsing session specific variables")
    {
        return Some(MessageKind::Media {
            detail: msg.to_string(),
        });
    }

    None
}

fn detect_channel_lifecycle(msg: &str) -> Option<MessageKind> {
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
    ];
    for prefix in &lifecycle_prefixes {
        if msg.starts_with(prefix) {
            return Some(MessageKind::ChannelLifecycle {
                detail: msg.to_string(),
            });
        }
    }

    if msg.starts_with("Channel ") {
        return Some(MessageKind::ChannelLifecycle {
            detail: msg.to_string(),
        });
    }

    if msg.starts_with("Application ") && msg.contains("Requires media") {
        return Some(MessageKind::ChannelLifecycle {
            detail: msg.to_string(),
        });
    }

    None
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
    // SET channel [name]=[value]
    // EXPORT (export_vars) [name]=[value]
    // EXPORT (export_vars) (REMOTE ONLY) [name]=[value]
    // Find "]=[" which uniquely identifies the [name]=[value] boundary
    let sep = msg.find("]=[");
    if let Some(sep_pos) = sep {
        let name_start = msg[..sep_pos].rfind('[')?;
        let name = &msg[name_start + 1..sep_pos];
        let val_start = sep_pos + 3; // skip "]=["
        let val_end = msg[val_start..]
            .find(']')
            .map(|p| val_start + p)
            .unwrap_or(msg.len());
        let value = &msg[val_start..val_end];
        return Some(MessageKind::Variable {
            name: format!("variable_{name}"),
            value: value.to_string(),
        });
    }

    // EXPORT with simple [name=value] (no ]=[ separator)
    // e.g. "EXPORT (export_vars) [originate_timeout=3600]"
    // This doesn't exist in the samples but handle it for robustness
    None
}

#[cfg(test)]
mod tests {
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
        let msg = "EXECUTE [depth=0] sofia/internal/+15550001234@192.0.2.1 export(originate_timeout=3600)";
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
        let msg = "Dialplan: sofia/internal/+15550001234@192.0.2.1 parsing [public->global] continue=true";
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
        let msg =
            "Dialplan: sofia/internal/+15550001234@192.0.2.1 Action set(call_direction=inbound)";
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
        let msg = "SET sofia/internal-v6/1263@[fd51:2050:2220:198::10] [ngcs_bridge_sip_req_uri]=[conf-factory-app.qc.core.ng.911bell.ca]";
        match classify_message(msg) {
            MessageKind::Variable { name, value } => {
                assert_eq!(name, "variable_ngcs_bridge_sip_req_uri");
                assert_eq!(value, "conf-factory-app.qc.core.ng.911bell.ca");
            }
            other => panic!("expected Variable, got {other:?}"),
        }
    }

    #[test]
    fn export_variable_message() {
        let msg =
            "EXPORT (export_vars) (REMOTE ONLY) [sip_from_uri]=[sip:cauca1.qc.psap.ng.911bell.ca]";
        match classify_message(msg) {
            MessageKind::Variable { name, value } => {
                assert_eq!(name, "variable_sip_from_uri");
                assert_eq!(value, "sip:cauca1.qc.psap.ng.911bell.ca");
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
        let msg =
            "Chatplan: sofia/internal/+15550001234@192.0.2.1 Action set(call_direction=inbound)";
        match classify_message(msg) {
            MessageKind::Dialplan { detail, .. } => {
                assert!(detail.starts_with("Action "));
            }
            other => panic!("expected Dialplan, got {other:?}"),
        }
    }

    #[test]
    fn chatplan_anti_action() {
        let msg =
            "Chatplan: sofia/internal/+15550001234@192.0.2.1 ANTI-Action log(WARNING no match)";
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
}
