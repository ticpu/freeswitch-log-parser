//! The typed vocabulary a classified message decomposes into.

use std::fmt;

use crate::codec::CodecMedia;

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

/// Source of a DTMF event log line.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtmfSource {
    /// RFC2833 DTMF decoded at the RTP layer (`switch_rtp.c`).
    Rtp,
    /// DTMF queued to channel after validation (`switch_channel.c`).
    Channel,
    /// DTMF received via SIP INFO method (`sofia.c`).
    SipInfo,
}

impl fmt::Display for DtmfSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtmfSource::Rtp => f.pad("rtp"),
            DtmfSource::Channel => f.pad("channel"),
            DtmfSource::SipInfo => f.pad("sip-info"),
        }
    }
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
    /// A channel variable named with its value, whichever narration logged it.
    /// `name` always carries the `variable_` prefix.
    Variable { name: String, value: String },
    /// Start of an SDP body block (`Local SDP:`, `Remote SDP:`).
    SdpMarker { direction: SdpDirection },
    /// Channel state transition (`State Change`, `Callstate Change`, `SOFIA` state).
    StateChange { detail: String },
    /// `Audio Codec Compare` lines during codec negotiation.
    CodecNegotiation { media: CodecMedia },
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
    /// DTMF digit received on the channel.
    /// Format: `[RTP] RECV DTMF <digit>:<duration_ms>` or `INFO DTMF(<digit>)`
    Dtmf {
        /// Where the DTMF was logged (RTP layer, channel layer, or SIP INFO).
        source: DtmfSource,
        /// The DTMF digit (0-9, *, #, A-D, or F for flash).
        digit: char,
        /// Duration in milliseconds. `None` for SIP INFO DTMF (no duration logged).
        duration_ms: Option<u32>,
    },
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
        "dtmf",
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
            MessageKind::CodecNegotiation { .. } => "codec-negotiation",
            MessageKind::Media { .. } => "media",
            MessageKind::ChannelLifecycle { .. } => "channel-lifecycle",
            MessageKind::SipInvite { .. } => "sip-invite",
            MessageKind::EventSocket { .. } => "event-socket",
            MessageKind::Dtmf { .. } => "dtmf",
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
            MessageKind::CodecNegotiation { media } => {
                f.pad(&format!("codec-negotiation({media})"))
            }
            MessageKind::Media { .. } => f.pad("media"),
            MessageKind::ChannelLifecycle { .. } => f.pad("channel-lifecycle"),
            MessageKind::SipInvite { .. } => f.pad("sip-invite"),
            MessageKind::EventSocket { .. } => f.pad("event-socket"),
            MessageKind::Dtmf {
                source,
                digit,
                duration_ms,
            } => match duration_ms {
                Some(ms) => write!(f, "dtmf({source}:{digit}:{ms}ms)"),
                None => write!(f, "dtmf({source}:{digit})"),
            },
            MessageKind::General => f.pad("general"),
            MessageKind::FileChange => f.pad("file-change"),
            MessageKind::DateChange => f.pad("date-change"),
        }
    }
}
