//! Types produced per log entry: the reassembled [`Block`] variants, the
//! [`LogEntry`] record itself, and parsing anomalies ([`ParseWarning`]).

use std::fmt;

use crate::attached::AttachedLines;
use crate::codec::{CodecMedia, CodecOffer, CodecParseError};
use crate::decode::truncate_at_char_boundary;
use crate::level::LogLevel;
use crate::line::LineKind;
use crate::message::{MessageKind, SdpDirection};

use super::collision::MOD_LOGFILE_BUF_SIZE;

/// Structured data extracted from a multi-line dump that follows a primary log entry.
///
/// Each variant corresponds to a block type that the stream state machine
/// recognizes and reassembles from continuation lines.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    /// Channel variable dump — `Channel-*` fields and `variable_*` key-value pairs.
    /// Multi-line variable values (e.g. embedded SDP) are reassembled with `\n` separators.
    ChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
    },
    /// SDP session description body, collected line by line.
    Sdp {
        direction: SdpDirection,
        body: Vec<String>,
    },
    /// Codec negotiation sequence for one media type. A run only ever covers a
    /// single [`CodecMedia`]; audio and video traces never share a block.
    CodecNegotiation {
        media: CodecMedia,
        /// `(remote offer, local implementation)` for each pair compared.
        comparisons: Vec<(CodecOffer, CodecOffer)>,
        matched: Vec<CodecOffer>,
        /// Codecs kept as fallbacks because only their ptime differed.
        near_matched: Vec<CodecOffer>,
    },
}

impl Block {
    /// Value of a `Channel-*` field in a CHANNEL_DATA dump, or `None` if this
    /// block is another kind or never carried that field.
    pub fn field(&self, name: &str) -> Option<&str> {
        let Block::ChannelData { fields, .. } = self else {
            return None;
        };
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Value of a channel variable in a CHANNEL_DATA dump.
    ///
    /// Accepts any of `freeswitch-types`' variable-name enums, and spares the
    /// caller from knowing that a dump spells its keys with the `variable_`
    /// prefix that [`SessionState::variable`](crate::SessionState::variable)
    /// strips — the two surfaces answer the same question the same way.
    pub fn variable<V: freeswitch_types::variables::VariableName>(&self, var: V) -> Option<&str> {
        let Block::ChannelData { variables, .. } = self else {
            return None;
        };
        let wanted = var.as_str();
        variables
            .iter()
            .find(|(n, _)| n.strip_prefix("variable_").unwrap_or(n) == wanted)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(feature = "sdp")]
impl Block {
    /// Codecs described by an SDP body.
    ///
    /// `None` when there is no body to read — another block type, or an SDP
    /// marker that carried none. Sofia logs several (`Duplicate SDP`,
    /// `Processing updated SDP`) purely as announcements, and an empty body is
    /// absence rather than a malformed session.
    ///
    /// Parsed on each call rather than stored — see `docs/design-rationale.md`.
    /// Only a session-level failure is an `Err`: a malformed `a=rtpmap` or a
    /// broken media section degrades into
    /// [`SdpCodecs::warnings`](freeswitch_types::sdp::SdpCodecs::warnings).
    pub fn sdp_codecs(
        &self,
    ) -> Option<Result<freeswitch_types::sdp::SdpCodecs, freeswitch_types::sdp::SdpCodecError>>
    {
        let Block::Sdp { body, .. } = self else {
            return None;
        };
        let text = body.join("\n");
        if text.trim().is_empty() {
            return None;
        }
        Some(freeswitch_types::sdp::SdpCodecs::parse(&text))
    }
}

/// Longest line excerpt a warning carries. An offending line can be tens of
/// kilobytes; the excerpt is for a human reading the warning, not for matching on.
pub(super) const WARNING_EXCERPT_LEN: usize = 80;

/// A per-session reading whose value its vocabulary did not know.
///
/// Named rather than free-form so a consumer can tell which reading lapsed
/// without matching on the value it choked on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionReading {
    ChannelState,
    CallState,
    CallDirection,
    HangupCause,
}

impl fmt::Display for SessionReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            SessionReading::ChannelState => "channel state",
            SessionReading::CallState => "call state",
            SessionReading::CallDirection => "call direction",
            SessionReading::HangupCause => "hangup cause",
        };
        f.write_str(label)
    }
}

/// A parsing anomaly, attached to the entry whose lines produced it.
///
/// The set is closed and every kind is named — see `docs/design-rationale.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseWarning {
    /// A CHANNEL_DATA variable opened its `[` and the block ended before the `]`.
    /// The value collected so far is still recorded.
    UnclosedVariable { name: String },
    /// A line inside a CHANNEL_DATA block matched neither the field nor the
    /// variable shape, so it contributed nothing to the block.
    UnparseableChannelData { line: String },
    /// A codec negotiation line matched no known trace shape, or its bracketed
    /// token would not parse. That codec is missing from the block.
    UnrecognizedCodecLine {
        line: String,
        source: Option<CodecParseError>,
    },
    /// A continuation line arrived while a codec negotiation block was open.
    /// The trace has no continuations, so the line belongs to nothing.
    UnexpectedCodecContinuation { line: String },
    /// The formatted line exceeded `mod_logfile`'s write buffer, so the record
    /// was cut short and lost its trailing newline. `bytes` is the formatted
    /// length, prefix included.
    OversizeLine { bytes: usize },
    /// The entry's attached lines outgrew the offsets addressing them, so this
    /// line could not be stored. Counted in
    /// [`ParseStats::lines_dropped`](super::ParseStats::lines_dropped).
    AttachedOverflow { line: String },
    /// A per-session reading met a value its vocabulary does not know — either
    /// FreeSWITCH gained one or the line is corrupt. The state that reading
    /// feeds keeps its last resolved value.
    UnreadableValue {
        reading: SessionReading,
        value: String,
    },
}

impl ParseWarning {
    /// Trim a line down to what a warning is willing to carry.
    pub(crate) fn excerpt(msg: &str) -> String {
        truncate_at_char_boundary(msg, WARNING_EXCERPT_LEN).to_string()
    }
}

impl fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseWarning::UnclosedVariable { name } => {
                write!(f, "unclosed multi-line variable: {name}")
            }
            ParseWarning::UnparseableChannelData { line } => {
                write!(f, "unparseable CHANNEL_DATA line: {line}")
            }
            ParseWarning::UnrecognizedCodecLine {
                line,
                source: Some(e),
            } => write!(f, "unrecognized codec negotiation line ({e}): {line}"),
            ParseWarning::UnrecognizedCodecLine { line, source: None } => {
                write!(f, "unrecognized codec negotiation line: {line}")
            }
            ParseWarning::UnexpectedCodecContinuation { line } => {
                write!(f, "unexpected codec negotiation continuation: {line}")
            }
            ParseWarning::OversizeLine { bytes } => write!(
                f,
                "line exceeds mod_logfile {MOD_LOGFILE_BUF_SIZE}-byte buffer \
                 ({bytes} bytes), data may be truncated"
            ),
            ParseWarning::UnreadableValue { reading, value } => {
                write!(f, "unreadable {reading}: {value}")
            }
            ParseWarning::AttachedOverflow { line } => {
                write!(f, "entry's attached lines full, dropped: {line}")
            }
        }
    }
}

/// A complete parsed log entry with all context resolved.
///
/// Produced by [`LogStream`](super::LogStream). Continuation lines have been
/// grouped, UUID/timestamp inherited from context where needed, and
/// multi-line blocks reassembled.
#[derive(Debug)]
pub struct LogEntry {
    /// Session UUID; `None` for system lines (no channel context).
    pub uuid: Option<String>,
    /// Timestamp with microsecond precision; inherited from the previous entry for continuations.
    pub timestamp: String,
    /// `None` for continuation and truncated lines.
    pub level: Option<LogLevel>,
    /// Core scheduler idle percentage; `None` for continuations.
    pub idle_pct: Option<String>,
    /// Source file:line; `None` for continuations.
    pub source: Option<String>,
    /// The primary message text.
    pub message: String,
    /// Which line format originated this entry.
    pub kind: LineKind,
    /// Semantic classification of the message content.
    pub message_kind: MessageKind,
    /// Typed, parsed multi-line block; `None` for entries without a trailing block.
    pub block: Option<Block>,
    /// Raw continuation lines that followed the primary line.
    pub attached: AttachedLines,
    /// 1-based line number in the input stream.
    pub line_number: u64,
    /// Per-entry warnings about parsing anomalies.
    pub warnings: Vec<ParseWarning>,
}

impl LogEntry {
    /// An entry for output the parser never produced — a separator line
    /// between files or dates, or a hand-built test fixture. Carries no
    /// uuid, timestamp, level, source or block; override individual fields
    /// with struct-update syntax for callers that need one set.
    pub fn synthetic(message: impl Into<String>) -> LogEntry {
        LogEntry {
            uuid: None,
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: message.into(),
            kind: LineKind::Full,
            message_kind: MessageKind::General,
            block: None,
            attached: AttachedLines::new(),
            line_number: 0,
            warnings: Vec::new(),
        }
    }
}
