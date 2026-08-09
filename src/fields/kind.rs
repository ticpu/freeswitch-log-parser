//! The span vocabulary: what a located field is, where it lives, and how a
//! rewrite of it can fail.

use std::fmt;
use std::ops::Range;

/// What a located span holds.
///
/// A kind names the *slot* the value sits in, not the value's shape — a
/// [`CallerIdName`](FieldKind::CallerIdName) frequently holds a number, and the
/// consumer decides what that means.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldKind {
    /// An endpoint channel name (`sofia/<profile>/<user>@<host>`, `loopback/...`).
    ChannelName,
    /// Caller-id display name.
    CallerIdName,
    /// Caller-id number.
    CallerIdNumber,
    /// The number the dialplan is routing to.
    DestinationNumber,
    /// A SIP `Call-ID`.
    CallId,
    /// A channel UUID appearing anywhere in the text.
    Uuid,
    /// A SIP URI. No shape emits one yet — the variant is reserved for URI
    /// positions FreeSWITCH itself frames; URIs in channel-variable values are
    /// deliberately not classified here.
    SipUri,
    /// An IP address, at positions the classifier frames (a channel name's host,
    /// an inbound INVITE's source).
    IpAddr,
    /// A dump slot's value — a channel variable's or a channel field's — where
    /// the name names no slot above. The crate locates it and stops there;
    /// whether the name makes the value sensitive is the consumer's call, from
    /// the name the classification carries.
    VariableValue,
}

impl FieldKind {
    /// The bare category string.
    pub fn label(&self) -> &'static str {
        match self {
            FieldKind::ChannelName => "channel-name",
            FieldKind::CallerIdName => "caller-id-name",
            FieldKind::CallerIdNumber => "caller-id-number",
            FieldKind::DestinationNumber => "destination-number",
            FieldKind::CallId => "call-id",
            FieldKind::Uuid => "uuid",
            FieldKind::SipUri => "sip-uri",
            FieldKind::IpAddr => "ip-addr",
            FieldKind::VariableValue => "variable-value",
        }
    }
}

impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.label())
    }
}

/// Which of an entry's texts a range indexes.
///
/// An entry has two coordinate systems: [`LogEntry::message`](crate::LogEntry)
/// is header-stripped, while each attached line is the full physical line,
/// session-UUID prefix included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldLocation {
    /// The entry's primary message.
    Message,
    /// The i-th attached line, indexed as [`AttachedLines::get`](crate::AttachedLines::get) takes it.
    Attached(usize),
}

/// A located byte range and what it holds.
///
/// Ranges always index raw line text, never a reassembled [`Block`](crate::Block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    pub at: FieldLocation,
    pub range: Range<usize>,
}

/// Why a rewrite could not be applied.
///
/// Every span handed to [`apply_fields`] is validated, replaced or not, so a
/// malformed one fails the same way regardless of what the callback returns.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The range runs past the end of the text it was applied to.
    OutOfBounds {
        at: FieldLocation,
        range: Range<usize>,
        len: usize,
    },
    /// An endpoint falls inside a multi-byte character.
    NotOnCharBoundary {
        at: FieldLocation,
        range: Range<usize>,
    },
    /// Two replaced spans overlap without one containing the other, so there is
    /// no rewrite that honours both.
    OverlappingSpans {
        at: FieldLocation,
        first: Range<usize>,
        second: Range<usize>,
    },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::OutOfBounds { at, range, len } => write!(
                f,
                "span {}..{} is past the end of {at} ({len} bytes)",
                range.start, range.end
            ),
            RenderError::NotOnCharBoundary { at, range } => write!(
                f,
                "span {}..{} splits a character in {at}",
                range.start, range.end
            ),
            RenderError::OverlappingSpans { at, first, second } => write!(
                f,
                "replaced spans {}..{} and {}..{} partially overlap in {at}",
                first.start, first.end, second.start, second.end
            ),
        }
    }
}

impl std::error::Error for RenderError {}

impl fmt::Display for FieldLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldLocation::Message => f.pad("the message"),
            FieldLocation::Attached(i) => write!(f, "attached line {i}"),
        }
    }
}

/// An entry's text after a rewrite, one string per render unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEntry {
    pub message: String,
    pub attached: Vec<String>,
}
/// Rank deciding which kind sorts first when two spans start together; the more
/// specific kind wins, so a contained generic span follows its container.
pub(super) fn kind_rank(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::ChannelName => 0,
        FieldKind::CallerIdName => 1,
        FieldKind::CallerIdNumber => 2,
        FieldKind::DestinationNumber => 3,
        FieldKind::CallId => 4,
        FieldKind::SipUri => 5,
        FieldKind::IpAddr => 6,
        FieldKind::VariableValue => 7,
        FieldKind::Uuid => 8,
    }
}
