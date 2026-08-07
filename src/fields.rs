//! Typed byte spans over the raw text of a log entry.
//!
//! [`message_fields`] locates the fields a message carries and returns their
//! byte ranges instead of copies, so a consumer can rewrite the text in place —
//! redacting a caller id, colorizing a channel name — without re-deriving
//! positions the classifier already computed.
//!
//! A kind is emitted only where classification isolates it. Nothing here scans
//! free text for numbers, addresses or URIs: see `docs/design-rationale.md`.

use std::fmt;
use std::net::IpAddr;
use std::ops::Range;

use crate::message::{
    classify_message, dialplan_parts, execute_parts, hangup_channel, new_channel_name,
    paren_channel, parse_bracketed_value, set_export_parts, sip_invite_direction,
    strip_channel_prefix, MessageKind, SipInviteDirection,
};
use crate::uuid::find_uuids;

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

/// The byte ranges a dialplan `Processing` line decomposes into.
///
/// `name` and `number` are `None` for the bracketless `from->to` shape, where
/// `head` is the whole caller side.
pub(crate) struct ProcessingParts {
    /// Caller side as a whole — display name and `<number>` if present.
    pub(crate) head: Range<usize>,
    pub(crate) name: Option<Range<usize>>,
    /// Inside the `<>`, brackets excluded.
    pub(crate) number: Option<Range<usize>>,
    pub(crate) dest: Range<usize>,
    pub(crate) context: Range<usize>,
}

/// Parse `Processing <name> <<number>>-><dest> in context <ctx>`.
///
/// The caller-id name is free-form and may contain spaces, `->` and `<`, so the
/// parse anchors on the fixed frame: the rightmost ` in context ` and the last
/// `>->` (the `>` closing `<number>` immediately precedes `->`, and only the
/// number→destination boundary has that shape). Falls back to the last bare `->`
/// for the bracketless `from->to` shape.
pub(crate) fn processing_parts(msg: &str) -> Option<ProcessingParts> {
    let proc_idx = msg.find("Processing ")?;
    let base = proc_idx + "Processing ".len();
    let after_proc = &msg[base..];

    let ctx_idx = after_proc.rfind(" in context ")?;
    let head = &after_proc[..ctx_idx];

    let ctx_start = base + ctx_idx + " in context ".len();
    let context_token = msg[ctx_start..].split_whitespace().next()?;
    let context = ctx_start..ctx_start + context_token.len();

    let (head_range, dest) = match head.rfind(">->") {
        Some(i) => (base..base + i + 1, base + i + ">->".len()..base + ctx_idx),
        None => {
            let i = head.rfind("->")?;
            (base..base + i, base + i + "->".len()..base + ctx_idx)
        }
    };

    // Only the bracketed shape separates a display name from a number, and the
    // head's closing `>` is what marks it.
    let (name, number) = match msg[head_range.clone()]
        .strip_suffix('>')
        .and_then(|h| h.rfind(" <"))
    {
        Some(i) => (
            Some(head_range.start..head_range.start + i),
            Some(head_range.start + i + " <".len()..head_range.end - 1),
        ),
        None => (None, None),
    };

    Some(ProcessingParts {
        head: head_range,
        name: name.filter(|r| !r.is_empty()),
        number: number.filter(|r| !r.is_empty()),
        dest,
        context,
    })
}

/// The byte range of `sub` inside `parent`, or `None` when `sub` is not a
/// subslice of it. Empty subslices never yield a range — a helper that returns
/// a `""` literal rather than an in-place empty slice must degrade to no span.
fn subslice_range(parent: &str, sub: &str) -> Option<Range<usize>> {
    if sub.is_empty() {
        return None;
    }
    let base = parent.as_ptr() as usize;
    let start = (sub.as_ptr() as usize).checked_sub(base)?;
    if start + sub.len() > parent.len() {
        return None;
    }
    Some(start..start + sub.len())
}

/// The host of a channel name, when it is a literal address rather than a
/// hostname. Handles the bracketed IPv6 form and a trailing port.
fn channel_host_ip(channel: &str) -> Option<&str> {
    let host = channel.rsplit_once('@')?.1;

    if let Some(inner) = host.strip_prefix('[') {
        let close = inner.find(']')?;
        let addr = &inner[..close];
        return addr.parse::<IpAddr>().ok().map(|_| addr);
    }

    if host.parse::<IpAddr>().is_ok() {
        return Some(host);
    }

    // An unbracketed host with a port: only IPv4 can be split this way, since a
    // bare IPv6 address is all colons.
    let addr = host.rsplit_once(':')?.0;
    addr.parse::<std::net::Ipv4Addr>().ok().map(|_| addr)
}

/// The source address of a `receiving invite from <addr>:<port>` line.
fn invite_source_addr(rest: &str) -> Option<&str> {
    let after = rest.split_once("receiving invite from ")?.1;
    let token = after.split_whitespace().next()?;

    if let Some(inner) = token.strip_prefix('[') {
        let close = inner.find(']')?;
        let addr = &inner[..close];
        return addr.parse::<IpAddr>().ok().map(|_| addr);
    }

    let addr = token.rsplit_once(':').map(|(a, _)| a).unwrap_or(token);
    addr.parse::<IpAddr>().ok().map(|_| addr)
}

/// Rank deciding which kind sorts first when two spans start together; the more
/// specific kind wins, so a contained generic span follows its container.
fn kind_rank(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::ChannelName => 0,
        FieldKind::CallerIdName => 1,
        FieldKind::CallerIdNumber => 2,
        FieldKind::DestinationNumber => 3,
        FieldKind::CallId => 4,
        FieldKind::SipUri => 5,
        FieldKind::IpAddr => 6,
        FieldKind::Uuid => 7,
    }
}

/// Locate the fields a message carries, as ranges into `msg`.
///
/// Pure and stateless — usable on a [`RawLine::message`](crate::RawLine) without
/// the stream parser. Every range is at [`FieldLocation::Message`]; see
/// [`LogEntry::fields`](crate::LogEntry::fields) for an entry's attached lines.
///
/// Spans are ordered by start ascending then by width descending, so a
/// containing span always precedes the spans inside it. Ranges are never empty,
/// and never partially overlap.
pub fn message_fields(msg: &str) -> Vec<Field> {
    let mut out = Vec::new();
    collect_typed(msg, &mut out);

    // The generic scan runs last: a UUID already covered by a kind that names
    // what it is adds nothing, and the specific kind is the better rewrite.
    for (start, uuid) in find_uuids(msg) {
        let range = start..start + uuid.len();
        if !out.iter().any(|f: &Field| intersects(&f.range, &range)) {
            push(&mut out, FieldKind::Uuid, range);
        }
    }

    out.sort_by(|a, b| {
        (
            a.range.start,
            std::cmp::Reverse(a.range.end),
            kind_rank(a.kind),
        )
            .cmp(&(
                b.range.start,
                std::cmp::Reverse(b.range.end),
                kind_rank(b.kind),
            ))
    });
    out
}

fn intersects(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

fn push(out: &mut Vec<Field>, kind: FieldKind, range: Range<usize>) {
    if !range.is_empty() {
        out.push(Field {
            kind,
            at: FieldLocation::Message,
            range,
        });
    }
}

/// Emit a channel name plus the address nested in it, when it has one.
fn push_channel(out: &mut Vec<Field>, msg: &str, channel: &str) {
    let Some(range) = subslice_range(msg, channel) else {
        return;
    };
    if let Some(host) = channel_host_ip(channel).and_then(|h| subslice_range(msg, h)) {
        push(out, FieldKind::IpAddr, host);
    }
    push(out, FieldKind::ChannelName, range);
}

fn collect_typed(msg: &str, out: &mut Vec<Field>) {
    // Dispatch is classify_message's; this only re-runs the isolation each arm
    // already performed, to recover the offsets it dropped.
    match classify_message(msg) {
        MessageKind::Execute { .. } => push_channel(out, msg, execute_parts(msg).channel),
        MessageKind::Dialplan { .. } => collect_dialplan(msg, out),
        MessageKind::Variable { .. } => {
            if let Some(channel) = set_export_parts(msg).and_then(|p| p.channel) {
                push_channel(out, msg, channel);
            }
        }
        MessageKind::ChannelField { name, .. } => collect_channel_field(msg, &name, out),
        MessageKind::SipInvite { direction, .. } => collect_invite(msg, direction, out),
        MessageKind::StateChange { .. } | MessageKind::Media { .. } => {
            collect_channel_prefixed(msg, out);
        }
        MessageKind::ChannelLifecycle { .. } if !collect_channel_prefixed(msg, out) => {
            if let Some(channel) = hangup_channel(msg).or_else(|| new_channel_name(msg)) {
                push_channel(out, msg, channel);
            }
        }
        _ => {}
    }
}

/// The channel token of a `sofia/...`-prefixed line. Returns whether one was found.
fn collect_channel_prefixed(msg: &str, out: &mut Vec<Field>) -> bool {
    match strip_channel_prefix(msg) {
        Some((channel, _)) => {
            push_channel(out, msg, channel);
            true
        }
        None => match paren_channel(msg) {
            Some(channel) => {
                push_channel(out, msg, channel);
                true
            }
            None => false,
        },
    }
}

fn collect_dialplan(msg: &str, out: &mut Vec<Field>) {
    if msg.starts_with("Dialplan: ") || msg.starts_with("Chatplan: ") {
        push_channel(out, msg, dialplan_parts(msg).0);
        return;
    }
    // The bracketless `from->to` shape names no display name, so `head` stays
    // unclassified rather than being guessed at.
    if let Some(parts) = processing_parts(msg) {
        if let Some(name) = parts.name {
            push(out, FieldKind::CallerIdName, name);
        }
        if let Some(number) = parts.number {
            push(out, FieldKind::CallerIdNumber, number);
        }
        push(out, FieldKind::DestinationNumber, parts.dest);
    }
}

fn collect_channel_field(msg: &str, name: &str, out: &mut Vec<Field>) {
    let kind = match name {
        "Channel-Name" => FieldKind::ChannelName,
        "Caller-Caller-ID-Name" => FieldKind::CallerIdName,
        "Caller-Caller-ID-Number" => FieldKind::CallerIdNumber,
        "Caller-Destination-Number" => FieldKind::DestinationNumber,
        _ => return,
    };
    let Some((_, value)) = parse_bracketed_value(msg, 0) else {
        return;
    };
    if kind == FieldKind::ChannelName {
        push_channel(out, msg, value);
    } else if let Some(range) = subslice_range(msg, value) {
        push(out, kind, range);
    }
}

fn collect_invite(msg: &str, direction: SipInviteDirection, out: &mut Vec<Field>) {
    let Some((channel, rest)) = strip_channel_prefix(msg) else {
        return;
    };
    push_channel(out, msg, channel);

    if sip_invite_direction(rest).is_none() {
        return;
    }
    if let Some(range) = crate::message::call_id_token(rest).and_then(|t| subslice_range(msg, t)) {
        push(out, FieldKind::CallId, range);
    }
    if direction == SipInviteDirection::Receiving {
        if let Some(range) = invite_source_addr(rest).and_then(|a| subslice_range(msg, a)) {
            push(out, FieldKind::IpAddr, range);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(msg: &str) -> ProcessingParts {
        processing_parts(msg).expect("should parse")
    }

    /// The `(kind, text)` pairs a message yields, in span order.
    fn spans(msg: &str) -> Vec<(FieldKind, &str)> {
        message_fields(msg)
            .into_iter()
            .map(|f| (f.kind, &msg[f.range]))
            .collect()
    }

    #[test]
    fn bracketed_shape_keeps_number_in_head() {
        let msg = "Processing ACME <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "ACME <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
        assert_eq!(&msg[p.context], "public");
    }

    #[test]
    fn name_containing_arrow_and_angle_survives_anchoring() {
        let msg = "Processing a->b <c <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "a->b <c <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn bare_shape_falls_back_to_last_arrow() {
        let msg = "Processing 15555550100->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "15555550100");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn multibyte_name_keeps_spans_on_char_boundaries() {
        let msg = "Processing Jérôme <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "Jérôme <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn context_stops_at_first_whitespace() {
        let msg = "Processing ACME <15555550100>->1263 in context public extra";
        let p = parts(msg);
        assert_eq!(&msg[p.context], "public");
    }

    #[test]
    fn rightmost_in_context_wins() {
        let msg = "Processing a in context b <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.context], "public");
        assert_eq!(&msg[p.head], "a in context b <15555550100>");
    }

    #[test]
    fn no_context_marker_yields_none() {
        assert!(processing_parts("Processing ACME <15555550100>->1263").is_none());
    }

    #[test]
    fn processing_splits_name_and_number() {
        let msg = "Processing ACME <15555550100>->1263 in context public";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::CallerIdName, "ACME"),
                (FieldKind::CallerIdNumber, "15555550100"),
                (FieldKind::DestinationNumber, "1263"),
            ]
        );
    }

    #[test]
    fn processing_numeric_display_name_is_still_a_name() {
        let msg = "Processing 1263 <1263>->start_recording in context recordings";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::CallerIdName, "1263"),
                (FieldKind::CallerIdNumber, "1263"),
                (FieldKind::DestinationNumber, "start_recording"),
            ]
        );
    }

    #[test]
    fn processing_empty_name_yields_no_name_span() {
        let msg = "Processing  <15555550100>->1263 in context public";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::CallerIdNumber, "15555550100"),
                (FieldKind::DestinationNumber, "1263"),
            ]
        );
    }

    #[test]
    fn processing_bare_shape_emits_only_destination() {
        let msg = "Processing 15555550100->1263 in context public";
        assert_eq!(spans(msg), [(FieldKind::DestinationNumber, "1263")]);
    }

    #[test]
    fn execute_emits_channel_and_its_host() {
        let msg = "EXECUTE [depth=0] sofia/internal/+15555550100@192.0.2.1 answer";
        assert_eq!(
            spans(msg),
            [
                (
                    FieldKind::ChannelName,
                    "sofia/internal/+15555550100@192.0.2.1"
                ),
                (FieldKind::IpAddr, "192.0.2.1"),
            ]
        );
    }

    #[test]
    fn execute_without_channel_emits_nothing() {
        assert_eq!(spans("Execute [depth=2] set(RECORD_STEREO=true)"), []);
    }

    #[test]
    fn dialplan_emits_channel() {
        let msg = "Dialplan: sofia/internal/1263@192.0.2.1 parsing [public->global] continue=true";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.1"),
            ]
        );
    }

    #[test]
    fn set_emits_channel_but_export_does_not() {
        let msg = "SET sofia/internal/1263@192.0.2.1 [ngcs_bridge]=[host.example.test]";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.1"),
            ]
        );
        assert_eq!(spans("EXPORT (export_vars) [originate_timeout]=[3600]"), []);
    }

    #[test]
    fn bracketed_ipv6_channel_host_excludes_brackets() {
        let msg = "SET sofia/internal-v6/1263@[2001:db8:2220:198::10] [x]=[y]";
        assert_eq!(
            spans(msg),
            [
                (
                    FieldKind::ChannelName,
                    "sofia/internal-v6/1263@[2001:db8:2220:198::10]"
                ),
                (FieldKind::IpAddr, "2001:db8:2220:198::10"),
            ]
        );
    }

    #[test]
    fn channel_host_with_port_strips_it() {
        let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1:5060 answer";
        assert_eq!(spans(msg)[1], (FieldKind::IpAddr, "192.0.2.1"));
    }

    #[test]
    fn hostname_channel_host_is_not_an_address() {
        let msg = "EXECUTE [depth=0] sofia/internal/1263@host.example.test answer";
        assert_eq!(
            spans(msg),
            [(
                FieldKind::ChannelName,
                "sofia/internal/1263@host.example.test"
            )]
        );
    }

    #[test]
    fn receiving_invite_emits_call_id_and_source() {
        let msg = "sofia/internal/1263@192.0.2.1 receiving invite from 192.0.2.10:47215 version: 1.10.13 call-id: 00112233-4455-6677-8899-aabbccddeeff";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.10"),
                (FieldKind::CallId, "00112233-4455-6677-8899-aabbccddeeff"),
            ]
        );
    }

    #[test]
    fn call_id_that_is_a_uuid_suppresses_the_generic_span() {
        let msg = "sofia/internal/sos sending invite call-id: ffeeddcc-bbaa-9988-7766-554433221100";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::ChannelName, "sofia/internal/sos"),
                (FieldKind::CallId, "ffeeddcc-bbaa-9988-7766-554433221100"),
            ]
        );
    }

    #[test]
    fn null_call_id_emits_nothing() {
        let msg = "sofia/telus/15555550101 sending invite call-id: (null)";
        assert_eq!(
            spans(msg),
            [(FieldKind::ChannelName, "sofia/telus/15555550101")]
        );
    }

    #[test]
    fn sending_invite_has_no_source_address() {
        let msg = "sofia/telus/15555550101 sending invite version: 1.10.13 64bit";
        assert_eq!(
            spans(msg),
            [(FieldKind::ChannelName, "sofia/telus/15555550101")]
        );
    }

    #[test]
    fn paren_channel_state_line_emits_channel() {
        let msg = "(sofia/internal-v4/sos) Callstate Change RINGING -> ACTIVE";
        assert_eq!(
            spans(msg),
            [(FieldKind::ChannelName, "sofia/internal-v4/sos")]
        );
    }

    #[test]
    fn hangup_and_new_channel_emit_channel() {
        let hangup = "Hangup sofia/internal/1263@192.0.2.1 [CS_CONSUME_MEDIA] [NORMAL_CLEARING]";
        assert_eq!(spans(hangup)[0].1, "sofia/internal/1263@192.0.2.1");

        let new =
            "New Channel sofia/internal/1263@192.0.2.1 [00112233-4455-6677-8899-aabbccddeeff]";
        assert_eq!(
            spans(new),
            [
                (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.1"),
                (FieldKind::Uuid, "00112233-4455-6677-8899-aabbccddeeff"),
            ]
        );
    }

    #[test]
    fn channel_data_caller_fields_map_to_their_kinds() {
        assert_eq!(
            spans("Caller-Caller-ID-Number: [15555550100]"),
            [(FieldKind::CallerIdNumber, "15555550100")]
        );
        assert_eq!(
            spans("Caller-Caller-ID-Name: [ACME INC]"),
            [(FieldKind::CallerIdName, "ACME INC")]
        );
        assert_eq!(
            spans("Caller-Destination-Number: [1263]"),
            [(FieldKind::DestinationNumber, "1263")]
        );
        assert_eq!(
            spans("Channel-Name: [sofia/internal/1263@192.0.2.1]"),
            [
                (FieldKind::ChannelName, "sofia/internal/1263@192.0.2.1"),
                (FieldKind::IpAddr, "192.0.2.1"),
            ]
        );
    }

    #[test]
    fn unmapped_channel_field_emits_nothing() {
        assert_eq!(spans("Channel-State: [CS_EXECUTE]"), []);
    }

    #[test]
    fn unique_id_value_keeps_its_uuid_span() {
        let msg = "Unique-ID: [00112233-4455-6677-8899-aabbccddeeff]";
        assert_eq!(
            spans(msg),
            [(FieldKind::Uuid, "00112233-4455-6677-8899-aabbccddeeff")]
        );
    }

    #[test]
    fn multibyte_name_shifts_later_spans() {
        let msg = "Processing Jérôme <15555550100>->1263 in context public";
        assert_eq!(
            spans(msg),
            [
                (FieldKind::CallerIdName, "Jérôme"),
                (FieldKind::CallerIdNumber, "15555550100"),
                (FieldKind::DestinationNumber, "1263"),
            ]
        );
        for f in message_fields(msg) {
            assert!(msg.is_char_boundary(f.range.start) && msg.is_char_boundary(f.range.end));
        }
    }

    #[test]
    fn spans_are_ordered_container_first() {
        let msg = "EXECUTE [depth=0] sofia/internal/1263@192.0.2.1 answer";
        let fields = message_fields(msg);
        assert_eq!(fields[0].kind, FieldKind::ChannelName);
        assert!(fields[0].range.start <= fields[1].range.start);
        assert!(fields[1].range.end <= fields[0].range.end);
    }

    #[test]
    fn general_message_emits_nothing() {
        assert_eq!(spans("Activating RTCP PORT 4001"), []);
    }
}
