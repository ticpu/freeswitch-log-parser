//! Locating the spans a message carries, by re-running the isolation each
//! classification arm already performed.

use std::net::IpAddr;
use std::ops::Range;
use std::str::FromStr;

use freeswitch_types::ChannelVariable;

use crate::message::{
    classify_message, dialplan_parts, execute_parts, hangup_channel,
    is_channel_variable_narration, new_channel_name, paren_channel, parse_bracketed_value,
    set_export_parts, sip_invite_direction, strip_channel_prefix, MessageKind, SipInviteDirection,
};
use crate::uuid::find_uuids;

use super::kind::{kind_rank, Field, FieldKind, FieldLocation};
use super::processing::processing_parts;
use super::subslice_range;

/// The address inside a `[...]`-bracketed literal, when valid. Shared by
/// `channel_host_ip` and `invite_source_addr`, whose unbracketed fallbacks
/// differ (see their doc comments) and stay separate.
fn bracketed_ip(token: &str) -> Option<&str> {
    let inner = token.strip_prefix('[')?;
    let close = inner.find(']')?;
    let addr = &inner[..close];
    addr.parse::<IpAddr>().ok().map(|_| addr)
}

/// The host of a channel name, when it is a literal address rather than a
/// hostname. Handles the bracketed IPv6 form and a trailing port.
fn channel_host_ip(channel: &str) -> Option<&str> {
    let host = channel.rsplit_once('@')?.1;

    if host.starts_with('[') {
        return bracketed_ip(host);
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
///
/// Unlike `channel_host_ip`, the unbracketed form always strips a trailing
/// `:port` before parsing (SIP always logs source as `addr:port`), so a bare
/// unbracketed IPv6 host — all colons, no port to strip — is not accepted here.
fn invite_source_addr(rest: &str) -> Option<&str> {
    let after = rest.split_once("receiving invite from ")?.1;
    let token = after.split_whitespace().next()?;

    if token.starts_with('[') {
        return bracketed_ip(token);
    }

    let addr = token.rsplit_once(':').map(|(a, _)| a).unwrap_or(token);
    addr.parse::<IpAddr>().ok().map(|_| addr)
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

    // The generic scan runs last: a UUID covered by a kind that names its shape
    // adds nothing — but a value slot names none, so a UUID nests inside it.
    for (start, uuid) in find_uuids(msg) {
        let range = start..start + uuid.len();
        let covered = out
            .iter()
            .any(|f: &Field| f.kind != FieldKind::VariableValue && intersects(&f.range, &range));
        if !covered {
            push(&mut out, FieldKind::Uuid, range);
        }
    }

    sort_spans(&mut out);
    out
}

/// Order by start ascending then width descending, so a containing span
/// always precedes the spans inside it.
fn sort_spans(fields: &mut [Field]) {
    fields.sort_by(|a, b| {
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
}

fn intersects(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Locate the fields of one raw physical line — an attached line, prefix and all.
///
/// `parse_line`'s message is always a suffix of the line it parsed, so the
/// header width is the length difference; deriving it that way keeps the
/// branches that hand back a `""` literal harmless, where taking the message's
/// address would not.
pub(super) fn raw_line_fields(line: &str, at: FieldLocation) -> Vec<Field> {
    let message = crate::line::parse_line(line).message;
    debug_assert!(line.ends_with(message), "message is a suffix of its line");
    let offset = line.len() - message.len();

    let mut out: Vec<Field> = message_fields(message)
        .into_iter()
        .map(|f| Field {
            kind: f.kind,
            at,
            range: f.range.start + offset..f.range.end + offset,
        })
        .collect();

    // The session UUID sits in the header the message excludes.
    for (start, uuid) in find_uuids(&line[..offset]) {
        out.push(Field {
            kind: FieldKind::Uuid,
            at,
            range: start..start + uuid.len(),
        });
    }

    sort_spans(&mut out);
    out
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

/// The slot a variable's name names; a name outside the identity vocabulary
/// falls to the neutral value slot rather than going unspanned.
fn variable_value_kind(name: &str) -> FieldKind {
    let bare = name.strip_prefix("variable_").unwrap_or(name);
    match ChannelVariable::from_str(bare) {
        Ok(ChannelVariable::CallerIdName)
        | Ok(ChannelVariable::EffectiveCallerIdName)
        | Ok(ChannelVariable::OriginationCallerIdName) => FieldKind::CallerIdName,
        Ok(ChannelVariable::CallerIdNumber)
        | Ok(ChannelVariable::EffectiveCallerIdNumber)
        | Ok(ChannelVariable::OriginationCallerIdNumber) => FieldKind::CallerIdNumber,
        Ok(ChannelVariable::DestinationNumber) => FieldKind::DestinationNumber,
        _ => FieldKind::VariableValue,
    }
}

/// The channel and value spans of a Variable-classified message, re-running the
/// isolation of whichever shape classify_message read it as.
fn collect_variable(msg: &str, name: &str, out: &mut Vec<Field>) {
    let push_value = |out: &mut Vec<Field>, value: &str| {
        if let Some(range) = subslice_range(msg, value) {
            push(out, variable_value_kind(name), range);
        }
    };
    if msg.starts_with("variable_") {
        if let Some((_, value)) = parse_bracketed_value(msg, 0) {
            push_value(out, value);
        }
        return;
    }
    if let Some((channel, rest)) = strip_channel_prefix(msg) {
        if is_channel_variable_narration(rest) {
            if let Some(parts) = set_export_parts(rest) {
                push_channel(out, msg, channel);
                push_value(out, parts.value);
            }
        }
        return;
    }
    if msg.starts_with("SET ")
        || msg.starts_with("EXPORT ")
        || msg.starts_with("PUSH ")
        || msg.starts_with("UNSHIFT ")
    {
        if let Some(parts) = set_export_parts(msg) {
            if let Some(channel) = parts.channel {
                push_channel(out, msg, channel);
            }
            push_value(out, parts.value);
        }
        return;
    }
    if let Some(rest) = msg.strip_prefix("CoreSession::setVariable(") {
        if let Some(inner) = rest.strip_suffix(')') {
            if let Some(comma) = inner.find(", ") {
                push_value(out, &inner[comma + 2..]);
            }
        }
        return;
    }
    if let Some(rest) = msg.strip_prefix("set variable ") {
        if let Some((_, value)) = rest.split_once('=') {
            push_value(out, value);
        }
    }
}

fn collect_typed(msg: &str, out: &mut Vec<Field>) {
    // Dispatch is classify_message's; this only re-runs the isolation each arm
    // already performed, to recover the offsets it dropped.
    match classify_message(msg) {
        MessageKind::Execute { .. } => push_channel(out, msg, execute_parts(msg).channel),
        MessageKind::Dialplan { .. } => collect_dialplan(msg, out),
        MessageKind::Variable { name, .. } => collect_variable(msg, &name, out),
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
