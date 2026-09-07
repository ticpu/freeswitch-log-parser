//! Message shapes the tracker reads out of dialplan, originate and bridge lines.

use std::str::FromStr;

use freeswitch_types::{BridgeDialString, DialString};

use crate::fields::processing_parts;
use crate::message::new_channel_name;

pub(super) struct DialplanContext {
    pub(super) from: String,
    pub(super) to: String,
    pub(super) context: String,
}

/// The context of a `parsing [<context>-><extension>]` line.
///
/// The extension is deliberately dropped: it names a dialplan entry point, not
/// the dialed number `dialplan_to` carries, and folding the two into one field
/// left it meaning whichever shape was logged last.
pub(super) fn parse_dialplan_context(detail: &str) -> Option<&str> {
    let rest = detail.strip_prefix("parsing [")?;
    let bracket_end = rest.find(']')?;
    let inner = &rest[..bracket_end];
    let arrow = inner.find("->")?;
    Some(&inner[..arrow])
}

pub(super) fn parse_processing_line(msg: &str) -> Option<DialplanContext> {
    let parts = processing_parts(msg)?;
    Some(DialplanContext {
        from: msg[parts.head].to_string(),
        to: msg[parts.dest].to_string(),
        context: msg[parts.context].to_string(),
    })
}

pub(super) fn parse_new_channel(detail: &str) -> Option<&str> {
    new_channel_name(detail)
}

/// Which of the two state vocabularies a `... Change <old> -> <new>` line speaks.
pub(super) enum StateChange<'a> {
    Channel(&'a str),
    Call(&'a str),
}

/// The new state a change line moves to. `Callstate Change` and `State Change`
/// are distinct markers, so the two vocabularies never have to share a slot.
pub(super) fn parse_state_change(detail: &str) -> Option<StateChange<'_>> {
    let arrow = detail.find(" -> ")?;
    let to = detail[arrow + 4..].trim();
    if detail.contains("Callstate Change") {
        Some(StateChange::Call(to))
    } else {
        Some(StateChange::Channel(to))
    }
}

/// The cause in the last bracket of a `Hangup <channel> [<state>] [<cause>]`
/// detail. The line's shape is the classifier's finding, not this one's.
pub(super) fn parse_hangup(detail: &str) -> Option<&str> {
    let start = detail.rfind('[')?;
    let end = detail[start..].find(']')?;
    Some(&detail[start + 1..start + end])
}

/// Extract `origination_uuid` and the bridge target channel from bridge() arguments.
/// Uses `BridgeDialString` from freeswitch-types for correct parsing of `[]`, `{}`,
/// `|` failover, and `,` simultaneous ring syntax.
///
/// Returns `None` when the arguments do not parse as a dial string or name no
/// endpoint at all.
pub fn parse_bridge_args(arguments: &str) -> Option<BridgeInfo> {
    let dial = BridgeDialString::from_str(arguments).ok()?;
    let first_ep = dial.groups().first()?.first()?;
    // `{}` variables apply to every endpoint, so a single-leg bridge can name
    // the new leg's UUID there instead of in the endpoint's own `[]`.
    let origination_uuid = first_ep
        .variables()
        .and_then(|v| v.get("origination_uuid"))
        .or_else(|| dial.variables().and_then(|v| v.get("origination_uuid")))
        .map(|s| s.to_string());
    let mut bare = first_ep.clone();
    bare.set_variables(None);
    let target_channel = bare.to_string();
    Some(BridgeInfo {
        origination_uuid,
        target_channel,
    })
}

/// What a `bridge()` argument list says about the leg it is about to create.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeInfo {
    /// The UUID the new leg is being forced to take, when the dial string sets one.
    pub origination_uuid: Option<String>,
    /// The first endpoint with its `{}`/`[]` variables removed, matching the form
    /// the new channel will report as its channel name.
    pub target_channel: String,
}
