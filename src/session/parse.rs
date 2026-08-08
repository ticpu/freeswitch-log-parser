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

pub(super) fn parse_new_channel(detail: &str) -> Option<String> {
    new_channel_name(detail).map(str::to_string)
}

pub(super) fn parse_state_change(detail: &str) -> Option<String> {
    let arrow = detail.find(" -> ")?;
    Some(detail[arrow + 4..].trim().to_string())
}

pub(super) fn parse_hangup(detail: &str) -> Option<String> {
    if !detail.contains("Hangup ") {
        return None;
    }
    let start = detail.rfind('[')?;
    let end = detail[start..].find(']')?;
    Some(detail[start + 1..start + end].to_string())
}

pub(super) fn is_answered(detail: &str) -> bool {
    detail.contains("has been answered")
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

/// Parse "Originate Resulted in Success: [channel] Peer UUID: uuid"
pub(super) fn parse_originate_success(msg: &str) -> Option<String> {
    let marker = "Peer UUID: ";
    let idx = msg.find(marker)?;
    let uuid = msg[idx + marker.len()..].trim();
    if uuid.is_empty() {
        None
    } else {
        Some(uuid.to_string())
    }
}

/// Parse the bracketed channel name from "Originate Resulted in Success: [<chan>] …".
/// Used as a fallback when the `Peer UUID:` suffix is absent (FS 1.10.5-dev and
/// similar builds). Returns the channel name borrowed from `msg`.
pub(super) fn parse_originate_channel(msg: &str) -> Option<&str> {
    let start = msg.find(" [")? + 2;
    let end = msg[start..].find(']')?;
    let chan = &msg[start..start + end];
    if chan.is_empty() {
        None
    } else {
        Some(chan)
    }
}

/// Terminal channel-/callstate values — sessions left in one of these are
/// stragglers from prior calls and must not be considered candidates when
/// disambiguating channel-name collisions in the originate-success fallback.
///
/// Covers both `Channel-State` (`CS_*`) and `Callstate` (`HANGUP`). `DOWN` is
/// excluded because it doubles as the initial Callstate before any change is
/// observed.
pub(super) fn is_terminal_channel_state(state: Option<&str>) -> bool {
    matches!(
        state,
        Some("CS_HANGUP" | "CS_REPORTING" | "CS_DESTROY" | "CS_NONE" | "HANGUP")
    )
}
