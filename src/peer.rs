//! Peer-leg UUID harvesting: which channel variables name another leg of the
//! same call, and how to pull those UUIDs out of a parsed entry.
//!
//! Distinct from [`SessionState::other_leg_uuid`](crate::SessionState::other_leg_uuid),
//! which tracks the one authoritative peer of a session as it evolves. This
//! harvests every peer a single entry mentions, which is what a "show me this
//! call and everything it bridged to" search needs to seed itself.

use std::str::FromStr;

use freeswitch_types::ChannelVariable;

use crate::message::MessageKind;
use crate::session::parse_bridge_args;
use crate::stream::{Block, LogEntry};
use crate::uuid::find_uuids;

/// Channel variables whose value is, or contains, a peer leg's UUID.
pub const PEER_UUID_VARS: &[ChannelVariable] = &[
    ChannelVariable::BridgeUuid,
    ChannelVariable::SignalBond,
    ChannelVariable::SignalBridge,
    ChannelVariable::LastBridgeTo,
    ChannelVariable::OriginatingLegUuid,
    ChannelVariable::OriginationUuid,
    ChannelVariable::OriginatedLegs,
    ChannelVariable::TransferSource,
    ChannelVariable::TransferHistory,
];

/// Whether `name` is one of [`PEER_UUID_VARS`]. Accepts the bare variable name;
/// strip any `variable_` prefix first.
pub fn is_peer_uuid_var(name: &str) -> bool {
    ChannelVariable::from_str(name)
        .map(|v| PEER_UUID_VARS.contains(&v))
        .unwrap_or(false)
}

/// Call `f` with every peer-leg UUID `entry` mentions.
///
/// See [`for_each_peer_uuid_with`]; this recognizes only vanilla FreeSWITCH
/// variables.
pub fn for_each_peer_uuid<F: FnMut(&str)>(entry: &LogEntry, f: F) {
    for_each_peer_uuid_with(entry, |_| false, f);
}

/// Call `f` with every peer-leg UUID `entry` mentions, treating a variable as
/// peer-bearing when it is in [`PEER_UUID_VARS`] or `extra_var` accepts its name.
///
/// Walks only structured variable assignments — `CHANNEL_DATA` fields, standalone
/// variable lines, `set`/`export`/`bridge` executions. Scanning the raw message
/// and attached text instead would harvest shared-context variables (a FusionPBX
/// `domain_uuid`, say) and pull in every unrelated call in the same tenant.
pub fn for_each_peer_uuid_with<F: FnMut(&str)>(
    entry: &LogEntry,
    extra_var: impl Fn(&str) -> bool,
    mut f: F,
) {
    let wanted = |name: &str| {
        let name = name.strip_prefix("variable_").unwrap_or(name);
        is_peer_uuid_var(name) || extra_var(name)
    };
    let mut harvest = |value: &str| {
        for (_, uuid) in find_uuids(value) {
            f(uuid);
        }
    };

    if let Some(Block::ChannelData { variables, .. }) = &entry.block {
        for (name, value) in variables {
            if wanted(name) {
                harvest(value);
            }
        }
    }

    match &entry.message_kind {
        MessageKind::Variable { name, value } => {
            if wanted(name) {
                harvest(value);
            }
        }
        MessageKind::Execute {
            application,
            arguments,
            ..
        } => match application.as_str() {
            "set" | "export" => {
                if let Some((name, value)) = arguments.split_once('=') {
                    if wanted(name) {
                        harvest(value);
                    }
                }
            }
            // The dial string's own `origination_uuid` names the leg this call is
            // about to create, before that leg logs anything of its own.
            "bridge" | "att_xfer" => {
                if let Some(uuid) = parse_bridge_args(arguments).and_then(|i| i.origination_uuid) {
                    f(&uuid);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attached::AttachedLines;
    use crate::line::LineKind;

    const PEER: &str = "11111111-2222-3333-4444-555555555555";

    fn entry(message_kind: MessageKind, block: Option<Block>) -> LogEntry {
        LogEntry {
            uuid: "self".to_string(),
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: String::new(),
            kind: LineKind::Full,
            message_kind,
            block,
            attached: AttachedLines::new(),
            line_number: 0,
            warnings: Vec::new(),
        }
    }

    fn var(name: &str, value: &str) -> LogEntry {
        entry(
            MessageKind::Variable {
                name: name.to_string(),
                value: value.to_string(),
            },
            None,
        )
    }

    fn collect(entry: &LogEntry) -> Vec<String> {
        let mut out = Vec::new();
        for_each_peer_uuid(entry, |u| out.push(u.to_string()));
        out
    }

    #[test]
    fn harvests_from_allowlisted_var() {
        assert_eq!(collect(&var("bridge_uuid", PEER)), vec![PEER]);
    }

    #[test]
    fn harvests_uppercase_hex() {
        let upper = "AAAABBBB-2222-3333-4444-5555CCCCDDDD";
        assert_eq!(collect(&var("bridge_uuid", upper)), vec![upper]);
    }

    #[test]
    fn ignores_shared_context_var() {
        assert!(collect(&var("domain_uuid", PEER)).is_empty());
    }

    #[test]
    fn strips_variable_prefix_in_channel_data() {
        let block = Block::ChannelData {
            fields: Vec::new(),
            variables: vec![("variable_signal_bond".to_string(), PEER.to_string())],
        };
        assert_eq!(
            collect(&entry(MessageKind::General, Some(block))),
            vec![PEER]
        );
    }

    #[test]
    fn harvests_from_set_and_bridge() {
        let set = entry(
            MessageKind::Execute {
                depth: 0,
                channel: "sofia/internal/1001".to_string(),
                application: "set".to_string(),
                arguments: format!("last_bridge_to={PEER}"),
            },
            None,
        );
        assert_eq!(collect(&set), vec![PEER]);

        let bridge = |args: String| {
            entry(
                MessageKind::Execute {
                    depth: 0,
                    channel: "sofia/internal/1001".to_string(),
                    application: "bridge".to_string(),
                    arguments: args,
                },
                None,
            )
        };
        // Per-endpoint `[]` scope and all-endpoint `{}` scope both name the leg.
        assert_eq!(
            collect(&bridge(format!(
                "[origination_uuid={PEER}]sofia/gateway/gw/5551234"
            ))),
            vec![PEER]
        );
        assert_eq!(
            collect(&bridge(format!(
                "{{origination_uuid={PEER}}}sofia/gateway/gw/5551234"
            ))),
            vec![PEER]
        );
    }

    #[test]
    fn att_xfer_names_its_leg_the_same_way() {
        let e = entry(
            MessageKind::Execute {
                depth: 0,
                channel: "sofia/internal/1001".to_string(),
                application: "att_xfer".to_string(),
                arguments: format!("[origination_uuid={PEER}]sofia/internal/1002"),
            },
            None,
        );
        assert_eq!(collect(&e), vec![PEER]);
    }

    #[test]
    fn extra_var_extends_the_allowlist() {
        let e = var("my_deployment_peer_id", PEER);
        assert!(collect(&e).is_empty());

        let mut out = Vec::new();
        for_each_peer_uuid_with(
            &e,
            |n| n == "my_deployment_peer_id",
            |u| out.push(u.to_string()),
        );
        assert_eq!(out, vec![PEER]);
    }

    #[test]
    fn harvests_every_uuid_in_a_multi_valued_var() {
        let second = "aaaabbbb-cccc-dddd-eeee-ffff00001111";
        let e = var("originated_legs", &format!("{PEER},{second}"));
        assert_eq!(collect(&e), vec![PEER, second]);
    }
}
