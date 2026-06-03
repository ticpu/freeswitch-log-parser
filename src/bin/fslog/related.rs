use std::collections::HashSet;
use std::str::FromStr;
use std::sync::LazyLock;

use freeswitch_log_parser::{
    Block, LogEntry, LogStream, MessageKind, SessionTracker, TrackedChain,
};
use freeswitch_types::{BridgeDialString, ChannelVariable, DialString};
use regex::Regex;

use crate::output::FilterConfig;

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").expect("UUID regex")
});

/// Channel variables whose value is (or contains) a peer-leg UUID.
static UUID_BEARING_VARS: &[ChannelVariable] = &[
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

fn is_peer_uuid_var(name: &str) -> bool {
    ChannelVariable::from_str(name)
        .map(|v| UUID_BEARING_VARS.contains(&v))
        .unwrap_or(false)
}

fn harvest_uuids(value: &str, collector: &mut HashSet<String>) {
    for mat in UUID_RE.find_iter(value) {
        collector.insert(mat.as_str().to_string());
    }
}

/// Harvest peer-leg UUIDs from a parsed entry's structured variable
/// assignments only — never from raw message/attached text, which would pull
/// shared-context vars (domain_uuid, extension_uuid) and match unrelated calls.
fn extract_peer_uuids(entry: &LogEntry, collector: &mut HashSet<String>) {
    if let Some(Block::ChannelData { variables, .. }) = &entry.block {
        for (raw_name, value) in variables {
            let name = raw_name.strip_prefix("variable_").unwrap_or(raw_name);
            if is_peer_uuid_var(name) {
                harvest_uuids(value, collector);
            }
        }
    }
    match &entry.message_kind {
        MessageKind::Variable { name, value } => {
            let name = name.strip_prefix("variable_").unwrap_or(name);
            if is_peer_uuid_var(name) {
                harvest_uuids(value, collector);
            }
        }
        MessageKind::Execute {
            application,
            arguments,
            ..
        } if matches!(application.as_str(), "set" | "export") => {
            if let Some((name, value)) = arguments.split_once('=') {
                if is_peer_uuid_var(name) {
                    harvest_uuids(value, collector);
                } else if name == "api_result" && value.starts_with("+OK ") {
                    // uuid_bridge API response: "+OK <bridged-uuid>".
                    harvest_uuids(value, collector);
                }
            }
        }
        MessageKind::Execute {
            application,
            arguments,
            ..
        } if application == "bridge" => {
            if let Ok(dial) = BridgeDialString::from_str(arguments) {
                if let Some(ep) = dial.groups().first().and_then(|g| g.first()) {
                    if let Some(uuid) = ep.variables().and_then(|v| v.get("origination_uuid")) {
                        collector.insert(uuid.to_string());
                    }
                }
            }
        }
        _ => {}
    }
}

/// Discovery pass: stream the logs once, collect the UUIDs of every session the
/// seed filter matches plus their bridged/transferred peer legs. The parser's
/// own `other_leg_uuid` tracking (originate success, bridge origination_uuid,
/// `Other-Leg-Unique-ID`) supplies peers the variable scan can't see.
pub fn discover(
    segments: Vec<(String, Box<dyn Iterator<Item = String>>)>,
    filter: &FilterConfig,
) -> HashSet<String> {
    let (chain, _) = TrackedChain::new(segments);
    let stream = LogStream::new(chain);
    let mut uuids = HashSet::new();
    let mut tracker = SessionTracker::new(stream);
    for enriched in tracker.by_ref() {
        if !filter.matches(&enriched.entry) {
            continue;
        }
        if !enriched.entry.uuid.is_empty() {
            uuids.insert(enriched.entry.uuid.clone());
        }
        extract_peer_uuids(&enriched.entry, &mut uuids);
        if let Some(peer) = enriched
            .session
            .as_ref()
            .and_then(|s| s.other_leg_uuid.clone())
        {
            uuids.insert(peer);
        }
    }
    uuids
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeswitch_log_parser::{AttachedLines, LineKind};

    fn var_entry(name: &str, value: &str) -> LogEntry {
        LogEntry {
            uuid: "self".to_string(),
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: String::new(),
            kind: LineKind::Full,
            message_kind: MessageKind::Variable {
                name: name.to_string(),
                value: value.to_string(),
            },
            block: None,
            attached: AttachedLines::new(),
            line_number: 0,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn harvests_from_whitelisted_var() {
        let mut set = HashSet::new();
        let peer = "11111111-2222-3333-4444-555555555555";
        extract_peer_uuids(&var_entry("bridge_uuid", peer), &mut set);
        assert!(set.contains(peer));
    }

    #[test]
    fn ignores_non_peer_var() {
        let mut set = HashSet::new();
        let other = "11111111-2222-3333-4444-555555555555";
        extract_peer_uuids(&var_entry("domain_uuid", other), &mut set);
        assert!(set.is_empty());
    }
}
