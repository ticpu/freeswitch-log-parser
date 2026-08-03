use std::collections::HashSet;

use freeswitch_log_parser::{for_each_peer_uuid_with, LogStream, SessionTracker, TrackedChain};

use crate::output::FilterConfig;

/// Variable names this deployment treats as peer-bearing on top of the vanilla
/// set. `api_result` is where a Lua `uuid_bridge` lands its `+OK <uuid>` reply —
/// a dialplan-chosen name, so it belongs here rather than in the parser.
fn extra_peer_var(name: &str) -> bool {
    name == "api_result"
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
        for_each_peer_uuid_with(&enriched.entry, extra_peer_var, |uuid| {
            uuids.insert(uuid.to_string());
        });
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
    use freeswitch_log_parser::{AttachedLines, LineKind, LogEntry, MessageKind};

    const PEER: &str = "11111111-2222-3333-4444-555555555555";

    fn set_entry(name: &str, value: &str) -> LogEntry {
        LogEntry {
            uuid: "self".to_string(),
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: String::new(),
            kind: LineKind::Full,
            message_kind: MessageKind::Execute {
                depth: 0,
                channel: "sofia/internal/1001".to_string(),
                application: "set".to_string(),
                arguments: format!("{name}={value}"),
            },
            block: None,
            attached: AttachedLines::new(),
            line_number: 0,
            warnings: Vec::new(),
        }
    }

    fn collect(entry: &LogEntry) -> Vec<String> {
        let mut out = Vec::new();
        for_each_peer_uuid_with(entry, extra_peer_var, |u| out.push(u.to_string()));
        out
    }

    #[test]
    fn api_result_is_harvested_here_not_in_the_parser() {
        let entry = set_entry("api_result", &format!("+OK {PEER}"));
        assert_eq!(collect(&entry), vec![PEER]);

        let mut vanilla = Vec::new();
        freeswitch_log_parser::for_each_peer_uuid(&entry, |u| vanilla.push(u.to_string()));
        assert!(vanilla.is_empty());
    }

    #[test]
    fn vanilla_peer_var_still_harvested() {
        assert_eq!(collect(&set_entry("bridge_uuid", PEER)), vec![PEER]);
    }

    #[test]
    fn shared_context_var_stays_ignored() {
        assert!(collect(&set_entry("domain_uuid", PEER)).is_empty());
    }
}
