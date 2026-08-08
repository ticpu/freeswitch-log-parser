use std::collections::{HashMap, HashSet};

use freeswitch_log_parser::{for_each_peer_uuid_with, LogStream, SessionTracker, TrackedChain};

use crate::output::FilterConfig;

/// Variable names this deployment treats as peer-bearing on top of the vanilla
/// set. `api_result` is where a Lua `uuid_bridge` lands its `+OK <uuid>` reply —
/// a dialplan-chosen name, so it belongs here rather than in the parser.
fn extra_peer_var(name: &str) -> bool {
    name == "api_result"
}

/// Discovery pass: stream the logs once, collect the UUIDs of every session the
/// seed filter matches plus their bridged/transferred peer legs and conference
/// mates. The parser's own `other_leg_uuid` tracking (originate success, bridge
/// origination_uuid, `Other-Leg-Unique-ID`) supplies peers the variable scan
/// can't see.
pub fn discover(
    segments: Vec<(String, Box<dyn Iterator<Item = String>>)>,
    filter: &FilterConfig,
) -> HashSet<String> {
    let (chain, _) = TrackedChain::new(segments);
    let stream = LogStream::new(chain);
    let mut uuids = HashSet::new();
    // A conference mate may join long after the seed's own entries, and the
    // tracker drops an instance once it empties, so membership is accumulated
    // over the whole pass and unioned at the end rather than queried inline.
    let mut members: HashMap<String, HashSet<String>> = HashMap::new();
    let mut wanted_instances: HashSet<String> = HashSet::new();
    let mut tracker = SessionTracker::new(stream);
    for enriched in tracker.by_ref() {
        let instance = enriched
            .session
            .as_ref()
            .and_then(|s| s.conference.as_ref())
            .map(|c| c.instance.clone());
        if let Some(instance) = &instance {
            if let Some(uuid) = &enriched.entry.uuid {
                members
                    .entry(instance.clone())
                    .or_default()
                    .insert(uuid.clone());
            }
        }
        if !filter.matches(&enriched.entry) {
            continue;
        }
        if let Some(instance) = instance {
            wanted_instances.insert(instance);
        }
        if let Some(uuid) = &enriched.entry.uuid {
            uuids.insert(uuid.clone());
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
    // A mate's own peer leg belongs to the conference's call graph as much as
    // the mate does — a loopback joins the conference on its A leg while the
    // work happens on the B leg, which never executes `conference` itself.
    let sessions = tracker.sessions();
    for instance in &wanted_instances {
        for mate in members.get(instance).into_iter().flatten() {
            if let Some(peer) = sessions.get(mate).and_then(|s| s.other_leg_uuid.clone()) {
                uuids.insert(peer);
            }
            uuids.insert(mate.clone());
        }
    }
    uuids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::FilterParams;
    use freeswitch_log_parser::{LogEntry, MessageKind};

    const PEER: &str = "11111111-2222-3333-4444-555555555555";
    const A_LEG: &str = "aaaaaaaa-1111-2222-3333-444444444444";
    const B_LEG: &str = "bbbbbbbb-1111-2222-3333-444444444444";

    fn set_entry(name: &str, value: &str) -> LogEntry {
        LogEntry {
            uuid: Some("self".to_string()),
            message_kind: MessageKind::Execute {
                depth: 0,
                channel: "sofia/internal/1001".to_string(),
                application: "set".to_string(),
                arguments: format!("{name}={value}"),
            },
            ..LogEntry::synthetic(String::new())
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

    fn full_line(uuid: &str, msg: &str) -> String {
        format!("{uuid} 2026-03-08 16:52:07.123456 95.97% [DEBUG] sofia.c:100 {msg}")
    }

    fn discover_from(lines: Vec<String>, seed: &str) -> HashSet<String> {
        let filter = FilterConfig::new(FilterParams {
            uuid: vec![seed.to_string()],
            ..Default::default()
        })
        .expect("seed builds a matcher");
        let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> =
            vec![("test.log".to_string(), Box::new(lines.into_iter()))];
        discover(segments, &filter.for_discovery())
    }

    #[test]
    fn discovers_peers_from_both_the_variable_scan_and_the_tracker() {
        let found = discover_from(
            vec![
                full_line(
                    A_LEG,
                    &format!("EXECUTE [depth=0] sofia/internal/1001 bridge([origination_uuid={B_LEG}]sofia/gateway/gw/5551234)"),
                ),
                full_line(A_LEG, &format!("Originate Resulted in Success: [sofia/gateway/gw/5551234] Peer UUID: {PEER}")),
            ],
            A_LEG,
        );
        assert!(found.contains(A_LEG), "the seed itself");
        assert!(found.contains(B_LEG), "origination_uuid in the dial string");
        assert!(found.contains(PEER), "peer the tracker linked");
    }

    #[test]
    fn conference_mates_and_their_peer_legs_are_pulled_in() {
        const MATE: &str = "cccccccc-1111-2222-3333-444444444444";
        const MATE_PEER: &str = "dddddddd-1111-2222-3333-444444444444";
        let found = discover_from(
            vec![
                format!("{A_LEG} EXECUTE [depth=0] pulseaudio/0000000000 conference(835)"),
                format!("{MATE} EXECUTE [depth=0] loopback/tty-a conference(835)"),
                full_line(MATE, "New Channel loopback/tty-a [ignored]"),
                full_line(MATE_PEER, "New Channel loopback/tty-b [ignored]"),
                format!("{PEER} EXECUTE [depth=0] sofia/internal/1002 conference(844)"),
            ],
            A_LEG,
        );
        assert!(found.contains(MATE), "same conference instance");
        assert!(found.contains(MATE_PEER), "the mate's loopback partner");
        assert!(!found.contains(PEER), "a different conference");
    }

    #[test]
    fn a_reused_conference_name_does_not_merge_instances() {
        const LATER: &str = "cccccccc-1111-2222-3333-444444444444";
        let found = discover_from(
            vec![
                format!("{A_LEG} EXECUTE [depth=0] pulseaudio/0000000000 conference(835)"),
                full_line(A_LEG, "Channel leaving conference, cause: NORMAL_CLEARING"),
                format!("{LATER} EXECUTE [depth=0] sofia/internal/1002 conference(835)"),
            ],
            A_LEG,
        );
        assert!(
            !found.contains(LATER),
            "a later conference of the same name"
        );
    }

    #[test]
    fn unrelated_sessions_are_not_pulled_in() {
        let found = discover_from(
            vec![
                full_line(A_LEG, "State Change CS_NEW -> CS_INIT"),
                full_line(
                    PEER,
                    &format!("EXECUTE [depth=0] sofia/internal/1002 set(domain_uuid={B_LEG})"),
                ),
            ],
            A_LEG,
        );
        assert_eq!(found, HashSet::from([A_LEG.to_string()]));
    }
}
