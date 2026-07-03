use std::io;

use freeswitch_log_parser::{read_log_lines, LogStream, MessageKind, SessionTracker};

fn main() {
    let lines = read_log_lines(io::stdin().lock()).map(|d| d.expect("read error").text);
    let stream = LogStream::new(lines);

    let mut tracker = SessionTracker::new(stream).with_post_hook(|entry, state| {
        if state.other_leg_uuid.is_some() {
            return;
        }

        if let MessageKind::Execute {
            application,
            arguments,
            ..
        } = &entry.message_kind
        {
            if application == "set" {
                if let Some(value) = arguments.strip_prefix("api_result=+OK ") {
                    let uuid = value.split_whitespace().next().unwrap_or("");
                    if uuid.len() == 36 {
                        state.other_leg_uuid = Some(uuid.to_string());
                    }
                }
            }
        }

        if let Some(uuid) = state.variables.get("sip_h_X-Custom-Peer-UUID") {
            if uuid.len() == 36 {
                state.other_leg_uuid = Some(uuid.clone());
            }
        }
    });

    let mut count = 0;
    for enriched in tracker.by_ref() {
        count += 1;
        let entry = &enriched.entry;
        let uuid = if entry.uuid.is_empty() {
            "-"
        } else {
            &entry.uuid
        };

        let other_leg = enriched
            .session
            .as_ref()
            .and_then(|s| s.other_leg_uuid.as_deref())
            .unwrap_or("-");

        println!(
            "{uuid} [{kind}] other_leg={other_leg} {msg}",
            kind = entry.message_kind,
            msg = entry.message,
        );
    }

    let stats = tracker.stats();
    eprintln!(
        "{count} entries, {} lines processed, {} unclassified",
        stats.lines_processed, stats.lines_unclassified,
    );
}
