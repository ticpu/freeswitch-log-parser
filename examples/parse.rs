use std::io::{self, BufRead};

use freeswitch_log_parser::{LogStream, SessionTracker};

fn main() {
    let stdin = io::stdin();
    let lines = stdin.lock().lines().map(|l| l.expect("read error"));
    let stream = LogStream::new(lines);
    let mut tracker = SessionTracker::new(stream);
    let mut count = 0;

    for enriched in tracker.by_ref() {
        count += 1;
        let entry = &enriched.entry;
        let uuid = if entry.uuid.is_empty() {
            "-"
        } else {
            &entry.uuid
        };
        let level = entry
            .level
            .map(|l| l.to_string())
            .unwrap_or_else(|| "-".to_string());
        let time = if entry.timestamp.len() >= 11 {
            &entry.timestamp[11..]
        } else {
            &entry.timestamp
        };
        let n = entry.attached.len();
        let branch = if n > 0 { "┌" } else { "─" };

        let ctx = enriched
            .session
            .as_ref()
            .and_then(|s| s.dialplan_context.as_deref())
            .unwrap_or("");

        println!(
            "{kind:>9} {branch}  {level:>7} {time} {uuid} [{mkind}] {ctx} {msg}",
            kind = entry.kind,
            mkind = entry.message_kind,
            msg = entry.message,
        );

        if let Some(block) = &entry.block {
            match block {
                freeswitch_log_parser::Block::ChannelData { fields, variables } => {
                    println!(
                        "          block: channel-data ({} fields, {} vars)",
                        fields.len(),
                        variables.len(),
                    );
                }
                freeswitch_log_parser::Block::Sdp { direction, body } => {
                    println!("          block: sdp ({}, {} lines)", direction, body.len(),);
                }
            }
        }

        for (i, line) in entry.attached.iter().enumerate() {
            if i == 0 {
                println!("          ├─ ({n} attached)");
            }
            if i + 1 < n {
                println!("          │  {line}");
            } else {
                println!("          └─ {line}");
            }
        }
    }

    let stats = tracker.stats();
    eprintln!(
        "{count} entries, {} lines processed, {} unclassified",
        stats.lines_processed, stats.lines_unclassified,
    );
}
