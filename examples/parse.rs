use std::io;

use freeswitch_log_parser::{read_log_lines, LogStream, SessionTracker};

fn main() {
    let lines = read_log_lines(io::stdin().lock()).map(|d| d.expect("read error").text);
    let stream = LogStream::new(lines);
    let mut tracker = SessionTracker::new(stream);
    let mut count = 0;

    for enriched in tracker.by_ref() {
        count += 1;
        let entry = &enriched.entry;
        let uuid = entry.uuid.as_deref().unwrap_or("-");
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
                    println!("          block: sdp ({}, {} lines)", direction, body.len());
                }
                freeswitch_log_parser::Block::CodecNegotiation {
                    media,
                    comparisons,
                    matched,
                    near_matched,
                } => {
                    println!(
                        "          block: codec-negotiation {media} ({} cmp, {} matched, {} near)",
                        comparisons.len(),
                        matched.len(),
                        near_matched.len(),
                    );
                }
                _ => {
                    println!("          block: {block:?}");
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
