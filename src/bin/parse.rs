use std::io::{self, BufRead};

use clap::Parser;
use freeswitch_log_parser::{Block, LogStream, SessionTracker, UnclassifiedTracking};

#[derive(Parser)]
#[command(
    name = "freeswitch-log-parse",
    about = "Parse FreeSWITCH log files and report structure, blocks, sessions, and unclassified data"
)]
struct Cli {
    /// Show only summary statistics, no per-entry output
    #[arg(long)]
    stats: bool,

    /// Show typed block details (channel-data fields/vars, sdp lines)
    #[arg(long)]
    blocks: bool,

    /// Show per-entry session snapshot (dialplan context, channel state)
    #[arg(long)]
    session: bool,

    /// Report unclassified lines to stderr with content
    #[arg(long)]
    unclassified: bool,

    /// Filter by UUID prefix (case-insensitive substring match)
    #[arg(short, long, value_name = "UUID")]
    uuid: Option<String>,

    /// Filter by minimum log level (debug, info, notice, warning, err, crit, alert, console)
    #[arg(short, long, value_name = "LEVEL")]
    level: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let stdin = io::stdin();
    let lines = stdin.lock().lines().map(|l| l.expect("read error"));

    let tracking = if cli.unclassified {
        UnclassifiedTracking::CaptureData
    } else {
        UnclassifiedTracking::CountOnly
    };

    let min_level: Option<freeswitch_log_parser::LogLevel> = cli.level.as_ref().map(|l| {
        l.parse().unwrap_or_else(|_| {
            eprintln!("invalid log level: {l}");
            std::process::exit(2);
        })
    });

    let uuid_filter = cli.uuid.as_deref().map(|u| u.to_lowercase());

    let stream = LogStream::new(lines).unclassified_tracking(tracking);
    let mut tracker = SessionTracker::new(stream);
    let mut count: u64 = 0;

    for enriched in tracker.by_ref() {
        count += 1;
        let entry = &enriched.entry;

        if let Some(min) = min_level {
            if let Some(level) = entry.level {
                if level < min {
                    continue;
                }
            }
        }

        if let Some(ref filter) = uuid_filter {
            if !entry.uuid.to_lowercase().contains(filter) {
                continue;
            }
        }

        if cli.stats {
            continue;
        }

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

        println!(
            "L{line:>6} {kind:>9} {level:>7} {time} {uuid} [{mkind}] {msg}",
            line = entry.line_number,
            kind = entry.kind,
            mkind = entry.message_kind,
            msg = entry.message,
        );

        if cli.blocks {
            if let Some(block) = &entry.block {
                match block {
                    Block::ChannelData { fields, variables } => {
                        for (name, value) in fields {
                            println!("         field  {name}: {value}");
                        }
                        for (name, value) in variables {
                            let short = if value.len() > 80 {
                                format!("{}...", &value[..77])
                            } else {
                                value.clone()
                            };
                            println!("         var    {name}: {short}");
                        }
                    }
                    Block::Sdp { direction, body } => {
                        println!("         sdp    {direction} ({} lines)", body.len());
                        for line in body {
                            println!("         sdp    {line}");
                        }
                    }
                }
            }
        }

        if cli.session {
            if let Some(session) = &enriched.session {
                let mut parts = Vec::new();
                if let Some(ctx) = &session.dialplan_context {
                    parts.push(format!("ctx={ctx}"));
                }
                if let Some(state) = &session.channel_state {
                    parts.push(format!("state={state}"));
                }
                if let Some(name) = &session.channel_name {
                    parts.push(format!("ch={name}"));
                }
                if !parts.is_empty() {
                    println!("         session {}", parts.join(" "));
                }
            }
        }

        if !entry.attached.is_empty() {
            println!("         ({} attached lines)", entry.attached.len());
        }
    }

    let stats = tracker.stats();
    eprintln!(
        "{count} entries, {} lines, {} unclassified, {} sessions",
        stats.lines_processed,
        stats.lines_unclassified,
        tracker.sessions().len(),
    );

    if cli.unclassified && !stats.unclassified_lines.is_empty() {
        eprintln!();
        eprintln!("unclassified lines:");
        for u in &stats.unclassified_lines {
            eprintln!(
                "  L{}: {:?}{}",
                u.line_number,
                u.reason,
                u.data
                    .as_ref()
                    .map(|d| format!(" | {}", if d.len() > 100 { &d[..100] } else { d }))
                    .unwrap_or_default(),
            );
        }
    }
}
