use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use std::collections::HashMap;

use freeswitch_log_parser::{
    classify_message, parse_line, Block, LineKind, LogEntry, LogStream, MessageKind,
    SessionTracker, UnclassifiedTracking,
};
use xz2::read::XzDecoder;

const FIXTURES_DIR: &str = "tests/fixtures";

fn lines_from_file(path: &Path) -> Box<dyn Iterator<Item = String>> {
    let file = File::open(path).expect("open fixture");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let reader: Box<dyn Read> = if ext == "xz" {
        Box::new(XzDecoder::new(file))
    } else {
        Box::new(file)
    };

    Box::new(
        BufReader::new(reader)
            .lines()
            .map(|l| l.expect("read line")),
    )
}

fn is_log_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".xz") || name.ends_with(".log") || name.ends_with(".1")
}

fn fixture_corpora() -> Vec<(String, Vec<std::path::PathBuf>)> {
    let dir = Path::new(FIXTURES_DIR);
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut corpora: Vec<(String, Vec<std::path::PathBuf>)> = std::fs::read_dir(dir)
        .expect("read fixtures dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .map(|subdir| {
            let name = subdir.file_name().unwrap().to_string_lossy().into_owned();
            let mut files: Vec<_> = std::fs::read_dir(&subdir)
                .expect("read corpus dir")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| is_log_file(p))
                .collect();
            files.sort();
            (name, files)
        })
        .filter(|(_, files)| !files.is_empty())
        .collect();
    corpora.sort_by(|a, b| a.0.cmp(&b.0));
    corpora
}

fn for_each_fixture(
    mut check: impl FnMut(&str, &str, usize, &LogEntry) -> Vec<String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (corpus, files) in &fixture_corpora() {
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy();
            for (i, entry) in LogStream::new(lines_from_file(file)).enumerate() {
                violations.extend(check(corpus, &name, i, &entry));
            }
        }
    }
    violations
}

fn assert_no_violations(violations: Vec<String>, label: &str) {
    assert!(
        violations.is_empty(),
        "{label} ({} violations):\n{}",
        violations.len(),
        violations
            .iter()
            .take(10)
            .fold(String::new(), |mut acc, v| {
                acc.push_str("  ");
                acc.push_str(v);
                acc.push('\n');
                acc
            }),
    );
}

fn skip_if_no_fixtures() -> bool {
    if fixture_corpora().is_empty() {
        eprintln!("skipping: no fixture files in {FIXTURES_DIR}");
        true
    } else {
        false
    }
}

#[test]
fn no_execute_in_attached() {
    let violations = for_each_fixture(|corpus, name, i, entry| {
        let mut v = Vec::new();
        for (j, line) in entry.attached.iter().enumerate() {
            let parsed = parse_line(line);
            if parsed.kind == LineKind::UuidContinuation && parsed.message.starts_with("EXECUTE ") {
                v.push(format!("{corpus}/{name}: entry {i} attached[{j}]"));
            }
        }
        v
    });
    if violations.is_empty() && skip_if_no_fixtures() {
        return;
    }
    assert_no_violations(violations, "EXECUTE lines found in attached");
}

#[test]
fn channel_data_has_typed_block() {
    let violations = for_each_fixture(|corpus, name, i, entry| {
        if entry.message_kind == MessageKind::ChannelData && !entry.attached.is_empty() {
            if entry.block.is_none() {
                return vec![format!(
                    "{corpus}/{name}: entry {i} CHANNEL_DATA with {} attached but no block",
                    entry.attached.len()
                )];
            }
            if let Some(Block::ChannelData { fields, variables }) = &entry.block {
                if fields.is_empty() && variables.is_empty() {
                    return vec![format!(
                        "{corpus}/{name}: entry {i} CHANNEL_DATA block with empty fields and variables"
                    )];
                }
            }
        }
        vec![]
    });
    if violations.is_empty() && skip_if_no_fixtures() {
        return;
    }
    assert_no_violations(violations, "CHANNEL_DATA entries missing typed block");
}

#[test]
fn sdp_has_typed_block() {
    let violations = for_each_fixture(|corpus, name, i, entry| {
        if matches!(&entry.message_kind, MessageKind::SdpMarker { .. })
            && !entry.attached.is_empty()
        {
            if entry.block.is_none() {
                return vec![format!(
                    "{corpus}/{name}: entry {i} SDP marker with {} attached but no block",
                    entry.attached.len()
                )];
            }
            if let Some(Block::Sdp { body, .. }) = &entry.block {
                if body.is_empty() {
                    return vec![format!(
                        "{corpus}/{name}: entry {i} SDP block with empty body"
                    )];
                }
            }
        }
        vec![]
    });
    if violations.is_empty() && skip_if_no_fixtures() {
        return;
    }
    assert_no_violations(violations, "SDP entries missing typed block");
}

fn message_kind_label(kind: &MessageKind) -> &'static str {
    kind.label()
}

#[test]
fn comprehensive_parse_report() {
    if skip_if_no_fixtures() {
        return;
    }
    for (corpus, files) in &fixture_corpora() {
        eprintln!();
        eprintln!(">>> corpus: {corpus} ({} files) <<<", files.len());
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy();
            let mut stream = LogStream::new(lines_from_file(file))
                .unclassified_tracking(UnclassifiedTracking::CaptureData);

            let mut entry_count: u64 = 0;
            let mut total_attached: u64 = 0;

            // Entry-level stats
            let mut entry_kind_counts: HashMap<&str, u64> = HashMap::new();
            let mut entry_line_kind_counts: HashMap<String, u64> = HashMap::new();
            let mut block_counts: HashMap<&str, u64> = HashMap::new();
            let mut no_block_count: u64 = 0;

            // Attached line stats: classify every attached line
            let mut attached_kind_counts: HashMap<&str, u64> = HashMap::new();
            let mut general_samples: Vec<String> = Vec::new();

            for entry in stream.by_ref() {
                entry_count += 1;
                total_attached += entry.attached.len() as u64;

                *entry_kind_counts
                    .entry(message_kind_label(&entry.message_kind))
                    .or_default() += 1;
                *entry_line_kind_counts
                    .entry(format!("{}", entry.kind))
                    .or_default() += 1;

                match &entry.block {
                    Some(Block::ChannelData { .. }) => {
                        *block_counts.entry("channel-data").or_default() += 1
                    }
                    Some(Block::Sdp { .. }) => *block_counts.entry("sdp").or_default() += 1,
                    Some(Block::CodecNegotiation { .. }) => {
                        *block_counts.entry("codec-negotiation").or_default() += 1
                    }
                    None => no_block_count += 1,
                }

                // Classify every attached line to find what's "general" / unparsed
                for attached_line in &entry.attached {
                    let parsed = parse_line(attached_line);
                    let msg_kind = classify_message(parsed.message);
                    let label = message_kind_label(&msg_kind);
                    *attached_kind_counts.entry(label).or_default() += 1;

                    if label == "general" && general_samples.len() < 20 {
                        let sample = if parsed.message.len() > 120 {
                            format!("{}...", &parsed.message[..120])
                        } else {
                            parsed.message.to_string()
                        };
                        general_samples.push(sample);
                    }
                }

                // Also check if the entry itself is general
                if message_kind_label(&entry.message_kind) == "general"
                    && general_samples.len() < 20
                {
                    let sample = if entry.message.len() > 120 {
                        format!("{}...", &entry.message[..120])
                    } else {
                        entry.message.clone()
                    };
                    general_samples.push(sample);
                }
            }

            let stats = stream.stats();

            eprintln!();
            eprintln!("=== {corpus}/{name} ===");
            eprintln!(
                "  lines: {}  entries: {}  attached: {}",
                stats.lines_processed, entry_count, total_attached,
            );

            eprintln!("  entry LineKind:");
            let mut lk: Vec<_> = entry_line_kind_counts.iter().collect();
            lk.sort_by(|a, b| b.1.cmp(a.1));
            for (kind, count) in &lk {
                eprintln!("    {kind:>12}: {count}");
            }

            eprintln!("  entry MessageKind:");
            let mut mk: Vec<_> = entry_kind_counts.iter().collect();
            mk.sort_by(|a, b| b.1.cmp(a.1));
            for (kind, count) in &mk {
                eprintln!("    {kind:>14}: {count}");
            }

            eprintln!("  blocks: {no_block_count} without block");
            for (kind, count) in &block_counts {
                eprintln!("    {kind:>14}: {count}");
            }

            eprintln!("  attached line MessageKind:");
            let mut ak: Vec<_> = attached_kind_counts.iter().collect();
            ak.sort_by(|a, b| b.1.cmp(a.1));
            for (kind, count) in &ak {
                eprintln!("    {kind:>14}: {count}");
            }

            eprintln!("  stream unclassified: {}", stats.lines_unclassified);
            for u in &stats.unclassified_lines {
                let data = u
                    .data
                    .as_ref()
                    .map(|d| {
                        if d.len() > 100 {
                            format!(" | {}...", &d[..100])
                        } else {
                            format!(" | {d}")
                        }
                    })
                    .unwrap_or_default();
                eprintln!("    L{}: {:?}{}", u.line_number, u.reason, data);
            }

            if !general_samples.is_empty() {
                eprintln!(
                    "  general (unparsed) samples ({} shown):",
                    general_samples.len()
                );
                for sample in &general_samples {
                    eprintln!("    | {sample}");
                }
            }

            eprintln!(
                "  accounting: in_entries={} empty_orphan={} split={} unaccounted={}",
                stats.lines_in_entries,
                stats.lines_empty_orphan,
                stats.lines_split,
                stats.unaccounted_lines(),
            );

            assert!(
                stats.lines_processed > 0,
                "{corpus}/{name}: no lines processed"
            );
            assert_eq!(
                stats.unaccounted_lines(),
                0,
                "{corpus}/{name}: line accounting invariant violated: \
             processed={} + split={} != in_entries={} + empty_orphan={}",
                stats.lines_processed,
                stats.lines_split,
                stats.lines_in_entries,
                stats.lines_empty_orphan,
            );
        }
    }
}

#[test]
fn session_tracker_learns_state() {
    if skip_if_no_fixtures() {
        return;
    }
    for (corpus, files) in &fixture_corpora() {
        eprintln!();
        eprintln!(">>> corpus: {corpus} ({} files) <<<", files.len());
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy();
            let stream = LogStream::new(lines_from_file(file));
            let mut tracker = SessionTracker::new(stream);
            let mut enriched_count: u64 = 0;
            let mut with_session: u64 = 0;
            let mut with_context: u64 = 0;
            let mut with_channel_name: u64 = 0;
            let mut vars_learned: u64 = 0;

            for enriched in tracker.by_ref() {
                enriched_count += 1;
                if let Some(session) = &enriched.session {
                    with_session += 1;
                    if session.dialplan_context.is_some() {
                        with_context += 1;
                    }
                    if session.channel_name.is_some() {
                        with_channel_name += 1;
                    }
                }
            }

            for state in tracker.sessions().values() {
                vars_learned += state.variables.len() as u64;
            }

            let session_count = tracker.sessions().len();
            eprintln!();
            eprintln!("=== {corpus}/{name} (session tracker) ===");
            eprintln!("  entries: {enriched_count}");
            eprintln!("  with session: {with_session}");
            eprintln!("  with dialplan context: {with_context}");
            eprintln!("  with channel name: {with_channel_name}");
            eprintln!("  sessions tracked: {session_count}");
            eprintln!("  total variables learned: {vars_learned}");
        }
    }
}

#[test]
fn warning_report() {
    if skip_if_no_fixtures() {
        return;
    }
    for (corpus, files) in &fixture_corpora() {
        eprintln!();
        eprintln!(">>> corpus: {corpus} ({} files) <<<", files.len());
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy();
            let mut entries_with_warnings: u64 = 0;
            let mut total_warnings: u64 = 0;
            let mut warning_samples: Vec<String> = Vec::new();

            for entry in LogStream::new(lines_from_file(file)) {
                if !entry.warnings.is_empty() {
                    entries_with_warnings += 1;
                    total_warnings += entry.warnings.len() as u64;
                    if warning_samples.len() < 10 {
                        for w in &entry.warnings {
                            if warning_samples.len() < 10 {
                                warning_samples.push(format!("L{}: {}", entry.line_number, w));
                            }
                        }
                    }
                }
            }

            eprintln!();
            eprintln!("=== {corpus}/{name} (warnings) ===");
            eprintln!("  entries with warnings: {entries_with_warnings}");
            eprintln!("  total warnings: {total_warnings}");
            for sample in &warning_samples {
                eprintln!("    | {sample}");
            }
        }
    }
}
