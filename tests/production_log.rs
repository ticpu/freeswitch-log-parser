use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use std::collections::HashMap;

use freeswitch_log_parser::{
    classify_message, parse_line, read_log_lines, truncate_at_char_boundary, Block, CodecMedia,
    LineKind, LogEntry, LogStream, MessageKind, SessionTracker, UnclassifiedTracking,
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

    Box::new(read_log_lines(BufReader::new(reader)).map(|d| d.expect("read fixture").text))
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

#[test]
fn channel_data_bare_continuations_accumulated() {
    // Production pattern: mod_logfile stops prepending the UUID mid-way through
    // a CHANNEL_DATA dump. Bare continuation lines (variable_* without UUID
    // prefix) must still be accumulated into the block. Found in 20+ instances
    // across bcf and pbx fixture corpora.
    if skip_if_no_fixtures() {
        return;
    }
    let mut total_blocks: u64 = 0;
    let mut blocks_with_bare: u64 = 0;
    let mut max_bare_ratio: f64 = 0.0;

    for (corpus, files) in &fixture_corpora() {
        for file in files {
            let name = file.file_name().unwrap().to_string_lossy();
            for entry in LogStream::new(lines_from_file(file)) {
                if let Some(Block::ChannelData { fields, variables }) = &entry.block {
                    total_blocks += 1;
                    // Count how many attached lines are bare continuations (no UUID)
                    let bare_count = entry
                        .attached
                        .iter()
                        .filter(|line| {
                            let parsed = parse_line(line);
                            parsed.kind == LineKind::BareContinuation
                        })
                        .count();

                    if bare_count > 0 {
                        blocks_with_bare += 1;
                        let total_vars = fields.len() + variables.len();
                        assert!(
                            total_vars > 0,
                            "{corpus}/{name}: L{} CHANNEL_DATA has {bare_count} bare lines \
                             but block has 0 fields+variables",
                            entry.line_number,
                        );
                        let ratio = bare_count as f64 / entry.attached.len() as f64;
                        if ratio > max_bare_ratio {
                            max_bare_ratio = ratio;
                        }
                    }
                }
            }
        }
    }

    eprintln!();
    eprintln!("CHANNEL_DATA UUID-drop stats:");
    eprintln!("  total blocks: {total_blocks}");
    eprintln!("  blocks with bare continuations: {blocks_with_bare}");
    eprintln!("  max bare/total ratio: {max_bare_ratio:.2}");
    assert!(
        blocks_with_bare > 0,
        "expected fixture data to contain CHANNEL_DATA blocks with bare continuations"
    );
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
                    .entry(entry.message_kind.label())
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
                    Some(other) => panic!("unexpected block type: {other:?}"),
                }

                // Classify every attached line to find what's "general" / unparsed
                for attached_line in &entry.attached {
                    let parsed = parse_line(attached_line);
                    let msg_kind = classify_message(parsed.message);
                    let label = msg_kind.label();
                    *attached_kind_counts.entry(label).or_default() += 1;

                    if label == "general" && general_samples.len() < 20 {
                        let sample = if parsed.message.len() > 120 {
                            format!("{}...", truncate_at_char_boundary(parsed.message, 120))
                        } else {
                            parsed.message.to_string()
                        };
                        general_samples.push(sample);
                    }
                }

                // Also check if the entry itself is general
                if entry.message_kind.label() == "general" && general_samples.len() < 20 {
                    let sample = if entry.message.len() > 120 {
                        format!("{}...", truncate_at_char_boundary(&entry.message, 120))
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
                            format!(" | {}...", truncate_at_char_boundary(d, 100))
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
fn system_lines_with_embedded_uuid_extracted() {
    // FreeSWITCH's C++ wrapper (switch_cpp.cpp) logs with SWITCH_CHANNEL_LOG
    // (no session context) but includes the UUID at the start of the message.
    // These must be extracted so -u filtering and session tracking work.
    if skip_if_no_fixtures() {
        return;
    }
    let mut total_system: u64 = 0;
    let mut system_with_uuid: u64 = 0;

    for (_corpus, files) in &fixture_corpora() {
        for file in files {
            for entry in LogStream::new(lines_from_file(file)) {
                if entry.kind == LineKind::System {
                    total_system += 1;
                    if !entry.uuid.is_empty() {
                        system_with_uuid += 1;
                    }
                }
            }
        }
    }

    eprintln!();
    eprintln!("System line UUID extraction stats:");
    eprintln!("  total system lines: {total_system}");
    eprintln!("  system lines with extracted UUID: {system_with_uuid}");
    assert!(
        system_with_uuid > 0,
        "expected fixture data to contain System lines with embedded UUIDs"
    );
}

#[test]
fn originate_success_channel_fallback_links_pbx_fixture() {
    // pbx/freeswitch.log.2026-05-11-14-20-22.1.xz contains a FusionPBX call where
    // bridge(user/6244@…) and Originate Resulted in Success: [sofia/internal/6244@…]
    // arrive with no `Peer UUID:` suffix (FS 1.10.5-dev).
    //
    // The fixture covers ~20 minutes of traffic, so by originate time several
    // prior sessions share the same b-leg channel_name. The liveness filter in
    // link_legs skips candidates in terminal channel/callstate (CS_DESTROY etc),
    // leaving exactly one live b-leg → link succeeds.
    let path = Path::new(FIXTURES_DIR)
        .join("pbx")
        .join("freeswitch.log.2026-05-11-14-20-22.1.xz");
    if !path.exists() {
        eprintln!("skipping: {} not present", path.display());
        return;
    }
    const A_LEG: &str = "fc541b63-d608-42af-9ae7-1717ec610def";
    const B_LEG: &str = "23f602c0-618a-46ed-adba-da2827c6a2ce";

    let stream = LogStream::new(lines_from_file(&path));
    let mut tracker = SessionTracker::new(stream);
    for _ in tracker.by_ref() {}

    let a = tracker
        .sessions()
        .get(A_LEG)
        .expect("a-leg session present");
    assert_eq!(
        a.other_leg_uuid.as_deref(),
        Some(B_LEG),
        "a-leg linked to b-leg via channel-name fallback (live candidate)"
    );

    let b = tracker
        .sessions()
        .get(B_LEG)
        .expect("b-leg session present");
    assert_eq!(
        b.other_leg_uuid.as_deref(),
        Some(A_LEG),
        "b-leg points back to a-leg"
    );
}

#[test]
fn conference_and_loopback_link_ra221_fixture() {
    // ra221/freeswitch.log.30.xz holds two conferences that reuse neither name
    // but run minutes apart: 835 is joined by a pulseaudio leg, a softphone, a
    // loopback A leg and a later gateway leg; 844 is a separate call entirely.
    // The loopback B leg never executes `conference` — it is reachable only
    // through the A/B name pairing.
    let path = Path::new(FIXTURES_DIR)
        .join("ra221")
        .join("freeswitch.log.30.xz");
    if !path.exists() {
        eprintln!("skipping: {} not present", path.display());
        return;
    }
    const PULSEAUDIO: &str = "35cd5158-b48e-44ce-b91d-5bd724cfbf34";
    const SOFTPHONE: &str = "1dd18372-af8f-416b-80f3-3339fcb3f371";
    const LOOPBACK_A: &str = "4827c0b0-e96c-4b7d-84ed-a6870b3112f2";
    const LOOPBACK_B: &str = "c70376e5-cada-4ee2-9c2d-b7fa69eee115";
    const GATEWAY: &str = "31a53234-a72c-42e9-9ab1-a6080cfc7b58";
    const OTHER_CONFERENCE: &str = "cb94c4aa-3455-4d1c-aca7-7df0d67e912b";

    let stream = LogStream::new(lines_from_file(&path));
    let mut tracker = SessionTracker::new(stream);
    let mut instances: HashMap<String, String> = HashMap::new();
    for enriched in tracker.by_ref() {
        if let Some(conf) = enriched
            .session
            .as_ref()
            .and_then(|s| s.conference.as_ref())
        {
            instances.insert(enriched.entry.uuid.clone(), conf.instance.clone());
        }
    }

    let instance = instances
        .get(PULSEAUDIO)
        .expect("pulseaudio leg joined a conference");
    for uuid in [SOFTPHONE, LOOPBACK_A, GATEWAY] {
        assert_eq!(
            instances.get(uuid),
            Some(instance),
            "{uuid} shares the conference instance"
        );
    }
    assert_ne!(
        instances.get(OTHER_CONFERENCE),
        Some(instance),
        "a conference minutes later is a separate instance"
    );

    let b_leg = tracker
        .sessions()
        .get(LOOPBACK_B)
        .expect("loopback b-leg session present");
    assert_eq!(
        b_leg.other_leg_uuid.as_deref(),
        Some(LOOPBACK_A),
        "loopback b-leg paired to the a-leg that joined the conference"
    );
    assert!(
        b_leg.conference.is_none(),
        "the b-leg never executes conference()"
    );
}

#[test]
fn codec_outcome_tracked_on_ra221_fixture() {
    // 83b3cbfd negotiates opus twice over PCMU/G722 offers, then the engine
    // reports the read implementation and the original read codec.
    let path = Path::new(FIXTURES_DIR)
        .join("ra221")
        .join("freeswitch.log.30.xz");
    if !path.exists() {
        eprintln!("skipping: {} not present", path.display());
        return;
    }
    const LEG: &str = "83b3cbfd-98ca-4532-89ed-eb31acb1de50";

    let stream = LogStream::new(lines_from_file(&path));
    let mut tracker = SessionTracker::new(stream);
    for _ in tracker.by_ref() {}

    let media = &tracker.sessions().get(LEG).expect("leg present").media;
    let negotiated = media.audio.negotiated.as_ref().expect("audio negotiated");
    assert_eq!(negotiated.name, "opus");
    assert_eq!(negotiated.clock_rate, Some(16000));
    assert!(
        media.audio.offered.len() < 20,
        "offered set is deduped, not one entry per comparison: {}",
        media.audio.offered.len()
    );
    assert_eq!(
        media.read_codec.as_ref().expect("read codec").name,
        "opus",
        "Original read codec set to opus:116"
    );
    assert_eq!(
        media
            .active_audio
            .as_ref()
            .expect("active audio")
            .clock_rate,
        Some(16000)
    );
    assert!(
        media.video.negotiated.is_none(),
        "this fixture has no video negotiation"
    );
}

#[test]
fn video_negotiation_classified_on_pbx_fixture() {
    let path = Path::new(FIXTURES_DIR)
        .join("pbx")
        .join("freeswitch.log.2026-05-11-14-20-22.1.xz");
    if !path.exists() {
        eprintln!("skipping: {} not present", path.display());
        return;
    }
    let video = LogStream::new(lines_from_file(&path))
        .filter(|e| {
            matches!(
                &e.block,
                Some(Block::CodecNegotiation {
                    media: CodecMedia::Video,
                    ..
                })
            )
        })
        .count();
    assert!(
        video > 0,
        "Video Codec Compare runs must form their own blocks"
    );
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
