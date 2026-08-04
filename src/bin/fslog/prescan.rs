//! Byte-level pre-filter that drops candidate files which cannot contain the
//! search term, so the full parse never opens them.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use freeswitch_log_parser::is_uuid;
use log::{debug, warn};
use rayon::prelude::*;

use crate::files::open_log_file;

/// Whether `needle` can be prescanned without risking a false negative.
///
/// The prescan matches within one physical line. A free-text pattern can
/// legitimately match only across an entry and the continuation lines the parser
/// reassembles into it — physically separate lines the raw scan never joins — so
/// prescanning free text could drop a file that really does match. A full UUID
/// or a `token@host` Call-ID never spans a line break, so both are safe.
pub fn is_single_line_safe(needle: &str) -> bool {
    is_uuid(needle) || is_sip_call_id(needle)
}

fn is_sip_call_id(s: &str) -> bool {
    if s.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let mut parts = s.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(user), Some(host), None) => !user.is_empty() && !host.is_empty(),
        _ => false,
    }
}

/// Narrow `files` to those whose decompressed bytes contain `needle`, scanning in
/// parallel. Files that cannot be opened are kept rather than dropped: a prescan
/// exists to save work, and guessing "no match" from a read failure would hide
/// entries the full parse would have reported.
pub fn narrow(files: &[(String, PathBuf)], needle: &str) -> Vec<(String, PathBuf)> {
    // Not a debug_assert: an empty needle reaches `windows(0)`, which panics in
    // release too, with nothing to say about where it came from.
    assert!(!needle.is_empty(), "prescan needle is empty");
    let total = files.len();
    debug!("prescanning {total} file(s) for {needle:?}");
    let done = AtomicUsize::new(0);
    // Progress is a terminal affordance; to a pipe or a log it is only escape noise.
    let progress = std::io::stderr().is_terminal();

    let mut kept: Vec<(usize, (String, PathBuf))> = files
        .par_iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let (name, path) = entry;
            let hit = file_contains(path, needle);
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if progress {
                eprint!("\r\x1b[Kscanning {n}/{total}: {name}");
            }
            hit.then(|| (i, entry.clone()))
        })
        .collect();
    if progress {
        eprint!("\r\x1b[K");
    }

    // par_iter yields in completion order; the parse depends on chronological
    // file order, so restore it.
    kept.sort_by_key(|(i, _)| *i);
    debug!("prescan kept {} of {total} file(s)", kept.len());
    kept.into_iter().map(|(_, entry)| entry).collect()
}

fn file_contains(path: &Path, needle: &str) -> bool {
    match open_log_file(path) {
        Ok(reader) => reader_contains(reader, needle, &path.display()),
        Err(e) => {
            warn!("prescan: cannot open {}: {e}; keeping it", path.display());
            true
        }
    }
}

/// Whether any single line of `reader` contains `needle`, case-insensitively.
/// `what` names the source in the warning a read error produces.
fn reader_contains<R: BufRead>(mut reader: R, needle: &str, what: &dyn std::fmt::Display) -> bool {
    let needle = needle.to_ascii_lowercase().into_bytes();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return false,
            Ok(_) => {
                if buf
                    .windows(needle.len())
                    .any(|w| w.eq_ignore_ascii_case(&needle))
                {
                    return true;
                }
            }
            Err(e) => {
                warn!("prescan: read error on {what}: {e}; keeping it");
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn full_identifiers_are_safe() {
        assert!(is_single_line_safe(UUID));
        assert!(is_single_line_safe("call-abc123@192.0.2.10"));
    }

    #[test]
    fn free_text_and_partials_are_not() {
        // A UUID prefix is a substring search, not an identifier.
        assert!(!is_single_line_safe(&UUID[..8]));
        assert!(!is_single_line_safe("receiving invite"));
        assert!(!is_single_line_safe("m=audio"));
        assert!(!is_single_line_safe(""));
    }

    fn scan(text: &str, needle: &str) -> bool {
        reader_contains(std::io::Cursor::new(text), needle, &"test")
    }

    #[test]
    fn scan_matches_ignoring_case() {
        let log = format!("2026-03-08 16:52:07 [DEBUG] switch.c:1 uuid {UUID}\n");
        assert!(scan(&log, UUID));
        assert!(scan(&log, &UUID.to_ascii_uppercase()));
        assert!(!scan(&log, "99999999-2222-3333-4444-555555555555"));
    }

    #[test]
    fn scan_does_not_join_lines() {
        // The guarantee `is_single_line_safe` rests on: a needle split across a
        // newline is not a match, so only needles that cannot split may prescan.
        assert!(!scan("11111111-2222-3333\n-4444-555555555555\n", UUID));
    }

    #[test]
    fn scan_tolerates_an_unterminated_last_line() {
        assert!(scan(&format!("first line\n{UUID}"), UUID));
    }

    #[test]
    fn scan_reports_no_match_on_empty_input() {
        assert!(!scan("", UUID));
    }

    #[test]
    fn call_id_needs_exactly_one_at_with_both_sides() {
        assert!(!is_single_line_safe("@192.0.2.10"));
        assert!(!is_single_line_safe("call-abc123@"));
        assert!(!is_single_line_safe("a@b@c"));
        assert!(!is_single_line_safe("call abc@192.0.2.10"));
    }
}
