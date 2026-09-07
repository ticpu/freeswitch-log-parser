//! `fslog search` — the file set a date window selects, and the parse over it.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use crate::cli::{build_filter, SearchArgs};
use crate::files::{
    self, discover_log_files, display_name, filter_files_by_date, format_size, lazy_log_reader,
};
use crate::output::ColorMode;
use crate::prescan;
use crate::related;
use crate::run::{pattern_flag, print_epilogue, print_hidden, run_output};

const MAX_UNCONFIRMED_FILES: usize = 20;
const MAX_UNCONFIRMED_BYTES: u64 = 1024 * 1024 * 1024;

fn max_unconfirmed_bytes() -> u64 {
    let raw = match std::env::var("FSLOG_CONFIRM_SIZE") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return MAX_UNCONFIRMED_BYTES,
        // Set but unreadable is a misconfiguration, not an absent setting.
        Err(e) => {
            eprintln!("fslog: FSLOG_CONFIRM_SIZE is set but unusable: {e}");
            process::exit(2);
        }
    };
    raw.parse().unwrap_or_else(|e| {
        eprintln!("fslog: FSLOG_CONFIRM_SIZE={raw} is not a byte count: {e}");
        process::exit(2);
    })
}

/// A human-readable span of the log files on hand, so an empty result says
/// whether the search was even looking at the right days.
fn coverage_note(files: &[files::LogFile]) -> Option<String> {
    let stamps: Vec<&str> = files.iter().filter_map(|f| f.date.as_deref()).collect();
    let active = files.iter().any(|f| f.date.is_none());
    match (stamps.first(), active) {
        (None, true) => Some("log coverage here: active log only".to_string()),
        (None, false) => None,
        (Some(first), _) => {
            let day = |s: &str| s[..s.len().min(10)].to_string();
            let last = if active {
                "now".to_string()
            } else {
                day(stamps.last()?)
            };
            Some(format!("log coverage here: {} – {last}", day(first)))
        }
    }
}

/// Resolve the files a search will scan: explicit `--file` paths, or
/// date-filtered discovery in `dir`. Returns `None` when nothing matches or the
/// user declines the large-scan confirmation.
fn resolve_search_files(
    dir: &Path,
    args: &SearchArgs,
    from: Option<&str>,
    until: Option<&str>,
) -> io::Result<Option<Vec<(String, PathBuf)>>> {
    if !args.files.is_empty() {
        let v = args
            .files
            .iter()
            .map(|p| (display_name(p), p.clone()))
            .collect();
        return Ok(Some(v));
    }

    let all_files = discover_log_files(dir)?;
    let selected = filter_files_by_date(&all_files, from, until);
    if selected.is_empty() {
        eprintln!("no log files match the date range");
        return Ok(None);
    }
    let total_size: u64 = selected.iter().map(|f| f.size).sum();
    // File count alone is a poor proxy for the wait: twenty rotated logs from a
    // quiet box are seconds, one from a busy one can be gigabytes decompressed.
    if !args.yes && (selected.len() > MAX_UNCONFIRMED_FILES || total_size > max_unconfirmed_bytes())
    {
        let scale = format!("{} files ({})", selected.len(), format_size(total_size));
        if !io::stdin().is_terminal() {
            return Err(io::Error::other(format!(
                "refusing to scan {scale} without confirmation; pass -y to override"
            )));
        }
        eprint!("about to scan {scale}, proceed? [y/N] ");
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Ok(None);
        }
    }
    let v = selected
        .iter()
        .map(|f| (display_name(&f.path), f.path.clone()))
        .collect();
    Ok(Some(v))
}

fn build_segments(
    files: &[(String, PathBuf)],
    max_line_bytes: usize,
) -> Vec<(String, Box<dyn Iterator<Item = String>>)> {
    files
        .iter()
        .map(|(name, path)| (name.clone(), lazy_log_reader(path.clone(), max_line_bytes)))
        .collect()
}

pub fn run(
    dir: &Path,
    args: &SearchArgs,
    color: ColorMode,
    out: &mut dyn Write,
    max_line_bytes: usize,
) -> io::Result<()> {
    if args.pattern.is_some() && args.filter.fgrep.is_some() {
        return Err(io::Error::other(
            "provide either a positional PATTERN or --fgrep, not both",
        ));
    }

    let (from, until) = args.window();
    let mut filter = build_filter(&args.filter, from.as_deref(), until.as_deref());
    if let Some(p) = &args.pattern {
        filter.set_fgrep(p)?;
    }

    let files = match resolve_search_files(dir, args, from.as_deref(), until.as_deref())? {
        Some(f) => f,
        None => return Ok(()),
    };

    // Coverage is only meaningful for the files discovery chose; with explicit
    // --file paths the operator already knows what was searched.
    let report_empty = || -> io::Result<()> {
        let note = if args.files.is_empty() {
            coverage_note(&discover_log_files(dir)?)
        } else {
            None
        };
        match note {
            Some(n) => eprintln!("no matching entries; {n}"),
            None => eprintln!("no matching entries"),
        }
        Ok(())
    };

    // A needle that cannot span a line break lets whole files be ruled out before
    // the parse touches them. Any other search reads everything.
    let seeded = if files.len() > 1 {
        match args
            .pattern
            .as_deref()
            .or(args.filter.fgrep.as_deref())
            .or(match args.filter.uuid.as_slice() {
                [only] => Some(only.as_str()),
                _ => None,
            })
            .filter(|n| prescan::is_single_line_safe(n))
        {
            Some(needle) => prescan::narrow(&files, needle),
            None => files.clone(),
        }
    } else {
        files.clone()
    };
    if seeded.is_empty() {
        return report_empty();
    }

    let printer = args.filter.printer(color);

    // The narrowed set is sound for discovery, which matches the seed the prescan
    // looked for. It is not sound for output: `--related` re-keys the filter onto
    // the discovered peer legs, and a peer's own file need never mention the seed.
    let mut rendered = seeded;
    if args.related {
        let discovered = related::discover(
            build_segments(&rendered, max_line_bytes),
            &filter.for_discovery(),
        );
        if discovered.is_empty() {
            return report_empty();
        }
        let seeds: Vec<String> = discovered.into_iter().collect();
        filter.set_uuids(&seeds)?;
        filter.uuid_strict = true;
        rendered = files;
    }

    let run = run_output(
        out,
        build_segments(&rendered, max_line_bytes),
        &filter,
        &printer,
        &args.filter,
        args.before(),
        args.after(),
    )?;

    if run.matched == 0 {
        report_empty()?;
    }
    print_hidden(
        &filter,
        pattern_flag(&args.filter, args.pattern.is_some()),
        args.related,
        &run.hidden,
    );
    print_epilogue(&printer, &args.filter, &run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_file(date: Option<&str>) -> files::LogFile {
        files::LogFile {
            path: PathBuf::from("freeswitch.log"),
            date: date.map(str::to_string),
            size: 0,
        }
    }

    #[test]
    fn coverage_spans_first_stamp_to_last() {
        let files = vec![
            log_file(Some("2026-05-01-00-00-00")),
            log_file(Some("2026-05-20-00-00-00")),
        ];
        assert_eq!(
            coverage_note(&files).unwrap(),
            "log coverage here: 2026-05-01 – 2026-05-20"
        );
    }

    #[test]
    fn active_log_makes_the_upper_bound_now() {
        let files = vec![log_file(Some("2026-05-01-00-00-00")), log_file(None)];
        assert_eq!(
            coverage_note(&files).unwrap(),
            "log coverage here: 2026-05-01 – now"
        );
    }

    #[test]
    fn active_log_alone_has_no_span() {
        assert_eq!(
            coverage_note(&[log_file(None)]).unwrap(),
            "log coverage here: active log only"
        );
    }

    #[test]
    fn no_files_no_note() {
        assert!(coverage_note(&[]).is_none());
    }
}
