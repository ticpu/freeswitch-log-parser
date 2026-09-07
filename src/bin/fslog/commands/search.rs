//! `fslog search` — the file set a date window selects, and the parse over it.

use std::io::{self, IsTerminal, Write};

use anyhow::Context;

use crate::cli::{build_filter, SearchArgs};
use crate::files::{
    self, discover_log_files, filter_files_by_date, format_size, lazy_log_reader, Segment,
};
use crate::prescan;
use crate::related;
use crate::run::{pattern_flag, print_epilogue, print_hidden, run_output, RunCtx, RunPlan};

const MAX_UNCONFIRMED_FILES: usize = 20;
const MAX_UNCONFIRMED_BYTES: u64 = 1024 * 1024 * 1024;

fn max_unconfirmed_bytes() -> anyhow::Result<u64> {
    let Some(raw) = crate::env::var("FSLOG_CONFIRM_SIZE")? else {
        return Ok(MAX_UNCONFIRMED_BYTES);
    };
    raw.parse()
        .with_context(|| format!("FSLOG_CONFIRM_SIZE={raw} is not a byte count"))
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
    args: &SearchArgs,
    all_files: &[files::LogFile],
    from: Option<&str>,
    until: Option<&str>,
) -> anyhow::Result<Option<Vec<Segment>>> {
    if !args.files.is_empty() {
        let v = args.files.iter().cloned().map(Segment::new).collect();
        return Ok(Some(v));
    }

    let selected = filter_files_by_date(all_files, from, until);
    if selected.is_empty() {
        eprintln!("no log files match the date range");
        return Ok(None);
    }
    let total_size: u64 = selected.iter().map(|f| f.size).sum();
    // File count alone is a poor proxy for the wait: twenty rotated logs from a
    // quiet box are seconds, one from a busy one can be gigabytes decompressed.
    if !args.yes
        && (selected.len() > MAX_UNCONFIRMED_FILES || total_size > max_unconfirmed_bytes()?)
    {
        let scale = format!("{} files ({})", selected.len(), format_size(total_size));
        if !io::stdin().is_terminal() {
            anyhow::bail!("refusing to scan {scale} without confirmation; pass -y to override");
        }
        eprint!("about to scan {scale}, proceed? [y/N] ");
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .context("reading the confirmation answer")?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Ok(None);
        }
    }
    let v = selected
        .iter()
        .map(|f| Segment::new(f.path.clone()))
        .collect();
    Ok(Some(v))
}

fn build_segments(
    files: &[Segment],
    max_line_bytes: usize,
) -> Vec<(String, Box<dyn Iterator<Item = String>>)> {
    files
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                lazy_log_reader(s.path.clone(), max_line_bytes),
            )
        })
        .collect()
}

pub fn run(ctx: &RunCtx, args: &SearchArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    let dir = ctx.dir.as_path();
    if args.pattern.is_some() && args.filter.fgrep.is_some() {
        anyhow::bail!("provide either a positional PATTERN or --fgrep, not both");
    }

    let (from, until) = args.window();
    let mut filter = build_filter(&args.filter, from.as_deref(), until.as_deref())?;
    if let Some(p) = &args.pattern {
        filter.set_fgrep(p)?;
    }

    // One directory walk feeds both the file set and the coverage note. With
    // explicit --file paths there is nothing to discover: the operator already
    // knows what was searched, so the note has nothing to add either.
    let discovered = match args.files.is_empty() {
        true => discover_log_files(dir)?,
        false => Vec::new(),
    };

    let files = match resolve_search_files(args, &discovered, from.as_deref(), until.as_deref())? {
        Some(f) => f,
        None => return Ok(()),
    };

    let report_empty = || match coverage_note(&discovered) {
        Some(n) => eprintln!("no matching entries; {n}"),
        None => eprintln!("no matching entries"),
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
            Some(needle) => prescan::narrow(&files, needle, ctx.color),
            None => files.clone(),
        }
    } else {
        files.clone()
    };
    if seeded.is_empty() {
        report_empty();
        return Ok(());
    }

    let printer = args.filter.printer(ctx.color);

    // The narrowed set is sound for discovery, which matches the seed the prescan
    // looked for. It is not sound for output: `--related` re-keys the filter onto
    // the discovered peer legs, and a peer's own file need never mention the seed.
    let mut rendered = seeded;
    if args.related {
        let legs = related::discover(
            build_segments(&rendered, ctx.max_line_bytes),
            &filter.for_discovery(),
        );
        if legs.is_empty() {
            report_empty();
            return Ok(());
        }
        let seeds: Vec<String> = legs.into_iter().collect();
        filter.set_uuids(&seeds)?;
        filter.uuid_strict = true;
        rendered = files;
    }

    let plan = RunPlan {
        filter: &filter,
        printer: &printer,
        fargs: &args.filter,
        before: args.before(),
        after: args.after(),
    };
    let run = run_output(out, build_segments(&rendered, ctx.max_line_bytes), &plan)?;

    if run.matched == 0 {
        report_empty();
    }
    print_hidden(
        &filter,
        pattern_flag(&args.filter, args.pattern.is_some()),
        args.related,
        &run.hidden,
    );
    Ok(print_epilogue(&plan, &run)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
