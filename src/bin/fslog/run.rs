//! The parse/emit loop shared by `search` and `read`, and the end-of-run notes
//! the two report identically.

use std::io::{self, Write};
use std::path::PathBuf;

use freeswitch_log_parser::{
    LogEntry, LogStream, MessageKind, ParseStats, SessionTracker, TrackedChain,
};

use crate::cli::FilterArgs;
use crate::context::{Emitter, FieldCounts, HiddenCounts};
use crate::output::{ColorMode, EntryPrinter, FilterConfig};
use crate::pager::is_broken_pipe;

/// What every subcommand needs from the global flags, resolved once.
pub struct RunCtx {
    pub dir: PathBuf,
    pub color: ColorMode,
    pub max_line_bytes: usize,
}

/// What one parse run renders and how wide: the filter it admits by, the
/// printer it renders through, and the grep-style context around each match.
pub struct RunPlan<'a> {
    pub filter: &'a FilterConfig,
    pub printer: &'a EntryPrinter,
    pub fargs: &'a FilterArgs,
    pub before: usize,
    pub after: usize,
}

pub struct RunSummary {
    pub stats: ParseStats,
    pub session_count: usize,
    pub count: u64,
    pub matched: u64,
    pub hidden: HiddenCounts,
    pub fields: FieldCounts,
}

/// Drive the parse over `segments`, emitting matches through `Emitter`. The
/// single output loop for both search and read.
pub fn run_output(
    out: &mut dyn Write,
    segments: Vec<(String, Box<dyn Iterator<Item = String>>)>,
    plan: &RunPlan,
) -> io::Result<RunSummary> {
    let fargs = plan.fargs;
    let (chain, seg_tracker) = TrackedChain::new(segments);
    let stream = LogStream::new(chain).unclassified_tracking(fargs.tracking());
    let mut emitter = Emitter::new(plan, &seg_tracker);

    let (stats, session_count) = if fargs.session {
        let mut tracker = SessionTracker::new(stream);
        for enriched in tracker.by_ref() {
            match emitter.on_entry(out, &enriched.entry, enriched.session.as_ref()) {
                Err(e) if is_broken_pipe(&e) => break,
                other => other?,
            }
        }
        (tracker.stats().clone(), tracker.sessions().len())
    } else {
        let mut stream = stream;
        for entry in stream.by_ref() {
            match emitter.on_entry(out, &entry, None) {
                Err(e) if is_broken_pipe(&e) => break,
                other => other?,
            }
        }
        (stream.stats().clone(), 0)
    };

    Ok(RunSummary {
        stats,
        session_count,
        count: emitter.count,
        matched: emitter.matched,
        hidden: emitter.hidden,
        fields: emitter.fields,
    })
}

pub(crate) fn separator_entry(kind: MessageKind, msg: String) -> LogEntry {
    LogEntry {
        message_kind: kind,
        ..LogEntry::synthetic(msg)
    }
}

/// Stats/unclassified epilogue on stderr, shared by search and read.
pub fn print_epilogue(plan: &RunPlan, run: &RunSummary) -> io::Result<()> {
    let (printer, fargs) = (plan.printer, plan.fargs);
    if fargs.stats || fargs.unclassified {
        printer.print_stats(&mut io::stderr(), &run.stats, run.count, run.session_count)?;
    }
    if fargs.stats {
        printer.print_field_stats(&mut io::stderr(), &run.fields, run.matched)?;
    }
    if fargs.unclassified {
        printer.print_unclassified(&mut io::stderr(), &run.stats)?;
    }
    Ok(())
}

/// Name the pattern flag in effect, so the note points at the one the operator
/// typed rather than a generic "pattern".
pub fn pattern_flag(fargs: &FilterArgs, positional: bool) -> &'static str {
    match (fargs.fgrep.is_some() || positional, fargs.grep.is_some()) {
        (true, true) => "--fgrep/--grep",
        (true, false) if positional => "PATTERN",
        (true, false) => "--fgrep",
        _ => "--grep",
    }
}

/// Report what a narrowed scope kept out of the output. Pattern search reads the
/// message only and `-u` the UUID column only, both deliberately; the silence is
/// what misleads, since hiding nothing and hiding hundreds print identically.
pub fn print_hidden(filter: &FilterConfig, flag: &str, related: bool, hidden: &HiddenCounts) {
    if hidden.pattern_in_uuid > 0 {
        eprintln!(
            "note: {} more entries carry this pattern in the channel-UUID column, which {flag} does not search",
            hidden.pattern_in_uuid
        );
        if let Some(uuid) = filter.suggested_uuid() {
            eprintln!("hint: rerun with -u {uuid}");
        }
    }

    if hidden.pattern_in_blocks > 0 {
        eprintln!(
            "note: {} more entries carry this pattern in attached block lines, which {flag} does not search",
            hidden.pattern_in_blocks
        );
        eprintln!("hint: rerun with --match-blocks");
    }

    if hidden.uuid_in_body > 0 {
        let subject = if filter.uuid_needle_count() == 1 {
            "this UUID"
        } else {
            "a filtered UUID"
        };
        eprintln!(
            "note: {} more entries name {subject} in a message or block line, which -u does not search",
            hidden.uuid_in_body
        );
        if !related {
            eprintln!("hint: --related expands to the legs those entries name");
        }
    }
}
