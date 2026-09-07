//! `fslog tail` — follow the live log, printing each match as it lands.

use std::io::{self, Write};
use std::path::Path;

use freeswitch_log_parser::{LogStream, SessionTracker};

use crate::cli::{build_filter, TailArgs};
use crate::files::{open_tail_reader, resolve_log_path};
use crate::output::ColorMode;
use crate::pager::is_broken_pipe;

pub fn run(
    dir: &Path,
    args: &TailArgs,
    color: ColorMode,
    out: &mut dyn Write,
    max_line_bytes: usize,
) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);

    let path = resolve_log_path(dir, args.file.as_deref());
    let lines = open_tail_reader(&path, args.lines, max_line_bytes)?;

    let printer = args.filter.printer(color);
    let stream = LogStream::new(lines).unclassified_tracking(args.filter.tracking());
    let mut tracker = SessionTracker::new(stream);

    for enriched in tracker.by_ref() {
        if !filter.matches(&enriched.entry) {
            continue;
        }
        if !args.filter.stats {
            let written = printer
                .print_entry(out, &enriched.entry, enriched.session.as_ref(), None)
                .and_then(|()| out.flush());
            match written {
                Err(e) if is_broken_pipe(&e) => break,
                other => other?,
            }
        }
    }

    Ok(())
}
