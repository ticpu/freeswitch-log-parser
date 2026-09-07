//! `fslog read` — one file, or stdin, through the shared parse loop.

use std::io::{self, Write};

use crate::cli::{build_filter, ReadArgs};
use crate::files::{display_name, lossy_line_iter, open_log_reader, resolve_log_path};
use crate::run::{pattern_flag, print_epilogue, print_hidden, run_output, RunCtx, RunPlan};

pub fn run(ctx: &RunCtx, args: &ReadArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    let (dir, max_line_bytes) = (ctx.dir.as_path(), ctx.max_line_bytes);
    let filter = build_filter(&args.filter, None, None)?;

    let (name, lines): (String, Box<dyn Iterator<Item = String>>) = match args.file.as_deref() {
        Some("-") => (
            "-".to_string(),
            lossy_line_iter(
                Box::new(io::stdin().lock()),
                "-".to_string(),
                max_line_bytes,
            ),
        ),
        file => {
            let p = resolve_log_path(dir, file);
            (display_name(&p), open_log_reader(&p, max_line_bytes)?)
        }
    };

    let printer = args.filter.printer(ctx.color);
    let plan = RunPlan {
        filter: &filter,
        printer: &printer,
        fargs: &args.filter,
        before: 0,
        after: 0,
    };
    let run = run_output(out, vec![(name, lines)], &plan)?;

    print_hidden(
        &filter,
        pattern_flag(&args.filter, false),
        false,
        &run.hidden,
    );
    Ok(print_epilogue(&plan, &run)?)
}
