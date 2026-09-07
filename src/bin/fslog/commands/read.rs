//! `fslog read` — one file, or stdin, through the shared parse loop.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::cli::{build_filter, ReadArgs};
use crate::files::{display_name, lossy_line_iter, open_log_reader, resolve_log_path};
use crate::output::ColorMode;
use crate::run::{pattern_flag, print_epilogue, print_hidden, run_output};

pub fn run(
    dir: &Path,
    args: &ReadArgs,
    color: ColorMode,
    out: &mut dyn Write,
    max_line_bytes: usize,
) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);

    let (name, lines): (String, Box<dyn Iterator<Item = String>>) = match args.file.as_deref() {
        Some("-") => (
            "-".to_string(),
            lossy_line_iter(
                Box::new(io::stdin().lock()),
                "-".to_string(),
                max_line_bytes,
            ),
        ),
        Some(path) => {
            let p = PathBuf::from(path);
            let p = if p.is_absolute() || p.exists() {
                p
            } else {
                dir.join(&p)
            };
            (display_name(&p), open_log_reader(&p, max_line_bytes)?)
        }
        None => {
            let p = resolve_log_path(dir, None);
            (display_name(&p), open_log_reader(&p, max_line_bytes)?)
        }
    };

    let printer = args.filter.printer(color);
    let run = run_output(
        out,
        vec![(name, lines)],
        &filter,
        &printer,
        &args.filter,
        0,
        0,
    )?;

    print_hidden(
        &filter,
        pattern_flag(&args.filter, false),
        false,
        &run.hidden,
    );
    print_epilogue(&printer, &args.filter, &run)
}
