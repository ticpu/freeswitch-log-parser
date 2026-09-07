//! `fslog list` — the log files on hand, with their rotation dates and sizes.

use std::io::Write;

use crate::files::{discover_log_files, display_name, format_size};
use crate::run::RunCtx;

pub fn run(ctx: &RunCtx, out: &mut dyn Write) -> anyhow::Result<()> {
    let files = discover_log_files(&ctx.dir)?;
    for f in &files {
        let date = f
            .date
            .as_deref()
            .map(|d| {
                // "2026-03-08-16-52-07" → "2026-03-08 16:52"
                if d.len() >= 16 {
                    format!("{} {}:{}", &d[..10], &d[11..13], &d[14..16])
                } else {
                    d.to_string()
                }
            })
            .unwrap_or_else(|| "(current)".to_string());
        let size = format_size(f.size);
        let name = display_name(&f.path);
        writeln!(out, "{date:<17} {size:>6}  {name}")?;
    }
    Ok(())
}
