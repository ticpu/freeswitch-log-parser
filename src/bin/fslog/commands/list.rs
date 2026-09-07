//! `fslog list` — the log files on hand, with their rotation dates and sizes.

use std::io::{self, Write};
use std::path::Path;

use crate::files::{discover_log_files, format_size};

pub fn run(dir: &Path, out: &mut dyn Write) -> io::Result<()> {
    let files = discover_log_files(dir)?;
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
        let name = f.path.file_name().unwrap().to_string_lossy();
        writeln!(out, "{date:<17} {size:>6}  {name}")?;
    }
    Ok(())
}
