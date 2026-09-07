//! Log files on disk: which ones exist and cover a date window, and how their
//! lines are read.

mod discover;
mod read;

use std::path::{Path, PathBuf};

pub use discover::{discover_log_files, filter_files_by_date, LogFile};
#[cfg(feature = "tui")]
pub use read::open_full_tail_reader;
pub use read::{
    lazy_log_reader, lossy_line_iter, open_log_file, open_log_reader, open_tail_reader,
    ReadFailures,
};

/// Bytes of one physical line a reader will materialize. A collided or verbatim
/// write runs to megabytes, and every reader here is one of several running at
/// once against a memory limit.
pub const DEFAULT_MAX_LINE_BYTES: usize = 1 << 20;

/// One file of a scan, and the name its entries are reported under.
#[derive(Clone)]
pub struct Segment {
    pub name: String,
    pub path: PathBuf,
}

impl Segment {
    pub fn new(path: PathBuf) -> Self {
        Segment {
            name: display_name(&path),
            path,
        }
    }
}

/// A path's file name for display, falling back to empty rather than the
/// full path when it has none (a `..` or root path, in practice never a log file).
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Resolve an optional FILE argument, defaulting to the live log in `dir`. A
/// path that is absolute or already exists is taken as typed; anything else is
/// a name to look for in `dir`, so the same argument works for every command.
pub fn resolve_log_path(dir: &Path, file: Option<&str>) -> PathBuf {
    let Some(path) = file.map(PathBuf::from) else {
        return dir.join("freeswitch.log");
    };
    if path.is_absolute() || path.exists() {
        path
    } else {
        dir.join(path)
    }
}

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_megabytes() {
        assert_eq!(format_size(12_900_000), "12.3M");
    }

    #[test]
    fn format_size_gigabytes() {
        assert_eq!(format_size(2_147_483_648), "2.0G");
    }

    #[test]
    fn format_size_kilobytes() {
        assert_eq!(format_size(500_000), "488.3K");
    }

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(512), "512B");
    }
}
