//! Which log files a directory holds, and which of them a date window can
//! reach.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use freeswitch_log_parser::log_rotation_stamp;

pub struct LogFile {
    pub path: PathBuf,
    pub date: Option<String>,
    pub size: u64,
}

pub fn discover_log_files(dir: &Path) -> io::Result<Vec<LogFile>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !name.starts_with("freeswitch.log") {
            continue;
        }
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let date = log_rotation_stamp(&name).map(str::to_string);
        files.push(LogFile {
            path,
            date,
            size: meta.len(),
        });
    }
    files.sort_by(|a, b| a.date.cmp(&b.date));
    Ok(files)
}

pub fn normalize_date(input: &str) -> String {
    let mut s = input.replace(['T', ':', ' '], "-");
    // Remove trailing dashes from replacement
    while s.ends_with('-') {
        s.pop();
    }
    s
}

pub fn normalize_date_from(input: &str) -> String {
    pad_date(
        &normalize_date(input),
        &["0000", "01", "01", "00", "00", "00"],
    )
}

pub fn normalize_date_until(input: &str) -> String {
    pad_date(
        &normalize_date(input),
        &["9999", "12", "31", "23", "59", "59"],
    )
}

/// Pad a partial `YYYY-MM-DD-HH-MM-SS` date with per-component defaults.
fn pad_date(s: &str, defaults: &[&str; 6]) -> String {
    let parts: Vec<&str> = s.split('-').collect();
    let mut result = Vec::new();
    for (i, default) in defaults.iter().enumerate() {
        if i < parts.len() && !parts[i].is_empty() {
            result.push(parts[i].to_string());
        } else {
            result.push(default.to_string());
        }
    }
    result.join("-")
}

pub fn filter_files_by_date<'a>(
    files: &'a [LogFile],
    from: Option<&str>,
    until: Option<&str>,
) -> Vec<&'a LogFile> {
    let from_norm = from.map(normalize_date_from);
    let until_norm = until.map(normalize_date_until);

    files
        .iter()
        .enumerate()
        .filter(|(i, f)| {
            let Some(ref file_date) = f.date else {
                // Current log (no date) — always include
                return true;
            };

            if let Some(ref until) = until_norm {
                // Skip file N if file_date > until AND previous file also > until
                if file_date.as_str() > until.as_str() && *i > 0 {
                    if let Some(ref prev_date) = files[*i - 1].date {
                        if prev_date.as_str() > until.as_str() {
                            return false;
                        }
                    }
                }
            }

            if let Some(ref from) = from_norm {
                // Include if file_date >= from (file might contain entries up to file_date)
                // But also include the file just before from, since it spans from previous rotation
                if file_date.as_str() < from.as_str() {
                    // Check if next file's date >= from (this file might contain the start)
                    if *i + 1 < files.len() {
                        if let Some(ref next_date) = files[*i + 1].date {
                            if next_date.as_str() >= from.as_str() {
                                return true;
                            }
                        } else {
                            // Next is current log — include this file
                            return true;
                        }
                    }
                    return false;
                }
            }

            true
        })
        .map(|(_, f)| f)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_iso_date() {
        assert_eq!(normalize_date("2026-03-08T15:48"), "2026-03-08-15-48");
    }

    #[test]
    fn normalize_fs_style() {
        assert_eq!(normalize_date("2026-03-08-15-48"), "2026-03-08-15-48");
    }

    #[test]
    fn normalize_space_date() {
        assert_eq!(normalize_date("2026-03-08 15:48"), "2026-03-08-15-48");
    }

    #[test]
    fn pad_from_year_month() {
        assert_eq!(normalize_date_from("2026-03"), "2026-03-01-00-00-00");
    }

    #[test]
    fn pad_until_year_month() {
        assert_eq!(normalize_date_until("2026-03"), "2026-03-31-23-59-59");
    }

    #[test]
    fn pad_from_date() {
        assert_eq!(normalize_date_from("2026-03-08"), "2026-03-08-00-00-00");
    }

    #[test]
    fn pad_until_date() {
        assert_eq!(normalize_date_until("2026-03-08"), "2026-03-08-23-59-59");
    }

    /// A rotation stamp is the *end* of the file's span, so the selection has to
    /// reach one file past each bound. These fixtures rotate daily at midnight.
    fn day_files(days: &[Option<&str>]) -> Vec<LogFile> {
        days.iter()
            .map(|d| LogFile {
                path: PathBuf::from("freeswitch.log"),
                date: d.map(|d| format!("2026-03-{d}-00-00-00")),
                size: 0,
            })
            .collect()
    }

    fn selected(files: &[LogFile], from: Option<&str>, until: Option<&str>) -> Vec<String> {
        filter_files_by_date(files, from, until)
            .iter()
            .map(|f| match &f.date {
                Some(d) => d[8..10].to_string(),
                None => "live".to_string(),
            })
            .collect()
    }

    #[test]
    fn unbounded_selection_keeps_everything() {
        let files = day_files(&[Some("08"), Some("09"), None]);
        assert_eq!(selected(&files, None, None), ["08", "09", "live"]);
    }

    #[test]
    fn from_reaches_back_one_file() {
        // Entries from the 10th live in the file stamped the 11th, and the file
        // stamped the 10th holds the small hours the 9th's rotation left behind.
        let files = day_files(&[Some("08"), Some("09"), Some("10"), Some("11")]);
        assert_eq!(
            selected(&files, Some("2026-03-10"), None),
            ["09", "10", "11"]
        );
    }

    #[test]
    fn from_drops_files_that_end_before_the_next_one_starts() {
        let files = day_files(&[Some("08"), Some("09"), Some("10"), Some("11")]);
        assert_eq!(selected(&files, Some("2026-03-11"), None), ["10", "11"]);
    }

    #[test]
    fn until_keeps_the_file_the_bound_falls_inside() {
        // The 10th's file spans the 9th, so an `until` on the 9th still needs it;
        // the 11th's cannot hold anything that early.
        let files = day_files(&[Some("08"), Some("09"), Some("10"), Some("11")]);
        assert_eq!(
            selected(&files, None, Some("2026-03-09")),
            ["08", "09", "10"]
        );
    }

    #[test]
    fn the_active_log_is_never_excluded_by_date() {
        // It has no stamp, so nothing can prove it lacks entries in the window.
        let files = day_files(&[Some("08"), Some("09"), None]);
        assert_eq!(
            selected(&files, None, Some("2026-03-08")),
            ["08", "09", "live"]
        );
        assert_eq!(selected(&files, Some("2026-03-20"), None), ["09", "live"]);
    }

    #[test]
    fn a_month_bound_spans_the_whole_month() {
        let files = day_files(&[Some("08"), Some("09")]);
        assert_eq!(
            selected(&files, Some("2026-03"), Some("2026-03")),
            ["08", "09"]
        );
        assert!(selected(&files, Some("2026-04"), Some("2026-04")).is_empty());
    }
}
