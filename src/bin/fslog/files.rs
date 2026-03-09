use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use xz2::read::XzDecoder;

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
        let date = extract_date(&name);
        files.push(LogFile {
            path,
            date,
            size: meta.len(),
        });
    }
    files.sort_by(|a, b| a.date.cmp(&b.date));
    Ok(files)
}

fn extract_date(filename: &str) -> Option<String> {
    let prefix = "freeswitch.log.";
    if !filename.starts_with(prefix) {
        return None;
    }
    let rest = &filename[prefix.len()..];
    if rest.len() < 19 {
        return None;
    }
    let candidate = &rest[..19];
    if !validate_date_pattern(candidate) {
        return None;
    }
    Some(candidate.to_string())
}

fn validate_date_pattern(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 19 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            4 | 7 | 10 | 13 | 16 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_digit() {
                    return false;
                }
            }
        }
    }
    true
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
    let normalized = normalize_date(input);
    pad_date_min(&normalized)
}

pub fn normalize_date_until(input: &str) -> String {
    let normalized = normalize_date(input);
    pad_date_max(&normalized)
}

fn pad_date_min(s: &str) -> String {
    // YYYY-MM-DD-HH-MM-SS  (19 chars)
    // Pad with minimum values
    let parts: Vec<&str> = s.split('-').collect();
    let defaults_min = ["0000", "01", "01", "00", "00", "00"];
    let mut result = Vec::new();
    for (i, default) in defaults_min.iter().enumerate() {
        if i < parts.len() && !parts[i].is_empty() {
            result.push(parts[i].to_string());
        } else {
            result.push(default.to_string());
        }
    }
    result.join("-")
}

fn pad_date_max(s: &str) -> String {
    let parts: Vec<&str> = s.split('-').collect();
    let defaults_max = ["9999", "12", "31", "23", "59", "59"];
    let mut result = Vec::new();
    for (i, default) in defaults_max.iter().enumerate() {
        if i < parts.len() && !parts[i].is_empty() {
            result.push(parts[i].to_string());
        } else {
            result.push(default.to_string());
        }
    }
    result.join("-")
}

pub fn normalize_entry_timestamp(ts: &str) -> String {
    // Entry timestamps: "YYYY-MM-DD HH:MM:SS.ffffff"
    // Normalize to "YYYY-MM-DD-HH-MM-SS" for comparison
    if ts.len() < 19 {
        return normalize_date(ts);
    }
    let date_part = &ts[..10];
    let time_part = &ts[11..19.min(ts.len())];
    format!("{}-{}", date_part, time_part.replace(':', "-"))
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

pub fn open_log_file(path: &Path) -> io::Result<Box<dyn BufRead>> {
    let file = fs::File::open(path)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "xz" {
        Ok(Box::new(BufReader::new(XzDecoder::new(file))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

pub fn open_log_reader(path: &Path) -> io::Result<Box<dyn Iterator<Item = String>>> {
    let reader = open_log_file(path)?;
    Ok(Box::new(reader.lines().map(|l| l.expect("read error"))))
}

pub fn lazy_log_reader(path: PathBuf) -> Box<dyn Iterator<Item = String>> {
    Box::new(LazyLogReader { path, inner: None })
}

struct LazyLogReader {
    path: PathBuf,
    inner: Option<Box<dyn Iterator<Item = String>>>,
}

impl Iterator for LazyLogReader {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.inner.is_none() {
            self.inner = Some(open_log_reader(&self.path).ok()?);
        }
        let result = self.inner.as_mut()?.next();
        if result.is_none() {
            self.inner = None;
        }
        result
    }
}

struct TailLines {
    reader: BufReader<fs::File>,
    buf: String,
}

impl TailLines {
    fn new(file: fs::File) -> Self {
        TailLines {
            reader: BufReader::new(file),
            buf: String::new(),
        }
    }
}

impl Iterator for TailLines {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        loop {
            self.buf.clear();
            match self.reader.read_line(&mut self.buf) {
                Ok(0) => {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                Ok(_) => {
                    let line = self.buf.trim_end_matches(['\n', '\r']).to_string();
                    return Some(line);
                }
                Err(_) => return None,
            }
        }
    }
}

fn read_tail_context(path: &Path, n_lines: usize) -> io::Result<(Vec<String>, u64)> {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();

    if n_lines == 0 || len == 0 {
        return Ok((Vec::new(), len));
    }

    let seek_back = (n_lines as u64).saturating_mul(1024).min(len);
    let seek_pos = len - seek_back;

    if seek_pos > 0 {
        file.seek(SeekFrom::Start(seek_pos))?;
    }

    let reader = BufReader::new(file);
    let mut lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    if seek_pos > 0 && !lines.is_empty() {
        lines.remove(0);
    }

    if lines.len() > n_lines {
        lines.drain(..lines.len() - n_lines);
    }

    Ok((lines, len))
}

pub fn open_tail_reader(
    path: &Path,
    initial_lines: usize,
) -> io::Result<Box<dyn Iterator<Item = String>>> {
    use std::io::{Seek, SeekFrom};

    let (context, file_len) = read_tail_context(path, initial_lines)?;

    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(file_len))?;
    let tail = TailLines::new(file);

    Ok(Box::new(context.into_iter().chain(tail)))
}

pub fn open_full_tail_reader(path: &Path) -> io::Result<Box<dyn Iterator<Item = String>>> {
    use std::io::{Seek, SeekFrom};

    let reader = open_log_file(path)?;
    let end_pos = fs::File::open(path)?.metadata()?.len();
    let lines = reader.lines().map(|l| l.expect("read error"));

    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(end_pos))?;
    let tail = TailLines::new(file);

    Ok(Box::new(lines.chain(tail)))
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
    fn extract_date_standard() {
        assert_eq!(
            extract_date("freeswitch.log.2026-03-08-16-52-07.1.xz"),
            Some("2026-03-08-16-52-07".to_string()),
        );
    }

    #[test]
    fn extract_date_no_extension() {
        assert_eq!(
            extract_date("freeswitch.log.2025-12-15-16-34-42.1"),
            Some("2025-12-15-16-34-42".to_string()),
        );
    }

    #[test]
    fn extract_date_current_log() {
        assert_eq!(extract_date("freeswitch.log"), None);
    }

    #[test]
    fn extract_date_invalid() {
        assert_eq!(extract_date("freeswitch.log.not-a-date.xz"), None);
    }

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

    #[test]
    fn normalize_entry_ts() {
        assert_eq!(
            normalize_entry_timestamp("2026-03-08 15:48:30.123456"),
            "2026-03-08-15-48-30",
        );
    }

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

    #[test]
    fn validate_date_pattern_valid() {
        assert!(validate_date_pattern("2026-03-08-16-52-07"));
    }

    #[test]
    fn validate_date_pattern_invalid() {
        assert!(!validate_date_pattern("not-a-date-pattern!"));
        assert!(!validate_date_pattern("2026-03-08"));
    }
}
