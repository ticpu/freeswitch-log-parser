use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use freeswitch_log_parser::{decode_log_line, log_rotation_stamp, read_log_lines, Utf8Decode};
use log::{error, warn};
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

/// Resolve an optional FILE argument, defaulting to the live log in `dir`.
pub fn resolve_log_path(dir: &Path, file: Option<&str>) -> PathBuf {
    match file {
        Some(p) => PathBuf::from(p),
        None => dir.join("freeswitch.log"),
    }
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
    Ok(lossy_line_iter(reader))
}

/// Yield log lines as `String`, replacing invalid UTF-8 with U+FFFD instead of
/// panicking. mod_logfile's 2 KiB buffer truncation can chop a multi-byte
/// codepoint mid-character; that benign case is recovered silently. A byte that
/// can't be part of any UTF-8 sequence is genuine corruption — warn, don't hide.
pub fn lossy_line_iter(reader: Box<dyn BufRead>) -> Box<dyn Iterator<Item = String>> {
    Box::new(read_log_lines(reader).map_while(|decoded| match decoded {
        Ok(line) => {
            if let Utf8Decode::InvalidBytes { at } = line.decode {
                warn!("invalid UTF-8 byte at offset {at}, recovered with U+FFFD");
            }
            Some(line.text)
        }
        Err(e) => {
            error!("read error: {e}");
            None
        }
    }))
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
            match open_log_reader(&self.path) {
                Ok(reader) => self.inner = Some(reader),
                Err(e) => {
                    warn!("skipping {}: open failed: {e}", self.path.display());
                    return None;
                }
            }
        }
        let result = self.inner.as_mut()?.next();
        if result.is_none() {
            self.inner = None;
        }
        result
    }
}

struct TailLines<R: BufRead> {
    reader: R,
    /// Bytes of a line the writer has not terminated yet. Emitting it would hand
    /// the parser half a record and the remainder as a bogus continuation.
    pending: Vec<u8>,
    path: PathBuf,
}

impl TailLines<BufReader<fs::File>> {
    fn new(file: fs::File, path: PathBuf) -> Self {
        TailLines {
            reader: BufReader::new(file),
            pending: Vec::new(),
            path,
        }
    }
}

impl<R: BufRead> Iterator for TailLines<R> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        loop {
            match self.reader.read_until(b'\n', &mut self.pending) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(250)),
                Ok(_) => {
                    if self.pending.last() != Some(&b'\n') {
                        continue;
                    }
                    let decoded = decode_log_line(&self.pending);
                    self.pending.clear();
                    if let Utf8Decode::InvalidBytes { at } = decoded.decode {
                        warn!(
                            "invalid UTF-8 byte at offset {at} while tailing {}, recovered with U+FFFD",
                            self.path.display()
                        );
                    }
                    return Some(decoded.text);
                }
                Err(e) => {
                    error!("tail read error on {}, stopping: {e}", self.path.display());
                    return None;
                }
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
    let mut lines = Vec::new();
    for decoded in read_log_lines(reader) {
        let line = decoded?;
        if let Utf8Decode::InvalidBytes { at } = line.decode {
            warn!("invalid UTF-8 byte at offset {at}, recovered with U+FFFD");
        }
        lines.push(line.text);
    }

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
    let tail = TailLines::new(file, path.to_path_buf());

    Ok(Box::new(context.into_iter().chain(tail)))
}

#[cfg(feature = "tui")]
pub fn open_full_tail_reader(path: &Path) -> io::Result<Box<dyn Iterator<Item = String>>> {
    use std::io::{Seek, SeekFrom};

    let reader = open_log_file(path)?;
    let end_pos = fs::File::open(path)?.metadata()?.len();
    let lines = lossy_line_iter(reader);

    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(end_pos))?;
    let tail = TailLines::new(file, path.to_path_buf());

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

    /// Drive the follower over a fixed buffer. Every assertion below consumes
    /// only terminated lines, so the EOF sleep is never reached.
    fn tail_over<R: BufRead>(reader: R) -> TailLines<R> {
        TailLines {
            reader,
            pending: Vec::new(),
            path: PathBuf::from("test.log"),
        }
    }

    fn cursor(bytes: &[u8]) -> io::Cursor<Vec<u8>> {
        io::Cursor::new(bytes.to_vec())
    }

    /// Errors instead of reporting EOF, so a test can reach the terminal arm of
    /// `TailLines::next` without waiting on the follower's EOF sleep.
    struct FailAtEof(io::Cursor<Vec<u8>>);

    impl io::Read for FailAtEof {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match io::Read::read(&mut self.0, buf)? {
                0 => Err(io::Error::other("simulated read failure")),
                n => Ok(n),
            }
        }
    }

    #[test]
    fn tail_survives_truncated_codepoint() {
        // "é" (0xC3 0xA9) cut after its lead byte, as mod_logfile's 2 KiB
        // buffer does; the follower must keep going, not stop on InvalidData.
        let lines: Vec<String> = tail_over(cursor(b"caf\xc3\nnext line\n")).take(2).collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("caf"), "line: {:?}", lines[0]);
        assert_eq!(lines[1], "next line");
    }

    #[test]
    fn tail_recovers_invalid_bytes() {
        let lines: Vec<String> = tail_over(cursor(b"bad\xffbyte\nafter\n")).take(2).collect();
        assert_eq!(lines[0], "bad\u{fffd}byte");
        assert_eq!(lines[1], "after");
    }

    #[test]
    fn tail_strips_crlf() {
        let lines: Vec<String> = tail_over(cursor(b"one\r\ntwo\n")).take(2).collect();
        assert_eq!(lines, vec!["one", "two"]);
    }

    #[test]
    fn tail_withholds_unterminated_line() {
        // The writer has not flushed the newline yet: emitting now would yield
        // half a record, and the remainder as a bogus continuation.
        let mut tail = tail_over(BufReader::new(FailAtEof(cursor(b"complete\nhalf-writ"))));
        assert_eq!(tail.next(), Some("complete".to_string()));
        assert_eq!(tail.next(), None);
        assert_eq!(tail.pending, b"half-writ");
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
