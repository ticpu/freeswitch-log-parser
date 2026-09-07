//! Turning a log file into lines: the decompressing reader, the follower, and
//! the read cap they share.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::Context;
use freeswitch_log_parser::{
    decode_log_line, read_log_line_capped, read_log_lines_capped, trim_capped_tail, OverCap,
    Utf8Decode,
};
use log::{error, warn};
use xz2::read::XzDecoder;

use super::display_name;

/// One file's over-cap lines: the first is reported as it happens, the rest
/// counted into a single summary when the reader is dropped.
struct CapReport {
    name: String,
    count: u64,
    largest: usize,
}

impl CapReport {
    fn new(name: String) -> Self {
        CapReport {
            name,
            count: 0,
            largest: 0,
        }
    }

    fn record(&mut self, over: OverCap) {
        self.count += 1;
        self.largest = self.largest.max(over.line_bytes);
        if self.count == 1 {
            warn!(
                "{}: line of {} bytes read only to {}, remainder dropped",
                self.name, over.line_bytes, over.cap
            );
        }
    }
}

impl Drop for CapReport {
    fn drop(&mut self) {
        if self.count > 1 {
            warn!(
                "{}: {} lines exceeded the read cap, largest {} bytes",
                self.name, self.count, self.largest
            );
        }
    }
}

pub fn open_log_file(path: &Path) -> anyhow::Result<Box<dyn BufRead>> {
    let file =
        fs::File::open(path).with_context(|| format!("opening log file {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "xz" {
        Ok(Box::new(BufReader::new(XzDecoder::new(file))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

pub fn open_log_reader(
    path: &Path,
    max_line_bytes: usize,
) -> anyhow::Result<Box<dyn Iterator<Item = String>>> {
    let reader = open_log_file(path)?;
    Ok(lossy_line_iter(reader, display_name(path), max_line_bytes))
}

/// Yield log lines as `String`, replacing invalid UTF-8 with U+FFFD instead of
/// panicking. mod_logfile's 2 KiB buffer truncation can chop a multi-byte
/// codepoint mid-character; that benign case is recovered silently. A byte that
/// can't be part of any UTF-8 sequence is genuine corruption — warn, don't hide.
///
/// A line past `max_line_bytes` is read only that far; what was dropped is
/// reported, never silently missing.
pub fn lossy_line_iter(
    reader: Box<dyn BufRead>,
    name: String,
    max_line_bytes: usize,
) -> Box<dyn Iterator<Item = String>> {
    let mut cap_report = CapReport::new(name);
    Box::new(read_log_lines_capped(reader, max_line_bytes).map_while(
        move |decoded| match decoded {
            Ok(capped) => {
                if let Some(over) = capped.over_cap {
                    cap_report.record(over);
                }
                if let Utf8Decode::InvalidBytes { at } = capped.line.decode {
                    warn!("invalid UTF-8 byte at offset {at}, recovered with U+FFFD");
                }
                Some(capped.line.text)
            }
            Err(e) => {
                error!("read error: {e}");
                None
            }
        },
    ))
}

pub fn lazy_log_reader(path: PathBuf, max_line_bytes: usize) -> Box<dyn Iterator<Item = String>> {
    Box::new(LazyLogReader {
        path,
        inner: None,
        max_line_bytes,
    })
}

struct LazyLogReader {
    path: PathBuf,
    inner: Option<Box<dyn Iterator<Item = String>>>,
    max_line_bytes: usize,
}

impl Iterator for LazyLogReader {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.inner.is_none() {
            match open_log_reader(&self.path, self.max_line_bytes) {
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
    /// Length of that line as written, which past the cap outruns `pending`.
    pending_bytes: usize,
    path: PathBuf,
    max_line_bytes: usize,
    cap_report: CapReport,
}

impl TailLines<BufReader<fs::File>> {
    fn new(file: fs::File, path: PathBuf, max_line_bytes: usize) -> Self {
        let cap_report = CapReport::new(display_name(&path));
        TailLines {
            reader: BufReader::new(file),
            pending: Vec::new(),
            pending_bytes: 0,
            path,
            max_line_bytes,
            cap_report,
        }
    }
}

impl<R: BufRead> Iterator for TailLines<R> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        loop {
            let read = match read_log_line_capped(
                &mut self.reader,
                self.max_line_bytes,
                &mut self.pending,
            ) {
                Ok(read) => read,
                Err(e) => {
                    error!("tail read error on {}, stopping: {e}", self.path.display());
                    return None;
                }
            };
            let Some(read) = read else {
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            };
            self.pending_bytes += read.line_bytes;
            if !read.terminated {
                continue;
            }
            if self.pending_bytes > self.max_line_bytes {
                self.cap_report
                    .record(OverCap::new(self.max_line_bytes, self.pending_bytes));
                trim_capped_tail(&mut self.pending);
            }
            let decoded = decode_log_line(&self.pending);
            self.pending.clear();
            self.pending_bytes = 0;
            if let Utf8Decode::InvalidBytes { at } = decoded.decode {
                warn!(
                    "invalid UTF-8 byte at offset {at} while tailing {}, recovered with U+FFFD",
                    self.path.display()
                );
            }
            return Some(decoded.text);
        }
    }
}

fn read_tail_context(
    path: &Path,
    n_lines: usize,
    max_line_bytes: usize,
) -> anyhow::Result<(Vec<String>, u64)> {
    use std::io::{Seek, SeekFrom};

    let mut file =
        fs::File::open(path).with_context(|| format!("opening log file {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();

    if n_lines == 0 || len == 0 {
        return Ok((Vec::new(), len));
    }

    let seek_back = (n_lines as u64).saturating_mul(1024).min(len);
    let seek_pos = len - seek_back;

    if seek_pos > 0 {
        file.seek(SeekFrom::Start(seek_pos))
            .with_context(|| format!("seeking to {seek_pos} in {}", path.display()))?;
    }

    let mut lines: Vec<String> = lossy_line_iter(
        Box::new(BufReader::new(file)),
        display_name(path),
        max_line_bytes,
    )
    .collect();

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
    max_line_bytes: usize,
) -> anyhow::Result<Box<dyn Iterator<Item = String>>> {
    use std::io::{Seek, SeekFrom};

    let (context, file_len) = read_tail_context(path, initial_lines, max_line_bytes)?;

    let mut file =
        fs::File::open(path).with_context(|| format!("opening log file {}", path.display()))?;
    file.seek(SeekFrom::Start(file_len))
        .with_context(|| format!("seeking to the end of {}", path.display()))?;
    let tail = TailLines::new(file, path.to_path_buf(), max_line_bytes);

    Ok(Box::new(context.into_iter().chain(tail)))
}

#[cfg(feature = "tui")]
pub fn open_full_tail_reader(
    path: &Path,
    max_line_bytes: usize,
) -> anyhow::Result<Box<dyn Iterator<Item = String>>> {
    use std::io::{Seek, SeekFrom};

    let reader = open_log_file(path)?;
    let end_pos = fs::File::open(path)
        .and_then(|f| f.metadata())
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    let lines = lossy_line_iter(reader, display_name(path), max_line_bytes);

    let mut file =
        fs::File::open(path).with_context(|| format!("opening log file {}", path.display()))?;
    file.seek(SeekFrom::Start(end_pos))
        .with_context(|| format!("seeking to the end of {}", path.display()))?;
    let tail = TailLines::new(file, path.to_path_buf(), max_line_bytes);

    Ok(Box::new(lines.chain(tail)))
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// Drive the follower over a fixed buffer. Every assertion below consumes
    /// only terminated lines, so the EOF sleep is never reached.
    fn tail_over<R: BufRead>(reader: R) -> TailLines<R> {
        tail_over_capped(reader, usize::MAX)
    }

    fn tail_over_capped<R: BufRead>(reader: R, max_line_bytes: usize) -> TailLines<R> {
        TailLines {
            reader,
            pending: Vec::new(),
            pending_bytes: 0,
            path: PathBuf::from("test.log"),
            max_line_bytes,
            cap_report: CapReport::new("test.log".to_string()),
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
    fn tail_hands_the_cr_on_to_the_stream() {
        // LogStream counts a line's bytes against mod_logfile's write budget
        // before trimming, so the reader must not drop one.
        let lines: Vec<String> = tail_over(cursor(b"one\r\ntwo\n")).take(2).collect();
        assert_eq!(lines, vec!["one\r", "two"]);
    }

    #[test]
    fn tail_caps_a_long_line_and_keeps_framing() {
        let lines: Vec<String> = tail_over_capped(cursor(b"aaaaaaaaaa\nbb\n"), 4)
            .take(2)
            .collect();
        assert_eq!(lines, vec!["aaaa", "bb"]);
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
}
