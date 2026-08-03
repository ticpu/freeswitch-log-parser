use std::collections::VecDeque;
use std::io::{self, Write};

use freeswitch_log_parser::{LogEntry, MessageKind, SegmentTracker, SessionSnapshot};

use crate::output::{EntryPrinter, FilterConfig};
use crate::separator_entry;

struct Buffered {
    bytes: Vec<u8>,
    seg: Option<(usize, String)>,
    date: String,
}

/// Drives match output with optional grep-style `-A`/`-B`/`-C` context. When
/// both context counts are zero it degenerates to "print each match", so the
/// no-context path stays byte-for-byte identical to direct printing.
pub struct Emitter<'a> {
    printer: &'a EntryPrinter,
    filter: &'a FilterConfig,
    seg_tracker: &'a SegmentTracker,
    stats_only: bool,
    before: usize,
    after: usize,
    ring: VecDeque<Buffered>,
    remaining_after: usize,
    has_printed: bool,
    contiguous: bool,
    last_seg: Option<usize>,
    last_date: String,
    pub count: u64,
}

impl<'a> Emitter<'a> {
    pub fn new(
        printer: &'a EntryPrinter,
        filter: &'a FilterConfig,
        seg_tracker: &'a SegmentTracker,
        stats_only: bool,
        before: usize,
        after: usize,
    ) -> Self {
        Emitter {
            printer,
            filter,
            seg_tracker,
            stats_only,
            before,
            after,
            ring: VecDeque::with_capacity(before),
            remaining_after: 0,
            has_printed: false,
            contiguous: false,
            last_seg: None,
            last_date: String::new(),
            count: 0,
        }
    }

    fn has_context(&self) -> bool {
        self.before > 0 || self.after > 0
    }

    pub fn on_entry(
        &mut self,
        out: &mut dyn Write,
        entry: &LogEntry,
        session: Option<&SessionSnapshot>,
    ) -> io::Result<()> {
        self.count += 1;
        if !self.filter.matches(entry) {
            if self.has_context() {
                self.feed_nonmatch(out, entry, session)?;
            }
            return Ok(());
        }
        if self.stats_only {
            return Ok(());
        }
        self.feed_match(out, entry, session)
    }

    fn feed_match(
        &mut self,
        out: &mut dyn Write,
        entry: &LogEntry,
        session: Option<&SessionSnapshot>,
    ) -> io::Result<()> {
        if self.has_context() && self.has_printed && !self.contiguous {
            writeln!(out, "--")?;
        }
        let ring: Vec<Buffered> = self.ring.drain(..).collect();
        for b in &ring {
            self.emit_bytes(out, b)?;
        }
        self.emit_entry(out, entry, session)?;
        self.remaining_after = self.after;
        self.has_printed = true;
        self.contiguous = true;
        Ok(())
    }

    fn feed_nonmatch(
        &mut self,
        out: &mut dyn Write,
        entry: &LogEntry,
        session: Option<&SessionSnapshot>,
    ) -> io::Result<()> {
        if self.remaining_after > 0 {
            self.remaining_after -= 1;
            self.has_printed = true;
            self.emit_entry(out, entry, session)
        } else {
            if self.before > 0 {
                let mut bytes = Vec::new();
                self.printer.print_entry(&mut bytes, entry, session, None)?;
                let seg = self
                    .seg_tracker
                    .segment_for_line(entry.line_number)
                    .map(|(i, n)| (i, n.to_string()));
                if self.ring.len() == self.before {
                    self.ring.pop_front();
                }
                self.ring.push_back(Buffered {
                    bytes,
                    seg,
                    date: entry.timestamp.clone(),
                });
            }
            self.contiguous = false;
            Ok(())
        }
    }

    fn emit_entry(
        &mut self,
        out: &mut dyn Write,
        entry: &LogEntry,
        session: Option<&SessionSnapshot>,
    ) -> io::Result<()> {
        let seg = self
            .seg_tracker
            .segment_for_line(entry.line_number)
            .map(|(i, n)| (i, n.to_string()));
        self.print_separators(
            out,
            seg.as_ref().map(|(i, n)| (*i, n.as_str())),
            &entry.timestamp,
        )?;
        self.printer.print_entry(out, entry, session, None)
    }

    fn emit_bytes(&mut self, out: &mut dyn Write, b: &Buffered) -> io::Result<()> {
        self.print_separators(out, b.seg.as_ref().map(|(i, n)| (*i, n.as_str())), &b.date)?;
        out.write_all(&b.bytes)
    }

    fn print_separators(
        &mut self,
        out: &mut dyn Write,
        seg: Option<(usize, &str)>,
        timestamp: &str,
    ) -> io::Result<()> {
        if let Some((idx, name)) = seg {
            if self.last_seg != Some(idx) {
                self.last_seg = Some(idx);
                let sep = separator_entry(MessageKind::FileChange, name.to_string());
                self.printer.print_entry(out, &sep, None, None)?;
            }
        }
        if timestamp.len() >= 10 {
            let date = &timestamp[..10];
            if date != self.last_date {
                self.last_date = date.to_string();
                let sep = separator_entry(MessageKind::DateChange, self.last_date.clone());
                self.printer.print_entry(out, &sep, None, None)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeswitch_log_parser::{AttachedLines, LineKind, TrackedChain};

    use crate::output::{ColorMode, FilterParams};

    fn entry(uuid: &str) -> LogEntry {
        LogEntry {
            uuid: uuid.to_string(),
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: "x".to_string(),
            kind: LineKind::Full,
            message_kind: MessageKind::General,
            block: None,
            attached: AttachedLines::new(),
            line_number: 0,
            warnings: Vec::new(),
        }
    }

    fn run(before: usize, after: usize, uuids: &[&str]) -> String {
        let printer = EntryPrinter {
            color: ColorMode::Never,
            show_blocks: false,
            show_session: false,
            show_filename: false,
            show_line_numbers: false,
        };
        let filter = crate::output::tests::filter(FilterParams {
            uuid: vec!["m".into()],
            ..Default::default()
        });
        let (_chain, tracker) = TrackedChain::new(Vec::new());
        let mut emitter = Emitter::new(&printer, &filter, &tracker, false, before, after);
        let mut out: Vec<u8> = Vec::new();
        for u in uuids {
            emitter.on_entry(&mut out, &entry(u), None).unwrap();
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn context_before_after() {
        // only "Mx" matches "m"; -B1 -A1 yields the b/Mx/c window
        let out = run(1, 1, &["a", "b", "Mx", "c", "d"]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains(" b "));
        assert!(lines[1].contains(" Mx "));
        assert!(lines[2].contains(" c "));
    }

    #[test]
    fn no_context_prints_only_matches() {
        let out = run(0, 0, &["a", "Mx", "b", "My"]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(!out.contains("--"));
    }

    #[test]
    fn divider_between_noncontiguous_groups() {
        // two matches separated by enough non-matches that after/before don't overlap
        let out = run(1, 1, &["Mx", "a", "b", "c", "My"]);
        assert!(out.contains("\n--\n"));
    }
}
