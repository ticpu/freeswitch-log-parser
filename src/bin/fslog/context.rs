use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Write};

use freeswitch_log_parser::{
    FieldLocation, LogEntry, MessageKind, SegmentTracker, SessionSnapshot,
};

use crate::output::{EntryPrinter, FilterConfig, Hidden, Verdict};
use crate::separator_entry;

/// Entries the filter rejected on a scope boundary alone, by the scope that
/// would have admitted them.
#[derive(Default)]
pub struct HiddenCounts {
    pub pattern_in_uuid: u64,
    pub pattern_in_blocks: u64,
    pub uuid_in_body: u64,
}

impl HiddenCounts {
    fn tally(&mut self, h: Hidden) {
        match h {
            Hidden::PatternInUuid => self.pattern_in_uuid += 1,
            Hidden::PatternInBlocks => self.pattern_in_blocks += 1,
            Hidden::UuidInBody => self.uuid_in_body += 1,
        }
    }
}

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
    /// Entries fed in, matching or not — what `--stats` reports.
    pub count: u64,
    /// Entries that passed the filter, which is what "found nothing" means.
    pub matched: u64,
    /// What a narrowed scope kept out, reported at end of run.
    pub hidden: HiddenCounts,
    /// Field spans of the matching entries, tallied only under `--stats`.
    pub fields: FieldCounts,
}

/// Per-kind field-span tally, for the `--stats` coverage line.
#[derive(Debug, Default)]
pub struct FieldCounts {
    pub entries_with_fields: u64,
    pub in_message: u64,
    pub in_attached: u64,
    by_kind: BTreeMap<&'static str, u64>,
}

impl FieldCounts {
    fn tally(&mut self, entry: &LogEntry) {
        let fields = entry.fields();
        if fields.is_empty() {
            return;
        }
        self.entries_with_fields += 1;
        for f in fields {
            *self.by_kind.entry(f.kind.label()).or_default() += 1;
            match f.at {
                FieldLocation::Message => self.in_message += 1,
                FieldLocation::Attached(_) => self.in_attached += 1,
            }
        }
    }

    pub fn total(&self) -> u64 {
        self.by_kind.values().sum()
    }

    /// Kinds seen, most frequent first.
    pub fn by_kind(&self) -> Vec<(&'static str, u64)> {
        let mut v: Vec<_> = self.by_kind.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v
    }
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
            matched: 0,
            hidden: HiddenCounts::default(),
            fields: FieldCounts::default(),
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
        match self.filter.verdict(entry) {
            Verdict::Match => {}
            verdict => {
                if let Verdict::Hidden(h) = verdict {
                    self.hidden.tally(h);
                }
                if self.has_context() {
                    self.feed_nonmatch(out, entry, session)?;
                }
                return Ok(());
            }
        }
        self.matched += 1;
        if self.stats_only {
            // Locating fields costs a re-parse per entry, so it is paid only
            // when the run exists to report on them.
            self.fields.tally(entry);
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
    use freeswitch_log_parser::TrackedChain;

    use crate::output::{ColorMode, FilterParams};

    fn entry(uuid: &str) -> LogEntry {
        LogEntry {
            uuid: Some(uuid.to_string()),
            ..LogEntry::synthetic("x")
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

    const CALL: &str = "aaaaaaaa-1111-1111-1111-111111111111";

    /// One session's output: a message naming its own UUID, a CHANNEL_DATA dump
    /// whose attached line names it, and two lines that carry it in the UUID
    /// column alone.
    fn session_log() -> Vec<String> {
        [
            format!("{CALL} 2026-05-17 09:48:33.534240 99.99% [NOTICE] switch_channel.c:1118 New Channel sofia/internal/caller@example.test [{CALL}]"),
            format!("{CALL} 2026-05-17 09:48:33.554242 99.99% [INFO] mod_dptools.c:1885 CHANNEL_DATA:"),
            format!("{CALL} Unique-ID: [{CALL}]"),
            format!("{CALL} 2026-05-17 09:48:34.000000 99.99% [NOTICE] switch_rtp.c:100 Audio Codec Compare PCMU"),
            format!("{CALL} 2026-05-17 09:50:55.014000 99.99% [NOTICE] switch_core_session.c:1234 State Change CS_EXECUTE -> CS_DESTROY"),
        ]
        .to_vec()
    }

    /// Entries emitted and entries bucketed, at context 0 — with `-A`/`-B`/`-C`
    /// the output also carries non-matching entries and `matched` stops meaning
    /// "what the filter accepted".
    fn tally(filter: &FilterConfig) -> (u64, HiddenCounts) {
        let printer = EntryPrinter {
            color: ColorMode::Never,
            show_blocks: false,
            show_session: false,
            show_filename: false,
            show_line_numbers: false,
        };
        let (_chain, tracker) = TrackedChain::new(Vec::new());
        let mut emitter = Emitter::new(&printer, filter, &tracker, false, 0, 0);
        let mut out: Vec<u8> = Vec::new();
        for e in freeswitch_log_parser::LogStream::new(session_log().into_iter()) {
            emitter.on_entry(&mut out, &e, None).unwrap();
        }
        (emitter.matched, emitter.hidden)
    }

    /// Every line here belongs to the session, which is what makes the sum
    /// exact: a system line naming the UUID has no UUID column, so the pattern
    /// shows it and `-u` never can.
    #[test]
    fn a_sessions_own_lines_are_fully_accounted_for() {
        let (shown, hidden) = tally(&crate::output::tests::filter(FilterParams {
            grep: Some(regex::Regex::new(CALL).expect("test pattern compiles")),
            ..Default::default()
        }));
        assert_eq!(shown, 1, "only the New Channel message names it");
        assert_eq!(hidden.pattern_in_uuid, 3);
        assert_eq!(hidden.pattern_in_blocks, 0);

        let (by_uuid, _) = tally(&crate::output::tests::filter(FilterParams {
            uuid: vec![CALL.into()],
            ..Default::default()
        }));
        assert_eq!(shown + hidden.pattern_in_uuid, by_uuid);
    }

    #[test]
    fn divider_between_noncontiguous_groups() {
        // two matches separated by enough non-matches that after/before don't overlap
        let out = run(1, 1, &["Mx", "a", "b", "c", "My"]);
        assert!(out.contains("\n--\n"));
    }
}
