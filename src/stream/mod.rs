//! Layer 2 structural state machine — groups continuation lines into
//! [`LogEntry`] values, classifying messages and reassembling multi-line
//! blocks (CHANNEL_DATA, SDP, codec negotiation).

mod block;
mod collision;
mod entry;
mod stats;
#[cfg(test)]
mod tests;

use std::collections::VecDeque;

use crate::attached::AttachedLines;
use crate::chain::SEGMENT_BOUNDARY;
use crate::fields::FieldLocation;
use crate::line::{
    is_date_at, is_log_header_at, is_uuid_at, parse_line, LineKind, RawLine, UUID_PREFIX_LEN,
};
use crate::message::{classify_message, MessageKind};

use block::BlockBuilder;
use collision::{WriteCursor, DECODE_DRIFT};

pub use entry::{Block, LogEntry, ParseWarning, SessionReading};
pub use stats::{ParseStats, UnclassifiedLine, UnclassifiedReason, UnclassifiedTracking};

/// `YYYY-MM-DD HH:MM:SS.ffffff` and the space after it — what a log header
/// opens with, and so the least a matched header occupies.
const TIMESTAMP_FIELD_LEN: usize = 27;

/// A Format A line's header: session UUID prefix, then timestamp field.
const FULL_HEADER_LEN: usize = UUID_PREFIX_LEN + TIMESTAMP_FIELD_LEN;

/// Bytes of the line's own header, which the heuristic must not match inside or
/// every line would split on itself.
fn header_len(bytes: &[u8]) -> usize {
    if is_uuid_at(bytes, 0) {
        if bytes.len() > UUID_PREFIX_LEN && bytes[UUID_PREFIX_LEN].is_ascii_digit() {
            FULL_HEADER_LEN
        } else {
            UUID_PREFIX_LEN
        }
    } else if is_date_at(bytes, 0) {
        TIMESTAMP_FIELD_LEN
    } else {
        0
    }
}

/// Every offset a record starts at after the first, plus one verdict per
/// resulting chunk — true only where the write's spent budget ended it.
fn scan_splits(
    bytes: &[u8],
    min_scan: usize,
    first_boundary: Option<usize>,
) -> (Vec<usize>, Vec<bool>) {
    let end = bytes.len();
    let mut next_boundary = first_boundary;
    let mut splits: Vec<usize> = Vec::new();
    let mut cut_verdicts: Vec<bool> = Vec::new();
    let mut chunk_start = 0usize;
    let mut offset = 0usize;
    while offset <= end {
        if let Some(boundary) = next_boundary {
            if offset >= boundary && offset <= boundary + DECODE_DRIFT {
                let uuid = is_uuid_at(bytes, offset);
                if uuid || is_log_header_at(bytes, offset) {
                    splits.push(offset);
                    cut_verdicts.push(true);
                    chunk_start = offset;
                    next_boundary = WriteCursor::boundary_after(uuid, offset, end);
                    offset += UUID_PREFIX_LEN;
                    continue;
                }
            }
        }
        // `min_scan` guards only the heuristic: past the first line of a write
        // the boundary sits early, often inside the header this must skip.
        if offset >= min_scan && is_log_header_at(bytes, offset) {
            let split_at = if offset >= chunk_start + UUID_PREFIX_LEN
                && is_uuid_at(bytes, offset - UUID_PREFIX_LEN)
            {
                offset - UUID_PREFIX_LEN
            } else {
                offset
            };
            if split_at > chunk_start {
                splits.push(split_at);
                cut_verdicts.push(false);
                chunk_start = split_at;
                next_boundary =
                    WriteCursor::boundary_after(is_uuid_at(bytes, split_at), split_at, end);
                offset += TIMESTAMP_FIELD_LEN;
            } else {
                // The chunk's own header. The max keeps the walk moving when
                // the UUID-prefix check rewound split_at behind us.
                offset = (offset + TIMESTAMP_FIELD_LEN).max(offset + 1);
            }
            continue;
        }
        offset += 1;
    }
    cut_verdicts.push(next_boundary.is_some());
    (splits, cut_verdicts)
}

/// Cut `line` at each offset in `splits`, returning the leading chunk and the
/// rest in order. Built right to left with `split_off`, which copies nothing.
fn split_chunks(line: String, splits: &[usize]) -> (String, Vec<String>) {
    let mut head = line;
    let mut chunks: Vec<String> = Vec::with_capacity(splits.len());
    for &at in splits.iter().rev() {
        chunks.push(head.split_off(at));
    }
    chunks.reverse();
    (head, chunks)
}

/// The current line's cut verdict, held until the entry owning that line claims
/// it — emitted on arrival the warning would land on the entry before it.
#[derive(Default)]
struct LineVerdict {
    /// Per chunk of the line, whether it ends at the write's spent budget. One
    /// physical line can hold several such cuts, and each is the record it ends.
    chunks: VecDeque<bool>,
    /// The chunk dispatched before the current one ended at a cut rather than
    /// at its own newline.
    prev_cut: bool,
    cut: bool,
    warning: Option<ParseWarning>,
}

impl LineVerdict {
    /// Move to the next chunk's verdict, returning the previous chunk's.
    fn advance(&mut self) -> bool {
        self.cut = self.chunks.pop_front().unwrap_or(false);
        if self.cut {
            self.warning = Some(ParseWarning::CutLine);
        }
        std::mem::replace(&mut self.prev_cut, self.cut)
    }

    /// Take the warning for the entry now owning the line.
    fn claim(&mut self) -> Option<ParseWarning> {
        self.warning.take()
    }

    /// Drop the cut verdicts at a segment boundary. An unclaimed warning is
    /// still owed to the entry that will claim it, so it stands.
    fn clear_cuts(&mut self) {
        self.chunks.clear();
        self.prev_cut = false;
        self.cut = false;
    }
}

/// The entry being assembled, together with the block it owns. Pairing them
/// is what keeps a block from outliving or preceding its entry.
struct Pending {
    entry: LogEntry,
    block: BlockBuilder,
}

/// Layer 2 structural state machine — groups continuation lines, classifies
/// messages, and detects multi-line blocks (CHANNEL_DATA, SDP, codec negotiation).
///
/// Wraps any `Iterator<Item = String>` and yields [`LogEntry`] values.
/// Maintains `last_uuid` and `last_timestamp` to fill in context for
/// continuation lines that lack their own.
///
/// Use the builder method [`unclassified_tracking()`](LogStream::unclassified_tracking)
/// to control diagnostic detail before iterating.
pub struct LogStream<I> {
    lines: I,
    last_uuid: String,
    last_timestamp: String,
    pending: Option<Pending>,
    stats: ParseStats,
    tracking: UnclassifiedTracking,
    line_number: u64,
    split_pending: VecDeque<String>,
    /// What the line being dispatched says about truncation, claimed by
    /// whichever of `open_entry`/`attach` ends up owning it.
    verdict: LineVerdict,
    /// How much of its budget the `mod_logfile` write in progress has spent.
    cursor: WriteCursor,
    /// Bytes of attached lines one entry may hold before further ones are
    /// dropped. The caller's budget, not a shape of the log.
    max_attached: usize,
}

impl<I: Iterator<Item = String>> LogStream<I> {
    /// Create a new stream from any line iterator.
    pub fn new(lines: I) -> Self {
        LogStream {
            lines,
            last_uuid: String::new(),
            last_timestamp: String::new(),
            pending: None,
            stats: ParseStats::default(),
            tracking: UnclassifiedTracking::CountOnly,
            line_number: 0,
            split_pending: VecDeque::new(),
            verdict: LineVerdict::default(),
            cursor: WriteCursor::default(),
            max_attached: usize::MAX,
        }
    }

    /// Set the unclassified line tracking level (builder pattern). Defaults to `CountOnly`.
    pub fn unclassified_tracking(mut self, level: UnclassifiedTracking) -> Self {
        self.tracking = level;
        self
    }

    /// Cap the bytes of attached lines one entry may hold (builder pattern).
    ///
    /// Defaults to the 4 GiB the attached buffer's `u32` offsets address. A line
    /// past the cap is reported as
    /// [`ParseWarning::AttachedOverflow`] and counted in
    /// [`ParseStats::lines_dropped`], exactly as one past the addressable range is.
    pub fn max_attached_bytes(mut self, max_bytes: usize) -> Self {
        self.max_attached = max_bytes;
        self
    }

    /// Cumulative parsing statistics up to the current position.
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Take all accumulated unclassified line records, leaving the internal vec empty.
    ///
    /// The `lines_unclassified` counter is not reset.
    pub fn drain_unclassified(&mut self) -> Vec<UnclassifiedLine> {
        std::mem::take(&mut self.stats.unclassified_lines)
    }

    fn record_unclassified(&mut self, reason: UnclassifiedReason, data: Option<&str>) {
        self.stats.lines_unclassified += 1;
        match self.tracking {
            UnclassifiedTracking::CountOnly => {}
            UnclassifiedTracking::TrackLines => {
                self.stats.unclassified_lines.push(UnclassifiedLine {
                    line_number: self.line_number,
                    reason,
                    data: None,
                });
            }
            UnclassifiedTracking::CaptureData => {
                self.stats.unclassified_lines.push(UnclassifiedLine {
                    line_number: self.line_number,
                    reason,
                    data: data.map(|s| s.to_string()),
                });
            }
        }
    }

    /// Close the pending entry's block into it and hand the entry over.
    fn take_pending(&mut self) -> Option<LogEntry> {
        let mut pending = self.pending.take()?;
        let (block, warnings) = pending.block.finish();
        pending.entry.block = block;
        pending.entry.warnings.extend(warnings);
        self.stats.lines_in_entries += 1 + pending.entry.attached.len() as u64;
        Some(pending.entry)
    }

    /// Store a raw line on the pending entry, or record that the entry has no
    /// room left for it. Every attach goes through here so a dropped line is
    /// counted once and the accounting invariant still balances.
    fn attach(&mut self, line: &str) {
        let Some(pending) = self.pending.as_mut() else {
            return;
        };
        let over_budget = pending.entry.attached.byte_len() + line.len() + 1 > self.max_attached;
        if over_budget || pending.entry.attached.push(line).is_err() {
            pending.entry.warnings.push(ParseWarning::AttachedOverflow {
                line: ParseWarning::excerpt(line),
            });
            self.stats.lines_dropped += 1;
        } else if self.verdict.cut {
            let i = pending.entry.attached.len() - 1;
            pending.entry.cut_texts.push(FieldLocation::Attached(i));
        }
        pending.entry.warnings.extend(self.verdict.claim());
    }

    /// Absorb a codec trace line into the run the pending entry already owns,
    /// reporting whether it belonged there.
    ///
    /// Only a matching UUID *and* media type continues a run: a video run
    /// following an audio one describes a different negotiation. The message is
    /// classified last, so the common case — no codec run open — costs nothing.
    fn merge_codec_run(&mut self, parsed: &RawLine<'_>, uuid: &str, line: &str) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        let Some(open_media) = pending.block.codec_media() else {
            return false;
        };
        if pending.entry.uuid.as_deref().unwrap_or("") != uuid {
            return false;
        }
        let MessageKind::CodecNegotiation { media } = classify_message(parsed.message) else {
            return false;
        };
        if media != open_media {
            return false;
        }

        let warning = pending.block.push_codec_trace(parsed.message);
        pending.entry.warnings.extend(warning);
        self.attach(line);
        true
    }

    /// Feed a continuation line to the pending entry — both its block and its
    /// raw attached lines.
    fn accumulate_continuation(&mut self, msg: &str, line: &str, has_uuid: bool, prev_cut: bool) {
        let Some(pending) = self.pending.as_mut() else {
            return;
        };
        if prev_cut {
            let warning = pending.block.mark_variable_cut();
            pending.entry.warnings.extend(warning);
        }
        let warning = pending.block.push_continuation(msg, has_uuid);
        pending.entry.warnings.extend(warning);
        self.attach(line);
    }

    /// Install a fresh pending entry for a line that starts one, opening
    /// whatever block its message calls for.
    ///
    /// `uuid` and `timestamp` are passed in rather than read off `parsed`
    /// because a continuation inherits them from context; everything else the
    /// line carries is copied straight across, and is `None` for the
    /// continuation kinds that carry no header.
    fn open_entry(&mut self, parsed: &RawLine<'_>, uuid: String, timestamp: String) {
        let message_kind = classify_message(parsed.message);

        if !uuid.is_empty() {
            self.last_uuid = uuid.clone();
        }
        if parsed.timestamp.is_some() {
            self.last_timestamp = timestamp.clone();
        }

        let mut block = BlockBuilder::open(&message_kind);
        // A codec run's opening line is itself a trace line, and the entry it
        // belongs to does not exist until below — so its warning is collected
        // here rather than routed through `warn`.
        let opening_warning = block.push_codec_trace(parsed.message);

        let entry = LogEntry {
            uuid: if uuid.is_empty() { None } else { Some(uuid) },
            timestamp,
            message: parsed.message.to_string(),
            kind: parsed.kind,
            message_kind,
            level: parsed.level,
            idle_pct: parsed.idle_pct.map(|s| s.to_string()),
            source: parsed.source.map(|s| s.to_string()),
            block: None,
            attached: AttachedLines::new(),
            line_number: self.line_number,
            warnings: self
                .verdict
                .claim()
                .into_iter()
                .chain(opening_warning)
                .collect(),
            cut_texts: if self.verdict.cut {
                vec![FieldLocation::Message]
            } else {
                Vec::new()
            },
        };
        self.pending = Some(Pending { entry, block });
    }
}

impl<I: Iterator<Item = String>> LogStream<I> {
    /// Split a physical line holding more than one record, keeping the write
    /// cursor and the per-chunk cut verdicts in step with what was split.
    ///
    /// Returns the leading chunk; the rest are queued in `split_pending` and
    /// never re-scanned, since [`scan_splits`] already found every offset.
    fn detect_collision(&mut self, line: String, on_disk_len: usize) -> String {
        let bytes = line.as_bytes();
        let prepended = is_uuid_at(bytes, 0);

        // A write starts at every prefixed line and is extended by the bare
        // lines after it; anything else came off the verbatim path, which has
        // no budget to spend and no start to carry forward.
        if prepended {
            self.cursor.begin();
        } else if bytes.is_empty() || is_date_at(bytes, 0) {
            self.cursor.lose();
        }

        let boundary = self.cursor.boundary_in(bytes.len());
        let (splits, cut_verdicts) = scan_splits(bytes, header_len(bytes), boundary);
        self.verdict.chunks = cut_verdicts.into();

        // The trailing chunk carries the write state into the next line.
        let last_start = splits.last().copied().unwrap_or(0);
        if last_start > 0 {
            if is_uuid_at(bytes, last_start) {
                self.cursor.begin();
            } else {
                self.cursor.lose();
            }
        }
        // On-disk cost of the trailing chunk, newline included — which is what
        // `advance` adds back, and which the trimmed length no longer carries.
        self.cursor.advance(on_disk_len - last_start - 1);

        if splits.is_empty() {
            return line;
        }

        let (head, chunks) = split_chunks(line, &splits);
        self.split_pending.extend(chunks);
        head
    }
}

/// What the line source has for the dispatcher.
enum Sourced {
    Line(String),
    /// A segment ended and its context is already cleared; a pending entry is
    /// the last of that segment, not the first of the next.
    Segment,
    Eof,
}

impl<I: Iterator<Item = String>> LogStream<I> {
    /// The next chunk to dispatch: a queued split first, then the underlying
    /// iterator. A queued chunk skips `detect_collision`, which already walked it.
    fn next_line(&mut self) -> Sourced {
        if let Some(split) = self.split_pending.pop_front() {
            self.stats.lines_split += 1;
            return Sourced::Line(split);
        }

        let Some(mut line) = self.lines.next() else {
            return Sourced::Eof;
        };

        // Exactly the sentinel, never merely starting with it: crash padding
        // leaves real log lines with a leading NUL that decodes as valid text.
        if line == SEGMENT_BOUNDARY {
            self.last_uuid.clear();
            self.last_timestamp.clear();
            // A write cannot continue across files, and the cut verdicts
            // describe lines the next segment never saw.
            self.cursor.lose();
            self.verdict.clear_cuts();
            return Sourced::Segment;
        }

        self.line_number += 1;
        self.stats.lines_processed += 1;

        // Trimmed here rather than at decode so the CR is still on the line
        // when its cost is counted; offsets are against the trimmed text.
        let on_disk_len = line.len() + 1;
        if line.ends_with('\r') {
            line.pop();
        }
        Sourced::Line(self.detect_collision(line, on_disk_len))
    }

    /// A line carrying its own header starts an entry, so it closes the one
    /// before it — unless it extends the codec run that entry already owns.
    fn dispatch_primary(&mut self, parsed: &RawLine<'_>, line: &str) -> Option<LogEntry> {
        let uuid = parsed.uuid.unwrap_or("").to_string();
        if self.merge_codec_run(parsed, &uuid, line) {
            return None;
        }

        let yielded = self.take_pending();
        let timestamp = parsed
            .timestamp
            .map(|t| t.to_string())
            .unwrap_or_else(|| self.last_timestamp.clone());
        self.open_entry(parsed, uuid, timestamp);
        yielded
    }

    fn dispatch_uuid_continuation(
        &mut self,
        parsed: &RawLine<'_>,
        line: &str,
        prev_cut: bool,
    ) -> Option<LogEntry> {
        let uuid = parsed.uuid.unwrap_or("").to_string();
        // An EXECUTE trace is its own entry even mid-block, and a different
        // UUID means a different session's output.
        let continues = !parsed.message.starts_with("EXECUTE ")
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.entry.uuid.as_deref() == Some(uuid.as_str()));

        if continues {
            self.accumulate_continuation(parsed.message, line, true, prev_cut);
            return None;
        }
        let yielded = self.take_pending();
        self.open_entry(parsed, uuid, self.last_timestamp.clone());
        yielded
    }

    /// A bare line joins the pending entry, or opens one on inherited context
    /// when there is none to join.
    fn dispatch_bare_continuation(&mut self, parsed: &RawLine<'_>, line: &str, prev_cut: bool) {
        if self.pending.is_some() {
            self.accumulate_continuation(parsed.message, line, false, prev_cut);
            return;
        }
        self.record_unclassified(UnclassifiedReason::OrphanContinuation, Some(line));
        let (uuid, timestamp) = (self.last_uuid.clone(), self.last_timestamp.clone());
        self.open_entry(parsed, uuid, timestamp);
    }

    fn dispatch_empty(&mut self, line: &str) {
        if self.pending.is_some() {
            self.attach(line);
        } else {
            self.stats.lines_empty_orphan += 1;
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for LogStream<I> {
    type Item = LogEntry;

    fn next(&mut self) -> Option<LogEntry> {
        loop {
            let line = match self.next_line() {
                Sourced::Line(line) => line,
                Sourced::Segment => match self.take_pending() {
                    Some(entry) => return Some(entry),
                    None => continue,
                },
                Sourced::Eof => return self.take_pending(),
            };

            let prev_cut = self.verdict.advance();
            let parsed = parse_line(&line);

            let yielded = match parsed.kind {
                LineKind::Full | LineKind::System | LineKind::Truncated => {
                    self.dispatch_primary(&parsed, &line)
                }
                LineKind::UuidContinuation => {
                    self.dispatch_uuid_continuation(&parsed, &line, prev_cut)
                }
                LineKind::BareContinuation => {
                    self.dispatch_bare_continuation(&parsed, &line, prev_cut);
                    None
                }
                LineKind::Empty => {
                    self.dispatch_empty(&line);
                    None
                }
            };

            if yielded.is_some() {
                return yielded;
            }
        }
    }
}
