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
use collision::{WriteCursor, DECODE_DRIFT, WRITE_LIMIT};

pub use entry::{Block, LineEncoding, LogEntry, ParseWarning, SessionReading};
pub use stats::{ParseStats, UnclassifiedLine, UnclassifiedReason, UnclassifiedTracking};

/// Where the next cut would fall after a split at `at`, if the chunk starting
/// there is a prepend write that can reach its budget inside this line.
fn arm_boundary(prepended: bool, at: usize, line_len: usize) -> Option<usize> {
    (prepended && at + WRITE_LIMIT <= line_len).then_some(at + WRITE_LIMIT)
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
    /// Whether the line dispatched before the current one ended at a split
    /// rather than at its own newline — the logger cut it short.
    prev_line_cut: bool,
    /// The same verdict about the line currently being dispatched, claimed by
    /// whichever of `open_entry`/`attach` ends up owning it.
    line_cut: bool,
    /// A warning about the line currently being dispatched, claimed by whichever
    /// of `open_entry`/`attach` ends up owning it. Emitting it on arrival would
    /// pin it on the pending entry, which for a line that starts a new one is
    /// the wrong entry entirely.
    line_warning: Option<ParseWarning>,
    /// How much of its budget the `mod_logfile` write in progress has spent.
    cursor: WriteCursor,
    /// Which write path produced the line being dispatched, claimed by the
    /// entry it opens.
    line_encoding: LineEncoding,
    /// Per chunk of the physical line being dispatched, whether it ends at the
    /// write's spent budget. One physical line can hold several such cuts, and
    /// each is the record it ends, so a single slot would report only the first.
    cut_verdicts: VecDeque<bool>,
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
            prev_line_cut: false,
            line_cut: false,
            line_warning: None,
            cursor: WriteCursor::default(),
            line_encoding: LineEncoding::Unknown,
            cut_verdicts: VecDeque::new(),
        }
    }

    /// Set the unclassified line tracking level (builder pattern). Defaults to `CountOnly`.
    pub fn unclassified_tracking(mut self, level: UnclassifiedTracking) -> Self {
        self.tracking = level;
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
        if pending.entry.attached.push(line).is_err() {
            pending.entry.warnings.push(ParseWarning::AttachedOverflow {
                line: ParseWarning::excerpt(line),
            });
            self.stats.lines_dropped += 1;
        } else if self.line_cut {
            let i = pending.entry.attached.len() - 1;
            pending.entry.cut_texts.push(FieldLocation::Attached(i));
        }
        pending.entry.warnings.extend(self.line_warning.take());
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
            let warning = pending.block.close_cut_variable();
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
            encoding: self.line_encoding,
            warnings: self
                .line_warning
                .take()
                .into_iter()
                .chain(opening_warning)
                .collect(),
            cut_texts: if self.line_cut {
                vec![FieldLocation::Message]
            } else {
                Vec::new()
            },
        };
        self.pending = Some(Pending { entry, block });
    }
}

impl<I: Iterator<Item = String>> LogStream<I> {
    /// Detect same-line collisions where multiple log entries were concatenated
    /// without a newline separator.
    ///
    /// Two collision mechanisms exist in production:
    ///
    /// 1. **Buffer truncation** (Format E): a `mod_logfile` write spends the
    ///    whole 2047-byte budget, so the `\n` it still owed never fits and the
    ///    next write lands on the same physical line. The offset is exact —
    ///    `WriteCursor` tracks how much of the budget the write in progress has
    ///    spent — and a write may span a prefixed line plus the bare ones after
    ///    it, so the cut often falls on a short line.
    ///
    /// 2. **Write contention**: multiple threads writing to the log file can
    ///    interleave output, producing concatenated entries at any line length.
    ///    Common with system lines (Format B) that lack UUID prefixes.
    ///
    /// A UUID splits only at the exact boundary; a full timestamp header splits
    /// anywhere, since contention answers to no budget.
    ///
    /// Returns the (possibly truncated) line. If a collision is detected,
    /// the suffix is stored in `split_pending` for processing in the next
    /// iteration. Recursive: split suffixes pass through this function again.
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
        self.line_encoding = if prepended || self.cursor.is_live() {
            LineEncoding::Prepended
        } else if bytes.is_empty() || is_date_at(bytes, 0) {
            LineEncoding::Verbatim
        } else {
            LineEncoding::Unknown
        };

        // Skip past the line's own header to avoid matching itself.
        let min_scan = if prepended {
            if bytes.len() > UUID_PREFIX_LEN && bytes[UUID_PREFIX_LEN].is_ascii_digit() {
                64 // Full line: UUID + timestamp
            } else {
                UUID_PREFIX_LEN // UUID continuation
            }
        } else if is_date_at(bytes, 0) {
            27 // System line: skip own timestamp
        } else {
            0
        };

        let end = bytes.len();

        // Single linear pass collecting every split point. Two collision
        // mechanisms handled in one walk:
        //
        //   * the write budget (Format E), checked only in the few bytes
        //     the cursor points at. A bare UUID is the parser's weakest
        //     signature; the boundary is what earns it the right to split,
        //     which is also why this check runs first at a shared offset.
        //
        //   * `is_log_header_at`: timestamp header (Format B write
        //     contention, Full/System line collisions). Fast-fails after
        //     one byte for non-digit input, so the per-offset cost stays
        //     low even on hundreds-of-KB lines.
        //
        // Collecting all splits in one pass (rather than splitting,
        // re-feeding the suffix, and re-scanning from scratch) is the
        // structural fix for the prior O(n²) behavior.
        let mut next_boundary = self.cursor.boundary_in(end);
        let mut splits: Vec<usize> = Vec::new();
        // Per chunk, whether it ends where the write spent its budget rather
        // than at a header the heuristic found. Only the first is a cut.
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
                        next_boundary = arm_boundary(uuid, offset, end);
                        offset += UUID_PREFIX_LEN;
                        continue;
                    }
                }
            }
            // `min_scan` guards only the heuristic: on the second and later
            // lines of one write the boundary sits early, often inside the
            // header the heuristic has to skip.
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
                    next_boundary = arm_boundary(is_uuid_at(bytes, split_at), split_at, end);
                    offset += 27;
                } else {
                    // Header at current chunk's own start — already
                    // accounted for. Step past it without recording a
                    // split. The max guarantees forward progress when
                    // the UUID-prefix check rewinds split_at behind us.
                    offset = (offset + 27).max(offset + 1);
                }
                continue;
            }
            offset += 1;
        }

        // A boundary still armed is one the walk passed with nothing
        // recognisable on it: the write was cut and its remainder lost rather
        // than glued to a successor we could name.
        cut_verdicts.push(next_boundary.is_some());
        self.cut_verdicts = cut_verdicts.into();

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
        // `advance` adds back, and which the trimmed `end` no longer carries.
        self.cursor.advance(on_disk_len - last_start - 1);

        if splits.is_empty() {
            return line;
        }

        // First chunk returned; the rest queued for subsequent iterations.
        // Building right-to-left with split_off avoids intermediate copies.
        let mut tail = line;
        let mut chunks: Vec<String> = Vec::with_capacity(splits.len());
        for &at in splits.iter().rev() {
            chunks.push(tail.split_off(at));
        }
        chunks.reverse();
        self.split_pending.extend(chunks);
        tail
    }
}

impl<I: Iterator<Item = String>> Iterator for LogStream<I> {
    type Item = LogEntry;

    fn next(&mut self) -> Option<LogEntry> {
        loop {
            let line = if let Some(split) = self.split_pending.pop_front() {
                self.stats.lines_split += 1;
                // A chunk only ever starts at a UUID or a log header, so its
                // own first bytes settle which path wrote it.
                self.line_encoding = if is_uuid_at(split.as_bytes(), 0) {
                    LineEncoding::Prepended
                } else {
                    LineEncoding::Verbatim
                };
                // Already split out by a prior detect_collision pass —
                // skip re-scanning, which would just walk the chunk again
                // and find nothing.
                split
            } else {
                let Some(mut line) = self.lines.next() else {
                    return self.take_pending();
                };

                // Exactly the sentinel, never merely starting with it: crash
                // padding leaves real log lines with a leading NUL, and decode
                // passes those through as valid text. Treating one as a segment
                // boundary would discard its content before any counter saw it.
                if line == SEGMENT_BOUNDARY {
                    let yielded = self.take_pending();
                    self.last_uuid.clear();
                    self.last_timestamp.clear();
                    // A write cannot continue across files, and the cut
                    // verdicts describe lines the next segment never saw.
                    self.cursor.lose();
                    self.cut_verdicts.clear();
                    self.prev_line_cut = false;
                    self.line_cut = false;
                    if yielded.is_some() {
                        return yielded;
                    }
                    continue;
                }

                self.line_number += 1;
                self.stats.lines_processed += 1;

                // Trimmed here rather than at decode so the CR is still on the
                // line when its cost is counted. Split offsets are computed
                // against the trimmed text; only the budget sees the byte.
                let on_disk_len = line.len() + 1;
                if line.ends_with('\r') {
                    line.pop();
                }
                self.detect_collision(line, on_disk_len)
            };

            // A non-empty queue means this chunk ended at a split, not a newline.
            // Recomputed every line: a stale flag would close a multi-line value.
            let chunk_cut = self.cut_verdicts.pop_front().unwrap_or(false);
            self.line_cut = chunk_cut || !self.split_pending.is_empty();
            if chunk_cut {
                self.line_warning = Some(ParseWarning::CutLine);
            }
            let prev_cut = std::mem::replace(&mut self.prev_line_cut, self.line_cut);

            let parsed = parse_line(&line);

            match parsed.kind {
                LineKind::Full | LineKind::System | LineKind::Truncated => {
                    let uuid = parsed.uuid.unwrap_or("").to_string();

                    // Merge consecutive codec negotiation entries with the same
                    // UUID *and* media type — a video run following an audio one
                    // describes a different negotiation and gets its own block.
                    if self.merge_codec_run(&parsed, &uuid, &line) {
                        continue;
                    }

                    let yielded = self.take_pending();
                    let timestamp = parsed
                        .timestamp
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| self.last_timestamp.clone());
                    self.open_entry(&parsed, uuid, timestamp);

                    if yielded.is_some() {
                        return yielded;
                    }
                }

                LineKind::UuidContinuation => {
                    let uuid = parsed.uuid.unwrap_or("").to_string();
                    // An EXECUTE trace is its own entry even mid-block, and a
                    // different UUID means a different session's output.
                    let continues = !parsed.message.starts_with("EXECUTE ")
                        && self
                            .pending
                            .as_ref()
                            .is_some_and(|p| p.entry.uuid.as_deref() == Some(uuid.as_str()));

                    if continues {
                        self.accumulate_continuation(parsed.message, &line, true, prev_cut);
                    } else {
                        let yielded = self.take_pending();
                        self.open_entry(&parsed, uuid, self.last_timestamp.clone());
                        if yielded.is_some() {
                            return yielded;
                        }
                    }
                }

                LineKind::BareContinuation => {
                    if self.pending.is_some() {
                        self.accumulate_continuation(parsed.message, &line, false, prev_cut);
                    } else {
                        self.record_unclassified(
                            UnclassifiedReason::OrphanContinuation,
                            Some(&line),
                        );
                        let (uuid, timestamp) =
                            (self.last_uuid.clone(), self.last_timestamp.clone());
                        self.open_entry(&parsed, uuid, timestamp);
                    }
                }

                LineKind::Empty => {
                    if self.pending.is_some() {
                        self.attach(&line);
                    } else {
                        self.stats.lines_empty_orphan += 1;
                    }
                }
            }
        }
    }
}
