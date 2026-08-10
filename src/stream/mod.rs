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
use collision::{COLLISION_SCAN_SLACK, MAX_LINE_PAYLOAD};

pub use entry::{Block, LogEntry, ParseWarning, SessionReading};
pub use stats::{ParseStats, UnclassifiedLine, UnclassifiedReason, UnclassifiedTracking};

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
    /// 1. **Buffer truncation** (Format E): `mod_logfile`'s 2048-byte `snprintf`
    ///    buffer truncates a long line, losing the trailing `\n`. The next entry
    ///    from the log queue collides on the same physical line. These lines
    ///    always exceed `MAX_LINE_PAYLOAD`.
    ///
    /// 2. **Write contention**: multiple threads writing to the log file can
    ///    interleave output, producing concatenated entries at any line length.
    ///    Common with system lines (Format B) that lack UUID prefixes.
    ///
    /// Returns the (possibly truncated) line. If a collision is detected,
    /// the suffix is stored in `split_pending` for processing in the next
    /// iteration. Recursive: split suffixes pass through this function again.
    fn detect_collision(&mut self, line: String) -> String {
        if line.len() > MAX_LINE_PAYLOAD {
            self.line_warning = Some(ParseWarning::OversizeLine {
                bytes: line.len() + UUID_PREFIX_LEN + 1,
            });
        }

        // Skip past the line's own header to avoid matching itself.
        let bytes = line.as_bytes();
        let min_scan = if is_uuid_at(bytes, 0) {
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

        let end = bytes.len().saturating_sub(28);
        let oversize = bytes.len() > MAX_LINE_PAYLOAD;

        // Single linear pass collecting every split point. Two collision
        // mechanisms handled in one walk:
        //
        //   * `is_log_header_at`: timestamp header (Format B write
        //     contention, Full/System line collisions). Fast-fails after
        //     one byte for non-digit input, so the per-offset cost stays
        //     low even on hundreds-of-KB lines.
        //
        //   * `is_uuid_at` within a ±64-byte window around the next
        //     expected mod_logfile truncation boundary (Format E). The
        //     boundary is `MAX_LINE_PAYLOAD` bytes past the start of the
        //     current chunk; we advance it as splits are found. Bounding
        //     this check is what kept the previous optimization fast on
        //     60 KB embedded-SDP lines — a 36-byte hex pattern check at
        //     every offset would dominate the scan.
        //
        // Collecting all splits in one pass (rather than splitting,
        // re-feeding the suffix, and re-scanning from scratch) is the
        // structural fix for the prior O(n²) behavior.
        let mut splits: Vec<usize> = Vec::new();
        let mut chunk_start = 0usize;
        let mut offset = min_scan;
        while offset <= end {
            if is_log_header_at(bytes, offset) {
                let split_at = if offset >= chunk_start + UUID_PREFIX_LEN
                    && is_uuid_at(bytes, offset - UUID_PREFIX_LEN)
                {
                    offset - UUID_PREFIX_LEN
                } else {
                    offset
                };
                if split_at > chunk_start {
                    splits.push(split_at);
                    chunk_start = split_at;
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
            if oversize {
                let boundary = chunk_start + MAX_LINE_PAYLOAD;
                if offset + COLLISION_SCAN_SLACK >= boundary
                    && offset <= boundary + COLLISION_SCAN_SLACK
                    && is_uuid_at(bytes, offset)
                {
                    splits.push(offset);
                    chunk_start = offset;
                    offset += UUID_PREFIX_LEN;
                    continue;
                }
            }
            offset += 1;
        }

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
                // Already split out by a prior detect_collision pass —
                // skip re-scanning, which would just walk the chunk again
                // and find nothing.
                split
            } else {
                let Some(line) = self.lines.next() else {
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
                    if yielded.is_some() {
                        return yielded;
                    }
                    continue;
                }

                self.line_number += 1;
                self.stats.lines_processed += 1;
                self.detect_collision(line)
            };

            // A non-empty queue means this chunk ended at a split, not a newline.
            // Recomputed every line: a stale flag would close a multi-line value.
            self.line_cut = !self.split_pending.is_empty();
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
