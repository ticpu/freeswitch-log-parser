//! Cumulative parsing statistics ([`ParseStats`]) and the tunable detail
//! level for lines that could not be fully classified ([`UnclassifiedTracking`]).

/// Controls how much detail is recorded for lines that couldn't be fully classified.
///
/// Higher fidelity levels allocate more memory. The default is `CountOnly`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnclassifiedTracking {
    /// Increment the counter only — zero allocation.
    CountOnly,
    /// Record line number and reason for each unclassified line.
    TrackLines,
    /// Like `TrackLines` plus the full line content.
    CaptureData,
}

/// Why a line was marked as unclassified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnclassifiedReason {
    /// Bare continuation line arrived with no pending entry to attach to.
    OrphanContinuation,
    /// Line was parsed but the message didn't match any known pattern.
    UnknownMessageFormat,
    /// EXECUTE or variable line was only partially readable.
    TruncatedField,
}

/// Record of a single unclassified line, captured when tracking is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclassifiedLine {
    pub line_number: u64,
    pub reason: UnclassifiedReason,
    /// The full line content; only populated under [`UnclassifiedTracking::CaptureData`].
    pub data: Option<String>,
}

/// Cumulative parsing statistics, updated as lines flow through the stream.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub lines_processed: u64,
    pub lines_unclassified: u64,
    /// Lines that became part of entries (primary line + attached lines per entry).
    pub lines_in_entries: u64,
    /// Empty lines that arrived with no pending entry to attach to.
    pub lines_empty_orphan: u64,
    /// Extra chunks produced by splitting physical lines that held more than
    /// one record: a cut write's successor glued on, or write contention
    /// interleaving two records. One line yielding N chunks counts N - 1.
    pub lines_split: u64,
    /// Continuation lines an entry could not store because its attached buffer
    /// outgrew the offsets addressing it. The entry carries a
    /// [`ParseWarning::AttachedOverflow`](super::ParseWarning::AttachedOverflow)
    /// naming each one.
    pub lines_dropped: u64,
    /// Populated only when tracking is `TrackLines` or `CaptureData`.
    pub unclassified_lines: Vec<UnclassifiedLine>,
}

impl ParseStats {
    /// Lines that were processed but not accounted for by any tracking category.
    ///
    /// Returns 0 when the parser correctly accounts for every input line.
    /// A non-zero value indicates a parser bug — lines were silently lost.
    /// A line the parser knowingly could not keep is counted in
    /// [`lines_dropped`](Self::lines_dropped) rather than going missing here.
    ///
    /// Invariant:
    /// `lines_processed + lines_split == lines_in_entries + lines_empty_orphan + lines_dropped`
    pub fn unaccounted_lines(&self) -> u64 {
        let expected = self.lines_in_entries + self.lines_empty_orphan + self.lines_dropped;
        let actual = self.lines_processed + self.lines_split;
        actual.saturating_sub(expected)
    }
}
