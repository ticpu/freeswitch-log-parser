//! `mod_logfile`'s write budget, and the cursor tracking how much of it the
//! write in progress has spent.

/// mod_logfile's `snprintf` buffer for UUID-prefixed lines.
pub(super) const MOD_LOGFILE_BUF_SIZE: usize = 2048;

/// Bytes one `snprintf` can put on disk: the buffer less its NUL. An intact
/// write never reaches it, since the newline it owes is inside the budget.
pub(super) const WRITE_LIMIT: usize = MOD_LOGFILE_BUF_SIZE - 1;

/// Forward tolerance on the boundary: the lossy decode swaps a chopped
/// codepoint's 1..=3 bytes for a 3-byte U+FFFD, so a successor only sits later.
pub(super) const DECODE_DRIFT: usize = 2;

/// Bytes the write in progress spent before the line now in hand.
///
/// `None` means its start was never seen, which switches the exact boundary off
/// rather than placing it somewhere assumed.
#[derive(Debug, Default)]
pub(super) struct WriteCursor(Option<usize>);

impl WriteCursor {
    /// This line carries a UUID prefix, so a write began at its first byte.
    pub(super) fn begin(&mut self) {
        self.0 = Some(0);
    }

    /// Nothing here says where a write started.
    pub(super) fn lose(&mut self) {
        self.0 = None;
    }

    /// Offset in a line of `line_len` bytes where a write with `spent` bytes
    /// behind it ends: `line_len` remaining is the smallest that does not fit.
    fn budget_ends(spent: usize, line_len: usize) -> Option<usize> {
        let remaining = WRITE_LIMIT.checked_sub(spent)?;
        (remaining <= line_len).then_some(remaining)
    }

    /// Offset within a line of `line_len` bytes at which the write in progress
    /// spends its budget, or `None` if it cannot reach it here.
    pub(super) fn boundary_in(&self, line_len: usize) -> Option<usize> {
        Self::budget_ends(self.0?, line_len)
    }

    /// Where the next cut would fall after a split at `at`, if the chunk
    /// starting there is a prepend write that can reach its budget in the line.
    pub(super) fn boundary_after(prepended: bool, at: usize, line_len: usize) -> Option<usize> {
        if !prepended {
            return None;
        }
        Some(at + Self::budget_ends(0, line_len - at)?)
    }

    /// Account for a line of `line_len` bytes and the newline after it.
    ///
    /// A write that has spent its budget cannot continue, so a cursor claiming
    /// otherwise is desynchronised and drops rather than clamps.
    pub(super) fn advance(&mut self, line_len: usize) {
        self.0 = match self.0 {
            Some(spent) if spent + line_len + 1 < WRITE_LIMIT => Some(spent + line_len + 1),
            _ => None,
        };
    }
}
