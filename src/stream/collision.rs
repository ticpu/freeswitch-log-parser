//! Byte-length constants describing `mod_logfile`'s write-buffer truncation
//! and the scan window used to recover collided lines.

use crate::line::UUID_PREFIX_LEN;

/// mod_logfile's `snprintf` buffer size for UUID-prefixed lines.
/// Lines exceeding this in the formatted output lose their trailing newline,
/// causing the next queue entry to collide on the same physical line.
pub(super) const MOD_LOGFILE_BUF_SIZE: usize = 2048;

/// Effective maximum payload per line (buffer minus the UUID prefix
/// `mod_logfile` prepends, minus the trailing newline).
pub(super) const MAX_LINE_PAYLOAD: usize = MOD_LOGFILE_BUF_SIZE - UUID_PREFIX_LEN - 1;

/// Physical length of a line the buffer cut: every byte `snprintf` could write
/// short of its NUL, the trailing newline lost to the cut. An intact prepended
/// line is at most one byte shorter, so this length is the cut itself.
pub(super) const CUT_LINE_LEN: usize = MOD_LOGFILE_BUF_SIZE - 1;

/// Tolerance around the expected truncation boundary when scanning oversize
/// lines for Format E collisions. The boundary is deterministic
/// (`MAX_LINE_PAYLOAD` from the start of the truncated chunk) but a few bytes
/// of slack covers minor variation in `snprintf` accounting and any future
/// drift in the prepend format.
pub(super) const COLLISION_SCAN_SLACK: usize = 64;
