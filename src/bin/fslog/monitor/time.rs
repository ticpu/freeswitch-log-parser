//! Log timestamps and the durations derived from them. The clock is the
//! log, never the wall: a rotated file replayed hours later must still show
//! the ages its own lines describe.

use std::time::Duration;

use jiff::civil::DateTime;

use super::model::CallRow;

pub(super) fn end_ts(row: &CallRow) -> &str {
    row.end
        .as_ref()
        .map(|e| e.log_ts.as_str())
        .unwrap_or(&row.log_last)
}

pub(super) fn call_duration(row: &CallRow) -> Duration {
    log_age(&row.log_start, end_ts(row))
}

pub(super) fn call_age(row: &CallRow, latest: &str) -> Duration {
    log_age(end_ts(row), latest)
}

/// The entry timestamp's date and time, sub-second part ignored.
pub(super) fn parse_timestamp(ts: &str) -> Option<DateTime> {
    DateTime::strptime("%Y-%m-%d %H:%M:%S", ts.get(..19)?).ok()
}

pub(super) fn log_age(start: &str, end: &str) -> Duration {
    let (Some(s), Some(e)) = (parse_timestamp(start), parse_timestamp(end)) else {
        return Duration::ZERO;
    };
    // A row whose last line predates its start is a clock the log disagrees
    // with, not a negative age.
    match e.duration_since(s).as_secs() {
        secs if secs > 0 => Duration::from_secs(secs as u64),
        _ => Duration::ZERO,
    }
}

pub(super) fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

pub(super) fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86400;
    let hours = secs / 3600;
    let minutes = secs / 60;
    if days > 0 {
        format!("{}d", days)
    } else if hours > 0 {
        format!("{}h", hours)
    } else {
        format!("{}m", minutes)
    }
}
