//! Log timestamps and the durations derived from them. The clock is the
//! log, never the wall: a rotated file replayed hours later must still show
//! the ages its own lines describe.

use std::time::Duration;

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

pub(super) fn parse_timestamp_secs(ts: &str) -> Option<u64> {
    if ts.len() < 19 {
        return None;
    }
    let year: u64 = ts[0..4].parse().ok()?;
    let month: u64 = ts[5..7].parse().ok()?;
    let day: u64 = ts[8..10].parse().ok()?;
    let hour: u64 = ts[11..13].parse().ok()?;
    let min: u64 = ts[14..16].parse().ok()?;
    let sec: u64 = ts[17..19].parse().ok()?;
    let (y, m) = if month > 2 {
        (year, month - 3)
    } else {
        (year - 1, month + 9)
    };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

pub(super) fn log_age(start: &str, end: &str) -> Duration {
    match (parse_timestamp_secs(start), parse_timestamp_secs(end)) {
        (Some(s), Some(e)) if e >= s => Duration::from_secs(e - s),
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
