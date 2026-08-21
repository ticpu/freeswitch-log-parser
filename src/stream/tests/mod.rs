//! Behavioral tests for [`LogStream`] — shared fixtures for the per-concern
//! modules below.

mod blocks;
mod codecs;
mod collision;
mod grouping;
mod stats;
mod warnings;

use super::entry::WARNING_EXCERPT_LEN;
use super::*;
use crate::codec::{CodecMedia, CodecOffer};
use crate::level::LogLevel;
use crate::message::SdpDirection;

const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const UUID2: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";

fn full_line(uuid: &str, ts: &str, msg: &str) -> String {
    format!("{uuid} {ts} 95.97% [DEBUG] sofia.c:100 {msg}")
}

/// A physical line holding a write that spent its budget: `head` padded to
/// exactly what the write had left, with `successor` glued where the newline no
/// longer fit. No fixture should spell this arithmetic out for itself.
fn cut_write(head: &str, successor: &str) -> String {
    cut_write_after(0, head, successor)
}

/// The same, for a line the write reached after `spent` bytes of earlier ones —
/// a write spanning a prefixed line and the bare continuations under it.
fn cut_write_after(spent: usize, head: &str, successor: &str) -> String {
    let padding = "x".repeat(WRITE_LIMIT - spent - head.len());
    format!("{head}{padding}{successor}")
}

const TS1: &str = "2025-01-15 10:30:45.123456";
const TS2: &str = "2025-01-15 10:30:46.234567";

fn assert_accounting(stream: &LogStream<impl Iterator<Item = String>>) {
    let stats = stream.stats();
    assert_eq!(
        stats.unaccounted_lines(),
        0,
        "line accounting invariant violated: \
         processed={} + split={} != in_entries={} + empty_orphan={}",
        stats.lines_processed,
        stats.lines_split,
        stats.lines_in_entries,
        stats.lines_empty_orphan,
    );
}
