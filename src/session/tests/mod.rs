//! Behavioral tests for [`SessionTracker`] — shared fixtures for the
//! per-concern modules below.

mod channel_data;
mod conference;
mod dialplan;
mod hooks;
mod legs;
mod lifecycle;

use freeswitch_types::variables::SofiaVariable;
use freeswitch_types::ChannelVariable;

use crate::message::MessageKind;
use crate::stream::LogStream;

use super::*;

const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const UUID2: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
const UUID3: &str = "c3d4e5f6-a7b8-9012-cdef-234567890123";
const TS1: &str = "2025-01-15 10:30:45.123456";
const TS2: &str = "2025-01-15 10:30:46.234567";

fn full_line(uuid: &str, ts: &str, msg: &str) -> String {
    format!("{uuid} {ts} 95.97% [DEBUG] sofia.c:100 {msg}")
}

fn collect_enriched(lines: Vec<String>) -> Vec<EnrichedEntry> {
    let stream = LogStream::new(lines.into_iter());
    SessionTracker::new(stream).collect()
}

fn track(lines: Vec<String>) -> SessionTracker<std::vec::IntoIter<String>> {
    let mut tracker = SessionTracker::new(LogStream::new(lines.into_iter()));
    for _ in tracker.by_ref() {}
    tracker
}
