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
use crate::testdata::{full_line, TS1, TS2, UUID1, UUID2};

use super::*;

const UUID3: &str = "c3d4e5f6-a7b8-9012-cdef-234567890123";

fn collect_enriched(lines: Vec<String>) -> Vec<EnrichedEntry> {
    let stream = LogStream::new(lines.into_iter());
    SessionTracker::new(stream).collect()
}

fn track(lines: Vec<String>) -> SessionTracker<std::vec::IntoIter<String>> {
    let mut tracker = SessionTracker::new(LogStream::new(lines.into_iter()));
    for _ in tracker.by_ref() {}
    tracker
}
