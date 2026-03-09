//! Parser for FreeSWITCH log files.
//!
//! Handles the full complexity of `mod_logfile` output: five distinct line
//! formats, multi-line CHANNEL_DATA and SDP dumps, truncated buffer collisions,
//! and per-session state tracking — all with zero dependencies and no regex.
//!
//! # Architecture
//!
//! The parser is organized in three composable layers, each wrapping the previous:
//!
//! - **Layer 1** ([`parse_line`]) — stateless, zero-allocation single-line classifier
//! - **Layer 2** ([`LogStream`]) — structural state machine that groups continuations,
//!   classifies messages, and detects multi-line blocks
//! - **Layer 3** ([`SessionTracker`]) — per-UUID state machine that propagates
//!   dialplan context, channel state, and variables across entries
//!
//! See `docs/design-rationale.md` in the repository for the full story on format
//! discovery, parsing strategy, and why each layer exists.
//!
//! # Examples
//!
//! Read lines from stdin, process through all three layers, and print enriched entries:
//!
//! ```no_run
//! use std::io::{self, BufRead};
//! use freeswitch_log_parser::{LogStream, SessionTracker};
//!
//! let lines = io::stdin().lock().lines().map(|l| l.expect("read error"));
//! let stream = LogStream::new(lines);
//! let mut tracker = SessionTracker::new(stream);
//!
//! for enriched in tracker.by_ref() {
//!     let e = &enriched.entry;
//!     println!("{} [{}] {}", e.timestamp, e.message_kind, e.message);
//! }
//!
//! let stats = tracker.stats();
//! eprintln!("{} lines, {} unclassified",
//!     stats.lines_processed, stats.lines_unclassified);
//! ```
//!
//! # Feature flags
//!
//! - **`cli`** — enables the `fslog` binary with clap, xz decompression, and regex filtering

mod chain;
mod level;
mod line;
mod message;
mod session;
mod stream;

pub use chain::{SegmentTracker, TrackedChain};
pub use freeswitch_types::{
    variables::SofiaVariable, CallDirection, CallState, ChannelState, ChannelVariable,
};
pub use level::{LogLevel, ParseLevelError};
pub use line::{parse_line, LineKind, RawLine};
pub use message::{classify_message, MessageKind, SdpDirection};
pub use session::{EnrichedEntry, SessionSnapshot, SessionState, SessionTracker};
pub use stream::{
    Block, LogEntry, LogStream, ParseStats, UnclassifiedLine, UnclassifiedReason,
    UnclassifiedTracking,
};
