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
//!   dialplan context, channel state, and variables across entries; extensible
//!   via [`SessionTracker::with_relationship_hook`] for custom leg detection
//!
//! See `docs/design-rationale.md` in the repository for the full story on format
//! discovery, parsing strategy, and why each layer exists.
//!
//! # Examples
//!
//! Read lines from stdin, process through all three layers, and print enriched entries:
//!
//! ```no_run
//! use std::io;
//! use freeswitch_log_parser::{read_log_lines, LogStream, SessionTracker};
//!
//! // read_log_lines tolerates mod_logfile's truncated codepoints; the strict
//! // BufRead::lines() reader would panic on them.
//! let lines = read_log_lines(io::stdin().lock()).map(|d| d.expect("read error").text);
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

mod attached;
mod chain;
mod decode;
mod level;
mod line;
mod message;
mod session;
mod stream;

pub use attached::{AttachedLines, AttachedLinesIter};
pub use chain::{SegmentTracker, TrackedChain};
pub use decode::{classify_utf8, read_log_lines, DecodedLine, Utf8Decode};
pub use freeswitch_types::{
    variables::SofiaVariable, CallDirection, CallState, ChannelState, ChannelVariable,
};
pub use level::{LogLevel, ParseLevelError};
pub use line::{parse_line, LineKind, RawLine};
pub use message::{classify_message, DtmfSource, MessageKind, SdpDirection, SipInviteDirection};
pub use session::{EnrichedEntry, SessionSnapshot, SessionState, SessionTracker};
pub use stream::{
    Block, LogEntry, LogStream, ParseStats, UnclassifiedLine, UnclassifiedReason,
    UnclassifiedTracking,
};
