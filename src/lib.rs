//! Parser for FreeSWITCH log files.
//!
//! Handles the full complexity of `mod_logfile` output: five distinct line
//! formats, multi-line CHANNEL_DATA and SDP dumps, truncated buffer collisions,
//! and per-session state tracking — no regex, a single dependency
//! (`freeswitch-types`).
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
//!   via [`SessionTracker::with_pre_hook`] and [`SessionTracker::with_post_hook`]
//!   for custom leg detection
//!
//! See `docs/design-rationale.md` in the repository for the parsing strategy
//! and why each layer exists; the line-format anatomy lives in the repository's
//! CLAUDE.md.
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
mod codec;
mod decode;
mod fields;
mod level;
mod line;
mod message;
mod peer;
mod session;
mod stamp;
mod stream;
mod uuid;

pub use attached::{AttachedLines, AttachedLinesIter, AttachedOverflow};
pub use chain::{SegmentTracker, TrackedChain};
pub use codec::{CodecMedia, CodecOffer, CodecParseError};
pub use decode::{
    classify_utf8, decode_log_line, read_log_line_capped, read_log_lines, read_log_lines_capped,
    trim_capped_tail, truncate_at_char_boundary, CappedLine, DecodedLine, LineRead, OverCap,
    Utf8Decode,
};
pub use fields::{
    apply_fields, message_fields, Field, FieldKind, FieldLocation, RenderError, RenderedEntry,
};
pub use freeswitch_types::{
    variables::{ConferenceVariable, SofiaVariable, VariableName},
    CallDirection, CallState, ChannelState, ChannelVariable, HangupCause,
};
pub use level::{LogLevel, ParseLevelError};
pub use line::{parse_line, LineKind, RawLine};
pub use message::{
    classify_message, regex_condition_parts, DtmfSource, MessageKind, RegexCondition, SdpDirection,
    SipInviteDirection,
};
pub use peer::{
    for_each_peer_uuid, for_each_peer_uuid_with, is_peer_uuid_var, LOOPBACK_PEER_UUID_VARS,
    PEER_UUID_VARS,
};
pub use session::{
    conference::ConferenceMembership,
    media::{CodecImpl, MediaCodecs, SessionMedia},
    parse_bridge_args, BridgeInfo, EnrichedEntry, SessionSnapshot, SessionState, SessionTracker,
};
pub use stamp::{log_rotation_stamp, normalize_entry_timestamp};
pub use stream::{
    Block, LogEntry, LogStream, ParseStats, ParseWarning, SessionReading, UnclassifiedLine,
    UnclassifiedReason, UnclassifiedTracking,
};
pub use uuid::{find_uuids, is_uuid, FindUuids};
