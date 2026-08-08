//! Layer 3 per-UUID state machine — accumulates dialplan context, channel
//! state, variables, conference membership and leg relationships across the
//! entries of one session.

pub mod conference;
mod index;
mod loopback;
pub mod media;
mod parse;
mod state;
#[cfg(test)]
mod tests;
mod tracker;

use crate::stream::LogEntry;

pub use parse::{parse_bridge_args, BridgeInfo};
pub use state::{SessionSnapshot, SessionState};
pub use tracker::{EnrichedEntry, SessionTracker};

type SessionHook = Box<dyn Fn(&LogEntry, &mut SessionState) + Send>;
