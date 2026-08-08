//! Layer 1 message classification — maps a log line's message text to a typed
//! [`MessageKind`] with positional byte checks, no regex and no state.

mod classify;
mod dtmf;
mod kind;
mod lifecycle;
mod media;
mod parts;
#[cfg(test)]
mod tests;

pub use classify::classify_message;
pub use kind::{DtmfSource, MessageKind, SdpDirection, SipInviteDirection};
pub(crate) use lifecycle::{call_id_token, sip_invite_direction};
pub(crate) use parts::{
    dialplan_parts, execute_parts, hangup_channel, new_channel_name, paren_channel,
    parse_bracketed_value, set_export_parts, strip_channel_prefix,
};
