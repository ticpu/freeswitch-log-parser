//! [`BlockBuilder`], the mutable accumulator that assembles a [`Block`] from
//! primary and continuation lines as they arrive.

use crate::codec::{CodecMedia, CodecOffer, CodecTrace};
use crate::message::{classify_message, MessageKind, SdpDirection};

use super::entry::{Block, ParseWarning};

/// SDP's mandatory first line. A body carrying no marker of its own is still
/// recognisable by it, since no other line may open one.
const SDP_VERSION_LINE: &str = "v=0";

fn parse_field_line(msg: &str) -> Option<(String, String)> {
    let colon = msg.find(": ")?;
    let name = &msg[..colon];
    if name.contains(' ') || name.is_empty() {
        return None;
    }
    let value_part = &msg[colon + 2..];
    let value = if let Some(inner) = value_part.strip_prefix('[') {
        inner.strip_suffix(']').unwrap_or(inner)
    } else {
        value_part
    };
    Some((name.to_string(), value.to_string()))
}

/// A channel variable whose `[` has not been closed yet.
pub(super) struct OpenVar {
    name: String,
    value: String,
    /// The logger cut this value mid-write. Its `]` may have died in the lost
    /// tail, so the join ends at the first line opening a name of its own.
    cut: bool,
}

/// Whether a CHANNEL_DATA line opens a name of its own, which is what bounds
/// the join after a cut. Only the bracketed shapes count — the looser
/// [`parse_field_line`] fallback matches SDP and header lines inside a value.
fn opens_own_name(msg: &str) -> bool {
    matches!(
        classify_message(msg),
        MessageKind::ChannelField { .. } | MessageKind::Variable { .. }
    )
}

/// A [`Block`] under construction. One variant per `Block` variant, plus the
/// idle state for an entry that opens no block.
pub(super) enum BlockBuilder {
    Idle,
    ChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
        // One field, so a half-open variable cannot be represented.
        open_var: Option<OpenVar>,
    },
    Sdp {
        direction: SdpDirection,
        body: Vec<String>,
    },
    Codec {
        media: CodecMedia,
        comparisons: Vec<(CodecOffer, CodecOffer)>,
        matched: Vec<CodecOffer>,
        near_matched: Vec<CodecOffer>,
    },
}

impl BlockBuilder {
    /// Open the builder a message calls for, or `Idle` if it opens no block.
    pub(super) fn open(message_kind: &MessageKind) -> Self {
        match message_kind {
            MessageKind::ChannelData => BlockBuilder::ChannelData {
                fields: Vec::new(),
                variables: Vec::new(),
                open_var: None,
            },
            MessageKind::SdpMarker { direction } => BlockBuilder::Sdp {
                direction: direction.clone(),
                body: Vec::new(),
            },
            MessageKind::CodecNegotiation { media } => BlockBuilder::Codec {
                media: *media,
                comparisons: Vec::new(),
                matched: Vec::new(),
                near_matched: Vec::new(),
            },
            _ => BlockBuilder::Idle,
        }
    }

    /// Media type of an open codec run, used to decide whether the next codec
    /// line continues this block or starts its own.
    pub(super) fn codec_media(&self) -> Option<CodecMedia> {
        match self {
            BlockBuilder::Codec { media, .. } => Some(*media),
            _ => None,
        }
    }

    /// Absorb a continuation line. An idle builder may open an SDP block here;
    /// `has_uuid` gates the marker-less version-line rule (see [`Block::Sdp`]).
    pub(super) fn push_continuation(&mut self, msg: &str, has_uuid: bool) -> Option<ParseWarning> {
        match self {
            BlockBuilder::ChannelData {
                fields,
                variables,
                open_var,
            } => {
                if let Some(open) = open_var.as_mut() {
                    if !(open.cut && opens_own_name(msg)) {
                        open.value.push('\n');
                        open.value.push_str(msg);
                        if msg.ends_with(']') {
                            if let Some(open) = open_var.take() {
                                let closed = open
                                    .value
                                    .strip_suffix(']')
                                    .unwrap_or(&open.value)
                                    .to_string();
                                variables.push((open.name, closed));
                            }
                        }
                        return None;
                    }
                }
                // The join a cut left running ends here, on a name of its own.
                if let Some(open) = open_var.take() {
                    variables.push((open.name, open.value));
                }
                match classify_message(msg) {
                    MessageKind::ChannelField { name, value } => fields.push((name, value)),
                    MessageKind::Variable { name, value } => {
                        if !msg.ends_with(']') && msg.contains(": [") {
                            *open_var = Some(OpenVar {
                                name,
                                value,
                                cut: false,
                            });
                        } else {
                            variables.push((name, value));
                        }
                    }
                    _ => match parse_field_line(msg) {
                        Some((name, value)) => fields.push((name, value)),
                        None => {
                            return Some(ParseWarning::UnparseableChannelData {
                                line: ParseWarning::excerpt(msg),
                            })
                        }
                    },
                }
                None
            }
            BlockBuilder::Sdp { body, .. } => {
                body.push(msg.to_string());
                None
            }
            BlockBuilder::Codec { .. } => Some(ParseWarning::UnexpectedCodecContinuation {
                line: ParseWarning::excerpt(msg),
            }),
            BlockBuilder::Idle => {
                // Trimming catches the CR a wire-CRLF body line keeps: the
                // logger's line split strips only spaces.
                if has_uuid && msg.trim() == SDP_VERSION_LINE {
                    *self = BlockBuilder::Sdp {
                        direction: SdpDirection::Unknown,
                        body: vec![msg.to_string()],
                    };
                } else if let MessageKind::SdpMarker { direction } = classify_message(msg) {
                    *self = BlockBuilder::Sdp {
                        direction,
                        body: Vec::new(),
                    };
                }
                None
            }
        }
    }

    /// Record that the logger cut the open variable's value. It stays open: the
    /// lines after the cut are still its own, and [`Self::push_continuation`]
    /// ends the join at the first name of its own.
    pub(super) fn mark_variable_cut(&mut self) -> Option<ParseWarning> {
        let BlockBuilder::ChannelData { open_var, .. } = self else {
            return None;
        };
        let open = open_var.as_mut()?;
        if open.cut {
            return None;
        }
        open.cut = true;
        Some(ParseWarning::TruncatedVariable {
            name: open.name.clone(),
        })
    }

    /// Absorb one line of a codec negotiation run. Unlike the other blocks
    /// these arrive as primary lines, so this is a separate entry point.
    pub(super) fn push_codec_trace(&mut self, msg: &str) -> Option<ParseWarning> {
        let BlockBuilder::Codec {
            media,
            comparisons,
            matched,
            near_matched,
        } = self
        else {
            return None;
        };
        match CodecTrace::parse(*media, msg) {
            Ok(CodecTrace::Compared { offered, local }) => comparisons.push((offered, local)),
            Ok(CodecTrace::Matched(c)) => matched.push(c),
            Ok(CodecTrace::NearMatched(c)) => near_matched.push(c),
            Ok(CodecTrace::Dropped(_)) => {}
            Err(e) => {
                return Some(ParseWarning::UnrecognizedCodecLine {
                    line: ParseWarning::excerpt(msg),
                    source: e.into(),
                })
            }
        }
        None
    }

    /// Close the builder, yielding the block and any warning its closing raised.
    pub(super) fn finish(&mut self) -> (Option<Block>, Vec<ParseWarning>) {
        let mut warnings = Vec::new();
        let block = match std::mem::replace(self, BlockBuilder::Idle) {
            BlockBuilder::Idle => None,
            BlockBuilder::ChannelData {
                fields,
                mut variables,
                open_var,
            } => {
                if let Some(open) = open_var {
                    // A cut one already reported why its value is incomplete.
                    if !open.cut {
                        warnings.push(ParseWarning::UnclosedVariable {
                            name: open.name.clone(),
                        });
                    }
                    variables.push((open.name, open.value));
                }
                Some(Block::ChannelData { fields, variables })
            }
            BlockBuilder::Sdp { direction, body } => Some(Block::Sdp { direction, body }),
            BlockBuilder::Codec {
                media,
                comparisons,
                matched,
                near_matched,
            } => Some(Block::CodecNegotiation {
                media,
                comparisons,
                matched,
                near_matched,
            }),
        };
        (block, warnings)
    }
}
