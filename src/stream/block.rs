//! [`BlockBuilder`], the mutable accumulator that assembles a [`Block`] from
//! primary and continuation lines as they arrive.

use crate::codec::{CodecMedia, CodecOffer, CodecTrace};
use crate::message::{classify_message, MessageKind, SdpDirection};

use super::entry::{Block, ParseWarning};

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

/// A [`Block`] under construction. One variant per `Block` variant, plus the
/// idle state for an entry that opens no block.
pub(super) enum BlockBuilder {
    Idle,
    ChannelData {
        fields: Vec<(String, String)>,
        variables: Vec<(String, String)>,
        // Name and accumulated value of a variable whose `[` has not been closed
        // yet. One field, so a half-open variable cannot be represented.
        open_var: Option<(String, String)>,
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

    /// Absorb a continuation line — one that carries no header of its own.
    pub(super) fn push_continuation(&mut self, msg: &str) -> Option<ParseWarning> {
        match self {
            BlockBuilder::ChannelData {
                fields,
                variables,
                open_var,
            } => {
                if let Some((_, val)) = open_var {
                    val.push('\n');
                    val.push_str(msg);
                    if msg.ends_with(']') {
                        if let Some((name, val)) = open_var.take() {
                            let closed = val.strip_suffix(']').unwrap_or(&val).to_string();
                            variables.push((name, closed));
                        }
                    }
                    return None;
                }
                match classify_message(msg) {
                    MessageKind::ChannelField { name, value } => fields.push((name, value)),
                    MessageKind::Variable { name, value } => {
                        if !msg.ends_with(']') && msg.contains(": [") {
                            *open_var = Some((name, value));
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
            BlockBuilder::Idle => None,
        }
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
                if let Some((name, value)) = open_var {
                    warnings.push(ParseWarning::UnclosedVariable { name: name.clone() });
                    variables.push((name, value));
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
