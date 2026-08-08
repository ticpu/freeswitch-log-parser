//! Typed byte spans over the raw text of a log entry.
//!
//! [`message_fields`] locates the fields a message carries and returns their
//! byte ranges instead of copies, so a consumer can rewrite the text in place —
//! redacting a caller id, colorizing a channel name — without re-deriving
//! positions the classifier already computed.
//!
//! A kind is emitted only where classification isolates it. Nothing here scans
//! free text for numbers, addresses or URIs: see `docs/design-rationale.md`.

mod collect;
mod kind;
mod processing;
mod render;
#[cfg(test)]
mod tests;

pub use collect::message_fields;
pub use kind::{Field, FieldKind, FieldLocation, RenderError, RenderedEntry};
pub(crate) use processing::processing_parts;
pub use render::apply_fields;
