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

use std::ops::Range;

/// The byte range of `sub` inside `parent`, or `None` when `sub` is not a
/// subslice of it. Empty subslices never yield a range — a helper that returns
/// a `""` literal rather than an in-place empty slice must degrade to no span.
///
/// Deriving the range from the subslice's own address is what keeps a span on a
/// char boundary: a length added to a marker offset silently omits whatever the
/// slicer skipped to reach the token.
fn subslice_range(parent: &str, sub: &str) -> Option<Range<usize>> {
    if sub.is_empty() {
        return None;
    }
    let base = parent.as_ptr() as usize;
    let start = (sub.as_ptr() as usize).checked_sub(base)?;
    if start + sub.len() > parent.len() {
        return None;
    }
    Some(start..start + sub.len())
}

pub use collect::message_fields;
pub use kind::{Field, FieldKind, FieldLocation, RenderError, RenderedEntry};
pub(crate) use processing::processing_parts;
pub use render::apply_fields;
