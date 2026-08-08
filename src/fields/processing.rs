//! The dialplan `Processing` line, decomposed into byte ranges.

use std::ops::Range;

/// The byte ranges a dialplan `Processing` line decomposes into.
///
/// `name` and `number` are `None` for the bracketless `from->to` shape, where
/// `head` is the whole caller side.
pub(crate) struct ProcessingParts {
    /// Caller side as a whole — display name and `<number>` if present.
    pub(crate) head: Range<usize>,
    pub(crate) name: Option<Range<usize>>,
    /// Inside the `<>`, brackets excluded.
    pub(crate) number: Option<Range<usize>>,
    pub(crate) dest: Range<usize>,
    pub(crate) context: Range<usize>,
}

/// Parse `Processing <name> <<number>>-><dest> in context <ctx>`.
///
/// The caller-id name is free-form and may contain spaces, `->` and `<`, so the
/// parse anchors on the fixed frame: the rightmost ` in context ` and the last
/// `>->` (the `>` closing `<number>` immediately precedes `->`, and only the
/// number→destination boundary has that shape). Falls back to the last bare `->`
/// for the bracketless `from->to` shape.
pub(crate) fn processing_parts(msg: &str) -> Option<ProcessingParts> {
    let proc_idx = msg.find("Processing ")?;
    let base = proc_idx + "Processing ".len();
    let after_proc = &msg[base..];

    let ctx_idx = after_proc.rfind(" in context ")?;
    let head = &after_proc[..ctx_idx];

    let ctx_start = base + ctx_idx + " in context ".len();
    let context_token = msg[ctx_start..].split_whitespace().next()?;
    let context = ctx_start..ctx_start + context_token.len();

    let (head_range, dest) = match head.rfind(">->") {
        Some(i) => (base..base + i + 1, base + i + ">->".len()..base + ctx_idx),
        None => {
            let i = head.rfind("->")?;
            (base..base + i, base + i + "->".len()..base + ctx_idx)
        }
    };

    // Only the bracketed shape separates a display name from a number, and the
    // head's closing `>` is what marks it.
    let (name, number) = match msg[head_range.clone()]
        .strip_suffix('>')
        .and_then(|h| h.rfind(" <"))
    {
        Some(i) => (
            Some(head_range.start..head_range.start + i),
            Some(head_range.start + i + " <".len()..head_range.end - 1),
        ),
        None => (None, None),
    };

    Some(ProcessingParts {
        head: head_range,
        name: name.filter(|r| !r.is_empty()),
        number: number.filter(|r| !r.is_empty()),
        dest,
        context,
    })
}
