//! Typed byte spans over the raw text of a log entry.

use std::ops::Range;

/// The byte ranges a dialplan `Processing` line decomposes into.
pub(crate) struct ProcessingParts {
    /// Caller side as a whole — display name and `<number>` if present.
    pub(crate) head: Range<usize>,
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

    let (head, dest) = match head.rfind(">->") {
        Some(i) => (base..base + i + 1, base + i + ">->".len()..base + ctx_idx),
        None => {
            let i = head.rfind("->")?;
            (base..base + i, base + i + "->".len()..base + ctx_idx)
        }
    };

    Some(ProcessingParts {
        head,
        dest,
        context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(msg: &str) -> ProcessingParts {
        processing_parts(msg).expect("should parse")
    }

    #[test]
    fn bracketed_shape_keeps_number_in_head() {
        let msg = "Processing ACME <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "ACME <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
        assert_eq!(&msg[p.context], "public");
    }

    #[test]
    fn name_containing_arrow_and_angle_survives_anchoring() {
        let msg = "Processing a->b <c <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "a->b <c <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn bare_shape_falls_back_to_last_arrow() {
        let msg = "Processing 15555550100->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "15555550100");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn multibyte_name_keeps_spans_on_char_boundaries() {
        let msg = "Processing Jérôme <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.head], "Jérôme <15555550100>");
        assert_eq!(&msg[p.dest], "1263");
    }

    #[test]
    fn context_stops_at_first_whitespace() {
        let msg = "Processing ACME <15555550100>->1263 in context public extra";
        let p = parts(msg);
        assert_eq!(&msg[p.context], "public");
    }

    #[test]
    fn rightmost_in_context_wins() {
        let msg = "Processing a in context b <15555550100>->1263 in context public";
        let p = parts(msg);
        assert_eq!(&msg[p.context], "public");
        assert_eq!(&msg[p.head], "a in context b <15555550100>");
    }

    #[test]
    fn no_context_marker_yields_none() {
        assert!(processing_parts("Processing ACME <15555550100>->1263").is_none());
    }
}
