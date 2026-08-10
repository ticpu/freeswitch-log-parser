//! Applying replacements to located spans.

use std::ops::Range;

use super::collect::{message_fields, raw_line_fields};
use super::kind::{Field, FieldLocation, RenderError, RenderedEntry};

/// Rewrite the spans of one text, returning the result.
///
/// `f` receives each field and the text it covers, and returns the replacement
/// or `None` to leave it alone. Every field must index `text` — filter by
/// [`Field::at`] before calling, since a range from another location means
/// nothing here.
///
/// Nested spans are how the parser reports an address inside a channel name, so
/// a replacement contained in another replacement is dropped: the outer rewrite
/// already covers those bytes. Two replacements that overlap only partially have
/// no such reading and are [`RenderError::OverlappingSpans`].
///
/// Bounds and character boundaries are checked for every field, so this never
/// panics on a hand-built span.
pub fn apply_fields<'a>(
    text: &str,
    fields: impl IntoIterator<Item = &'a Field>,
    f: impl Fn(&Field, &str) -> Option<String>,
) -> Result<String, RenderError> {
    let mut replacements: Vec<(FieldLocation, Range<usize>, String)> = Vec::new();

    for field in fields {
        let range = field.range.clone();
        if range.end > text.len() {
            return Err(RenderError::OutOfBounds {
                at: field.at,
                range,
                len: text.len(),
            });
        }
        if !text.is_char_boundary(range.start) || !text.is_char_boundary(range.end) {
            return Err(RenderError::NotOnCharBoundary {
                at: field.at,
                range,
            });
        }
        if let Some(new) = f(field, &text[range.clone()]) {
            replacements.push((field.at, range, new));
        }
    }

    replacements.sort_by(|(_, a, _), (_, b, _)| {
        (a.start, std::cmp::Reverse(a.end)).cmp(&(b.start, std::cmp::Reverse(b.end)))
    });

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut accepted: Option<Range<usize>> = None;

    for (at, range, new) in replacements {
        if let Some(prev) = &accepted {
            if range.start < prev.end {
                // Contained in a rewrite that already covers these bytes.
                if range.end <= prev.end {
                    continue;
                }
                return Err(RenderError::OverlappingSpans {
                    at,
                    first: prev.clone(),
                    second: range,
                });
            }
        }
        out.push_str(&text[cursor..range.start]);
        out.push_str(&new);
        cursor = range.end;
        accepted = Some(range);
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

impl crate::stream::LogEntry {
    /// Locate every field this entry carries, across its message and each raw
    /// attached line.
    ///
    /// Recomputed per call and never stored — an entry nobody interrogates pays
    /// nothing. Ranges index [`message`](crate::LogEntry::message) or the
    /// attached line named by [`Field::at`], never a reassembled
    /// [`Block`](crate::Block); [`uuid`](crate::LogEntry::uuid) is a field of the
    /// entry rather than message text, so no span covers it.
    ///
    /// Ordering within one location is [`message_fields`]'s; locations follow
    /// the message, then attached lines in order.
    pub fn fields(&self) -> Vec<Field> {
        let mut out = message_fields(&self.message);
        for (i, line) in self.attached.iter().enumerate() {
            out.extend(raw_line_fields(line, FieldLocation::Attached(i)));
        }
        out
    }

    /// Whether the logger's write buffer cut short the text this span indexes,
    /// leaving the span itself incomplete.
    ///
    /// The cut always falls at the end of the text, so a span that stops before
    /// it survived whole. A closed `[value]` is spanned inside its brackets and
    /// so can never reach the end of its line; only a value the cut left
    /// unterminated can. A span at a location this entry does not have is not
    /// truncated — it indexes nothing here.
    pub fn is_truncated(&self, field: &Field) -> bool {
        if !self.cut_texts.contains(&field.at) {
            return false;
        }
        let len = match field.at {
            FieldLocation::Message => self.message.len(),
            FieldLocation::Attached(i) => match self.attached.get(i) {
                Some(line) => line.len(),
                None => return false,
            },
        };
        field.range.end == len
    }

    /// Rewrite this entry's fields, returning one string per render unit.
    ///
    /// `f` is called with each field and the text it covers; `None` leaves it
    /// as it was. The message and each attached line are rewritten separately
    /// because they are separate texts — see [`apply_fields`] for how nested and
    /// overlapping replacements resolve.
    ///
    /// [`uuid`](crate::LogEntry::uuid), [`timestamp`](crate::LogEntry::timestamp)
    /// and the rest of the header are entry fields rather than message text, so
    /// a consumer rendering them handles them itself.
    pub fn render_with(
        &self,
        f: impl Fn(&Field, &str) -> Option<String>,
    ) -> Result<RenderedEntry, RenderError> {
        let fields = self.fields();

        let message = apply_fields(
            &self.message,
            fields.iter().filter(|x| x.at == FieldLocation::Message),
            &f,
        )?;

        let attached = self
            .attached
            .iter()
            .enumerate()
            .map(|(i, line)| {
                apply_fields(
                    line,
                    fields.iter().filter(|x| x.at == FieldLocation::Attached(i)),
                    &f,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RenderedEntry { message, attached })
    }
}
