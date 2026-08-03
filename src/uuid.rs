//! Positional UUID recognition, for callers that need to find a channel UUID
//! somewhere other than a line's session prefix — inside a message body, a
//! channel-variable value, or an operator-supplied search needle.

use crate::line::{is_uuid_body_at, UUID_LEN};

/// Whether `s` is exactly one canonical UUID: 8-4-4-4-12 hex digits, either case.
pub fn is_uuid(s: &str) -> bool {
    s.len() == UUID_LEN && is_uuid_body_at(s.as_bytes(), 0)
}

/// Iterate the UUIDs embedded anywhere in `text`, yielding each match's byte
/// offset and slice. Matches never overlap.
pub fn find_uuids(text: &str) -> FindUuids<'_> {
    FindUuids { text, pos: 0 }
}

/// Iterator returned by [`find_uuids`].
#[derive(Debug, Clone)]
pub struct FindUuids<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Iterator for FindUuids<'a> {
    type Item = (usize, &'a str);

    fn next(&mut self) -> Option<(usize, &'a str)> {
        let bytes = self.text.as_bytes();
        while self.pos + UUID_LEN <= bytes.len() {
            let start = self.pos;
            // Every UUID byte is ASCII, so `start` is always a char boundary and
            // the slice below cannot split a codepoint.
            if is_uuid_body_at(bytes, start) {
                self.pos = start + UUID_LEN;
                return Some((start, &self.text[start..self.pos]));
            }
            self.pos += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-2222-3333-4444-555555555555";
    const B: &str = "aaaabbbb-cccc-dddd-eeee-ffff00001111";

    fn found(text: &str) -> Vec<&str> {
        find_uuids(text).map(|(_, u)| u).collect()
    }

    #[test]
    fn is_uuid_accepts_either_case() {
        assert!(is_uuid(A));
        assert!(is_uuid("AAAABBBB-2222-3333-4444-5555CCCCDDDD"));
    }

    #[test]
    fn is_uuid_rejects_partial_and_trailing() {
        assert!(!is_uuid(&A[..35]));
        assert!(!is_uuid(&format!("{A}0")));
        assert!(!is_uuid("11111111_2222-3333-4444-555555555555"));
        assert!(!is_uuid("gggggggg-2222-3333-4444-555555555555"));
    }

    #[test]
    fn finds_uuid_at_end_of_string() {
        assert_eq!(found(&format!("Peer UUID: {A}")), vec![A]);
    }

    #[test]
    fn finds_uuid_abutting_punctuation() {
        assert_eq!(found(&format!("<{A}>;tag=x")), vec![A]);
    }

    #[test]
    fn finds_uppercase_hex() {
        let upper = "AAAABBBB-2222-3333-4444-5555CCCCDDDD";
        assert_eq!(found(&format!("+OK {upper}")), vec![upper]);
    }

    #[test]
    fn finds_back_to_back_uuids() {
        assert_eq!(found(&format!("{A}{B}")), vec![A, B]);
        assert_eq!(found(&format!("+OK {A}\n{B}")), vec![A, B]);
    }

    #[test]
    fn reports_byte_offsets() {
        let text = format!("Peer UUID: {A}");
        let hits: Vec<usize> = find_uuids(&text).map(|(at, _)| at).collect();
        assert_eq!(hits, vec![11]);
    }

    #[test]
    fn offsets_survive_multibyte_text() {
        let text = format!("café {A}");
        let (at, uuid) = find_uuids(&text).next().unwrap();
        assert_eq!(uuid, A);
        assert_eq!(&text[at..], A);
    }

    #[test]
    fn no_match_in_plain_text() {
        assert!(found("no identifiers here at all").is_empty());
        assert!(found("deadbeef-dead-beef-dead").is_empty());
    }

    #[test]
    fn a_longer_hex_run_yields_its_leading_uuid() {
        // Substring semantics, not tokenization: nothing here delimits a UUID, so
        // the first 36 conforming bytes are the match.
        assert_eq!(found(&format!("{A}99")), vec![A]);
    }
}
