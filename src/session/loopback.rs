//! mod_loopback A/B leg pairing.
//!
//! The two halves of a loopback call are separate sessions with no peer UUID
//! between them until a channel dump exposes `other_loopback_leg_uuid`. Their
//! names carry the pairing: mod_loopback derives the B leg's name from the A
//! leg's destination number, differing only in the trailing leg letter.

const PREFIX: &str = "loopback/";

/// A leg name of the loopback whose B leg is `channel_name`.
pub(crate) fn a_leg_name(channel_name: &str) -> Option<String> {
    let destination = channel_name.strip_prefix(PREFIX)?.strip_suffix("-b")?;
    if destination.is_empty() {
        return None;
    }
    Some(format!("{PREFIX}{destination}-a"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b_leg_names_its_a_leg() {
        assert_eq!(
            a_leg_name("loopback/tty-b").as_deref(),
            Some("loopback/tty-a")
        );
        assert_eq!(
            a_leg_name("loopback/9-1-1-b").as_deref(),
            Some("loopback/9-1-1-a")
        );
    }

    #[test]
    fn a_leg_and_foreign_endpoints_pair_with_nothing() {
        assert!(a_leg_name("loopback/tty-a").is_none());
        assert!(a_leg_name("sofia/internal/1000-b").is_none());
        assert!(a_leg_name("loopback/-b").is_none());
    }
}
