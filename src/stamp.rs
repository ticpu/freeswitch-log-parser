//! The `YYYY-MM-DD-HH-MM-SS` stamp form, which sorts lexicographically and so
//! lets a caller order rotated files and window entries without a date library.

use crate::mask::Mask;

/// Width of the `YYYY-MM-DD-HH-MM-SS` stamp form.
const STAMP_LEN: usize = 19;

const STAMP_MASK: Mask = Mask {
    len: STAMP_LEN,
    separators: &[(4, b'-'), (7, b'-'), (10, b'-'), (13, b'-'), (16, b'-')],
    filler: u8::is_ascii_digit,
};

/// The rotation stamp encoded in a `freeswitch.log.*` filename, or `None` for the
/// active log and for any name that does not carry one.
///
/// Only the stamp is read; whatever logrotate appends after it (a sequence
/// number, a compression suffix) is ignored.
pub fn log_rotation_stamp(filename: &str) -> Option<&str> {
    let rest = filename.strip_prefix("freeswitch.log.")?;
    let candidate = rest.get(..STAMP_LEN)?;
    STAMP_MASK
        .matches_at(candidate.as_bytes(), 0)
        .then_some(candidate)
}

/// Rewrite a log entry's `YYYY-MM-DD HH:MM:SS.ffffff` timestamp into the stamp
/// form, dropping the sub-second part so it compares against a filename stamp.
///
/// Input too short to hold a full timestamp is normalized as best it can be
/// rather than rejected, so a partially parsed entry still windows sanely.
pub fn normalize_entry_timestamp(ts: &str) -> String {
    // `get` rather than a byte slice: a caller can hand this any string, and a
    // multibyte codepoint straddling either bound would panic on `&ts[..n]`.
    if let (Some(date), Some(time)) = (ts.get(..10), ts.get(11..STAMP_LEN)) {
        return format!("{date}-{}", time.replace(':', "-"));
    }
    loose_stamp(ts)
}

/// The stamp form of whatever `input` spells, however partial: the separators
/// an operator is likely to type become `-`, and a trailing one is dropped.
fn loose_stamp(input: &str) -> String {
    let mut s = input.replace(['T', ':', ' '], "-");
    while s.ends_with('-') {
        s.pop();
    }
    s
}

/// Fill a partial stamp out to all six components, taking each missing one
/// from `defaults`.
fn pad_stamp(s: &str, defaults: [&str; 6]) -> String {
    let parts: Vec<&str> = s.split('-').collect();
    defaults
        .iter()
        .enumerate()
        .map(|(i, default)| match parts.get(i) {
            Some(p) if !p.is_empty() => *p,
            _ => default,
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// The earliest stamp a partial date names — `"2026-03"` becomes
/// `"2026-03-01-00-00-00"` — for use as an inclusive window start.
pub fn stamp_lower_bound(input: &str) -> String {
    pad_stamp(&loose_stamp(input), ["0000", "01", "01", "00", "00", "00"])
}

/// The latest stamp a partial date names — `"2026-03"` becomes
/// `"2026-03-31-23-59-59"` — for use as an inclusive window end.
///
/// The day defaults to 31 whatever the month holds: the stamp is compared
/// lexicographically, so a bound past the month's last day excludes nothing.
pub fn stamp_upper_bound(input: &str) -> String {
    pad_stamp(&loose_stamp(input), ["9999", "12", "31", "23", "59", "59"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_from_rotated_name() {
        assert_eq!(
            log_rotation_stamp("freeswitch.log.2026-03-08-16-52-07.1.xz"),
            Some("2026-03-08-16-52-07"),
        );
        assert_eq!(
            log_rotation_stamp("freeswitch.log.2026-03-08-16-52-07"),
            Some("2026-03-08-16-52-07"),
        );
    }

    #[test]
    fn no_stamp_on_active_log_or_foreign_names() {
        assert_eq!(log_rotation_stamp("freeswitch.log"), None);
        assert_eq!(log_rotation_stamp("freeswitch.log.1.xz"), None);
        assert_eq!(log_rotation_stamp("freeswitch.log.not-a-date-here!!"), None);
        assert_eq!(log_rotation_stamp("other.log.2026-03-08-16-52-07"), None);
    }

    #[test]
    fn stamp_rejects_multibyte_boundary() {
        // `get(..19)` returns None rather than panicking mid-codepoint.
        assert_eq!(
            log_rotation_stamp("freeswitch.log.2026-03-08-16-52-é"),
            None
        );
    }

    #[test]
    fn entry_timestamp_normalized() {
        assert_eq!(
            normalize_entry_timestamp("2026-03-08 16:52:07.123456"),
            "2026-03-08-16-52-07",
        );
        assert_eq!(
            normalize_entry_timestamp("2026-03-08 16:52:07"),
            "2026-03-08-16-52-07",
        );
    }

    #[test]
    fn short_entry_timestamp_still_normalizes() {
        assert_eq!(normalize_entry_timestamp("2026-03-08"), "2026-03-08");
        assert_eq!(normalize_entry_timestamp("2026-03-08 "), "2026-03-08");
        assert_eq!(normalize_entry_timestamp(""), "");
    }

    #[test]
    fn multibyte_entry_timestamp_does_not_panic() {
        // A codepoint straddling either slice bound would panic on a byte slice.
        assert_eq!(
            normalize_entry_timestamp("2026-03-08é16:52:07"),
            "2026-03-08é16-52-07"
        );
        assert_eq!(
            normalize_entry_timestamp("2026-03-0é 16:52:07"),
            "2026-03-0é-16-52-07"
        );
        assert_eq!(normalize_entry_timestamp("ééééééééé"), "ééééééééé");
    }

    #[test]
    fn bounds_fill_a_partial_date_from_both_ends() {
        for (input, lower, upper) in [
            ("2026", "2026-01-01-00-00-00", "2026-12-31-23-59-59"),
            ("2026-03", "2026-03-01-00-00-00", "2026-03-31-23-59-59"),
            ("2026-03-08", "2026-03-08-00-00-00", "2026-03-08-23-59-59"),
            (
                "2026-03-08T15:48",
                "2026-03-08-15-48-00",
                "2026-03-08-15-48-59",
            ),
            (
                "2026-03-08 15:48:07",
                "2026-03-08-15-48-07",
                "2026-03-08-15-48-07",
            ),
        ] {
            assert_eq!(stamp_lower_bound(input), lower, "lower for {input}");
            assert_eq!(stamp_upper_bound(input), upper, "upper for {input}");
        }
    }

    #[test]
    fn an_empty_bound_spans_everything() {
        assert!(stamp_lower_bound("") < stamp_upper_bound(""));
        assert!(stamp_lower_bound("") < normalize_entry_timestamp("2026-03-08 16:52:07.123456"));
    }

    #[test]
    fn normalized_forms_compare_lexicographically() {
        let entry = normalize_entry_timestamp("2026-03-08 16:52:07.123456");
        let earlier = log_rotation_stamp("freeswitch.log.2026-03-08-00-00-00.1.xz").unwrap();
        let later = log_rotation_stamp("freeswitch.log.2026-03-09-00-00-00.1.xz").unwrap();
        assert!(entry.as_str() > earlier);
        assert!(entry.as_str() < later);
    }
}
