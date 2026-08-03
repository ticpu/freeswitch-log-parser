//! The `YYYY-MM-DD-HH-MM-SS` stamp form, which sorts lexicographically and so
//! lets a caller order rotated files and window entries without a date library.

/// The rotation stamp encoded in a `freeswitch.log.*` filename, or `None` for the
/// active log and for any name that does not carry one.
///
/// Only the stamp is read; whatever logrotate appends after it (a sequence
/// number, a compression suffix) is ignored.
pub fn log_rotation_stamp(filename: &str) -> Option<&str> {
    const STAMP_LEN: usize = 19;
    let rest = filename.strip_prefix("freeswitch.log.")?;
    let candidate = rest.get(..STAMP_LEN)?;
    candidate
        .bytes()
        .enumerate()
        .all(|(i, b)| match i {
            4 | 7 | 10 | 13 | 16 => b == b'-',
            _ => b.is_ascii_digit(),
        })
        .then_some(candidate)
}

/// Rewrite a log entry's `YYYY-MM-DD HH:MM:SS.ffffff` timestamp into the stamp
/// form, dropping the sub-second part so it compares against a filename stamp.
///
/// Input too short to hold a full timestamp is normalized as best it can be
/// rather than rejected, so a partially parsed entry still windows sanely.
pub fn normalize_entry_timestamp(ts: &str) -> String {
    const TS_LEN: usize = 19;
    if ts.len() < TS_LEN {
        let mut s = ts.replace(['T', ':', ' '], "-");
        while s.ends_with('-') {
            s.pop();
        }
        return s;
    }
    format!("{}-{}", &ts[..10], ts[11..TS_LEN].replace(':', "-"))
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
    fn normalized_forms_compare_lexicographically() {
        let entry = normalize_entry_timestamp("2026-03-08 16:52:07.123456");
        let earlier = log_rotation_stamp("freeswitch.log.2026-03-08-00-00-00.1.xz").unwrap();
        let later = log_rotation_stamp("freeswitch.log.2026-03-09-00-00-00.1.xz").unwrap();
        assert!(entry.as_str() > earlier);
        assert!(entry.as_str() < later);
    }
}
