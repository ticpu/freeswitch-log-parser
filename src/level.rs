use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Err,
    Crit,
    Alert,
    Console,
}

impl LogLevel {
    pub const ALL_LABELS: &[&str] = &[
        "debug", "info", "notice", "warning", "err", "crit", "alert", "console",
    ];
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Notice => "notice",
            LogLevel::Warning => "warning",
            LogLevel::Err => "err",
            LogLevel::Crit => "crit",
            LogLevel::Alert => "alert",
            LogLevel::Console => "console",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLevelError;

impl fmt::Display for ParseLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid log level")
    }
}

impl std::error::Error for ParseLevelError {}

impl FromStr for LogLevel {
    type Err = ParseLevelError;

    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        if s.eq_ignore_ascii_case("debug") {
            Ok(LogLevel::Debug)
        } else if s.eq_ignore_ascii_case("info") {
            Ok(LogLevel::Info)
        } else if s.eq_ignore_ascii_case("notice") {
            Ok(LogLevel::Notice)
        } else if s.eq_ignore_ascii_case("warning") {
            Ok(LogLevel::Warning)
        } else if s.eq_ignore_ascii_case("err") {
            Ok(LogLevel::Err)
        } else if s.eq_ignore_ascii_case("crit") {
            Ok(LogLevel::Crit)
        } else if s.eq_ignore_ascii_case("alert") {
            Ok(LogLevel::Alert)
        } else if s.eq_ignore_ascii_case("console") {
            Ok(LogLevel::Console)
        } else {
            Result::Err(ParseLevelError)
        }
    }
}

impl LogLevel {
    pub fn from_bracketed(s: &str) -> Option<LogLevel> {
        let bytes = s.as_bytes();
        if bytes.len() < 3 || bytes[0] != b'[' || bytes[bytes.len() - 1] != b']' {
            return None;
        }
        s[1..s.len() - 1].parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_round_trip() {
        let variants = [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Notice,
            LogLevel::Warning,
            LogLevel::Err,
            LogLevel::Crit,
            LogLevel::Alert,
            LogLevel::Console,
        ];
        for v in variants {
            let s = v.to_string();
            let parsed: LogLevel = s.parse().unwrap();
            assert_eq!(parsed, v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("DEBUG".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("Info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("WARNING".parse::<LogLevel>().unwrap(), LogLevel::Warning);
        assert_eq!("err".parse::<LogLevel>().unwrap(), LogLevel::Err);
    }

    #[test]
    fn from_str_invalid() {
        assert!("FAKE".parse::<LogLevel>().is_err());
        assert!("".parse::<LogLevel>().is_err());
        assert!("ERROR".parse::<LogLevel>().is_err());
    }

    #[test]
    fn from_bracketed_all_variants() {
        assert_eq!(LogLevel::from_bracketed("[DEBUG]"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_bracketed("[INFO]"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_bracketed("[NOTICE]"), Some(LogLevel::Notice));
        assert_eq!(
            LogLevel::from_bracketed("[WARNING]"),
            Some(LogLevel::Warning)
        );
        assert_eq!(LogLevel::from_bracketed("[ERR]"), Some(LogLevel::Err));
        assert_eq!(LogLevel::from_bracketed("[CRIT]"), Some(LogLevel::Crit));
        assert_eq!(LogLevel::from_bracketed("[ALERT]"), Some(LogLevel::Alert));
        assert_eq!(
            LogLevel::from_bracketed("[CONSOLE]"),
            Some(LogLevel::Console)
        );
    }

    #[test]
    fn from_bracketed_rejects_malformed() {
        assert_eq!(LogLevel::from_bracketed("[FAKE]"), None);
        assert_eq!(LogLevel::from_bracketed("DEBUG"), None);
        assert_eq!(LogLevel::from_bracketed("[]"), None);
        assert_eq!(LogLevel::from_bracketed("["), None);
        assert_eq!(LogLevel::from_bracketed(""), None);
    }

    #[test]
    fn ord_severity_order() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Notice);
        assert!(LogLevel::Notice < LogLevel::Warning);
        assert!(LogLevel::Warning < LogLevel::Err);
        assert!(LogLevel::Err < LogLevel::Crit);
        assert!(LogLevel::Crit < LogLevel::Alert);
        assert!(LogLevel::Alert < LogLevel::Console);
    }
}
