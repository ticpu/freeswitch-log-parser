use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};

use freeswitch_log_parser::{Block, LogLevel};

use crate::files::normalize_entry_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Always,
    Never,
}

const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const DIM_YELLOW: &str = "\x1b[33;2m";
const DIM_GREEN: &str = "\x1b[32;2m";
const BRIGHT_GREEN: &str = "\x1b[92m";

fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match h as u32 {
        0..=59 => (c, x, 0.0),
        60..=119 => (x, c, 0.0),
        120..=179 => (0.0, c, x),
        180..=239 => (0.0, x, c),
        240..=299 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

/// Stable per-UUID truecolor so each call is visually distinct across entries.
fn uuid_truecolor(uuid: &str) -> (u8, u8, u8) {
    let mut hasher = DefaultHasher::new();
    uuid.hash(&mut hasher);
    let hue = (hasher.finish() % 360) as f64;
    hsl_to_rgb(hue, 0.30, 0.82)
}

fn level_color(level: Option<LogLevel>) -> &'static str {
    match level {
        Some(LogLevel::Err | LogLevel::Crit | LogLevel::Alert) => RED,
        Some(LogLevel::Warning) => MAGENTA,
        Some(LogLevel::Info) => GREEN,
        Some(LogLevel::Notice) => CYAN,
        Some(LogLevel::Debug) => YELLOW,
        Some(LogLevel::Console) => GREEN,
        None => "",
    }
}

pub struct EntryPrinter {
    pub color: ColorMode,
    pub show_blocks: bool,
    pub show_session: bool,
    pub show_filename: bool,
    pub show_line_numbers: bool,
}

impl EntryPrinter {
    pub fn print_entry(
        &self,
        w: &mut dyn Write,
        entry: &freeswitch_log_parser::LogEntry,
        session: Option<&freeswitch_log_parser::SessionSnapshot>,
        filename: Option<&str>,
    ) -> io::Result<()> {
        let level = entry
            .level
            .map(|l| l.to_string())
            .unwrap_or_else(|| "-".to_string());
        let time = if entry.timestamp.len() >= 11 {
            &entry.timestamp[11..]
        } else {
            &entry.timestamp
        };

        let use_color = self.color == ColorMode::Always;
        let lc = if use_color {
            level_color(entry.level)
        } else {
            ""
        };
        let reset = if use_color { RESET } else { "" };
        let dim = if use_color { DIM } else { "" };

        let uuid = if entry.uuid.is_empty() {
            format!("{dim}-{reset}")
        } else if use_color {
            let (r, g, b) = uuid_truecolor(&entry.uuid);
            format!("\x1b[38;2;{r};{g};{b}m{}{RESET}", entry.uuid)
        } else {
            entry.uuid.clone()
        };

        if let Some(fname) = filename.filter(|_| self.show_filename) {
            write!(w, "{dim}{fname}{reset} ")?;
        }

        if self.show_line_numbers {
            write!(w, "{lc}L{line:>6} ", line = entry.line_number)?;
        }

        writeln!(
            w,
            "{lc}{kind:>9} {level:>7}{reset} {time} {uuid} {lc}[{mkind}]{reset} {lc}{msg}{reset}",
            kind = entry.kind,
            mkind = entry.message_kind,
            msg = entry.message,
        )?;

        if self.show_blocks {
            if let Some(block) = &entry.block {
                self.print_block(w, block, use_color)?;
            }
        }

        if self.show_session {
            if let Some(session) = session {
                self.print_session(w, session, use_color)?;
            }
        }

        for warning in &entry.warnings {
            let wc = if use_color { MAGENTA } else { "" };
            writeln!(w, "{wc}    WARN {warning}{reset}")?;
        }

        if !entry.attached.is_empty() {
            let dim_s = if use_color { DIM } else { "" };
            writeln!(
                w,
                "{dim_s}         ({} attached lines){reset}",
                entry.attached.len()
            )?;
        }

        Ok(())
    }

    fn print_block(&self, w: &mut dyn Write, block: &Block, use_color: bool) -> io::Result<()> {
        let bc = if use_color { DIM_GREEN } else { "" };
        let sc = if use_color { BRIGHT_GREEN } else { "" };
        let reset = if use_color { RESET } else { "" };

        match block {
            Block::ChannelData { fields, variables } => {
                for (name, value) in fields {
                    writeln!(w, "{bc}         field  {name}: {value}{reset}")?;
                }
                for (name, value) in variables {
                    let short = if value.len() > 80 {
                        format!("{}...", &value[..77])
                    } else {
                        value.clone()
                    };
                    writeln!(w, "{bc}         var    {name}: {short}{reset}")?;
                }
            }
            Block::Sdp { direction, body } => {
                writeln!(
                    w,
                    "{sc}         sdp    {direction} ({} lines){reset}",
                    body.len()
                )?;
                for line in body {
                    writeln!(w, "{sc}         sdp    {line}{reset}")?;
                }
            }
            Block::CodecNegotiation {
                comparisons,
                selected,
            } => {
                let cc = if use_color { DIM_YELLOW } else { "" };
                writeln!(
                    w,
                    "{cc}         codec  {} comparisons, {} selected{reset}",
                    comparisons.len(),
                    selected.len()
                )?;
                for (offered, local) in comparisons {
                    writeln!(w, "{cc}         codec  {offered} vs {local}{reset}")?;
                }
                for s in selected {
                    writeln!(w, "{cc}         codec  MATCH {s}{reset}")?;
                }
            }
            _ => {
                writeln!(w, "{bc}         block  {block:?}{reset}")?;
            }
        }
        Ok(())
    }

    fn print_session(
        &self,
        w: &mut dyn Write,
        session: &freeswitch_log_parser::SessionSnapshot,
        use_color: bool,
    ) -> io::Result<()> {
        let dim = if use_color { DIM } else { "" };
        let reset = if use_color { RESET } else { "" };
        let mut parts = Vec::new();
        if let Some(ctx) = &session.dialplan_context {
            parts.push(format!("ctx={ctx}"));
        }
        if let Some(d) = &session.initial_destination {
            parts.push(format!("dest={d}"));
        }
        if let Some(state) = &session.channel_state {
            parts.push(format!("state={state}"));
        }
        if let Some(name) = &session.channel_name {
            parts.push(format!("ch={name}"));
        }
        if !parts.is_empty() {
            writeln!(w, "{dim}         session {}{reset}", parts.join(" "))?;
        }
        Ok(())
    }

    pub fn print_stats(
        &self,
        w: &mut dyn Write,
        stats: &freeswitch_log_parser::ParseStats,
        entry_count: u64,
        session_count: usize,
    ) -> io::Result<()> {
        writeln!(
            w,
            "{entry_count} entries, {} lines, {} unclassified, {session_count} sessions",
            stats.lines_processed, stats.lines_unclassified,
        )
    }

    pub fn print_unclassified(
        &self,
        w: &mut dyn Write,
        stats: &freeswitch_log_parser::ParseStats,
    ) -> io::Result<()> {
        if stats.unclassified_lines.is_empty() {
            return Ok(());
        }
        writeln!(w)?;
        writeln!(w, "unclassified lines:")?;
        for u in &stats.unclassified_lines {
            writeln!(
                w,
                "  L{}: {:?}{}",
                u.line_number,
                u.reason,
                u.data
                    .as_ref()
                    .map(|d| format!(" | {}", if d.len() > 100 { &d[..100] } else { d }))
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct FilterConfig {
    /// Lowercased UUID needles; an entry matches if any is a substring.
    pub uuid_filter: Vec<String>,
    /// Restrict UUID matching to `entry.uuid` (output pass) vs. also scanning
    /// message and attached lines (discovery pass).
    pub uuid_strict: bool,
    /// Extend fgrep/grep matching into attached/block lines, not just the message.
    pub match_blocks: bool,
    pub min_level: Option<LogLevel>,
    pub category: Option<String>,
    /// Lowercased fixed-string needle.
    pub fgrep: Option<String>,
    pub grep: Option<regex::Regex>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

impl FilterConfig {
    /// A copy suited to peer-UUID discovery: category cleared (the seed term may
    /// surface under any message kind), UUID matching loosened to message bodies
    /// and attached lines so the seed is found wherever it appears.
    pub fn for_discovery(&self) -> FilterConfig {
        FilterConfig {
            uuid_filter: self.uuid_filter.clone(),
            uuid_strict: false,
            match_blocks: true,
            min_level: self.min_level,
            category: None,
            fgrep: self.fgrep.clone(),
            grep: self.grep.clone(),
            from_ts: self.from_ts.clone(),
            until_ts: self.until_ts.clone(),
        }
    }

    pub fn matches(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        if let Some(min) = self.min_level {
            if let Some(level) = entry.level {
                if level < min {
                    return false;
                }
            }
        }

        if !self.uuid_filter.is_empty() {
            let uuid_lc = entry.uuid.to_lowercase();
            let in_uuid = self.uuid_filter.iter().any(|f| uuid_lc.contains(f));
            let hit = if self.uuid_strict {
                in_uuid
            } else {
                in_uuid
                    || {
                        let msg_lc = entry.message.to_lowercase();
                        self.uuid_filter.iter().any(|f| msg_lc.contains(f))
                    }
                    || entry.attached.iter().any(|l| {
                        let l_lc = l.to_lowercase();
                        self.uuid_filter.iter().any(|f| l_lc.contains(f))
                    })
            };
            if !hit {
                return false;
            }
        }

        if let Some(ref cat) = self.category {
            if entry.message_kind.label() != cat.as_str() {
                return false;
            }
        }

        if let Some(ref pattern) = self.fgrep {
            let in_msg = entry.message.to_lowercase().contains(pattern);
            let hit = in_msg
                || (self.match_blocks
                    && entry
                        .attached
                        .iter()
                        .any(|l| l.to_lowercase().contains(pattern)));
            if !hit {
                return false;
            }
        }

        if let Some(ref re) = self.grep {
            let hit = re.is_match(&entry.message)
                || (self.match_blocks && entry.attached.iter().any(|l| re.is_match(l)));
            if !hit {
                return false;
            }
        }

        if (self.from_ts.is_some() || self.until_ts.is_some()) && !entry.timestamp.is_empty() {
            let entry_ts = normalize_entry_timestamp(&entry.timestamp);
            if let Some(ref from) = self.from_ts {
                if entry_ts.as_str() < from.as_str() {
                    return false;
                }
            }
            if let Some(ref until) = self.until_ts {
                if entry_ts.as_str() > until.as_str() {
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeswitch_log_parser::{AttachedLines, LineKind, LogEntry, MessageKind};

    fn entry(uuid: &str, message: &str, attached: &[&str]) -> LogEntry {
        let mut a = AttachedLines::new();
        for l in attached {
            a.push(l);
        }
        LogEntry {
            uuid: uuid.to_string(),
            timestamp: String::new(),
            level: None,
            idle_pct: None,
            source: None,
            message: message.to_string(),
            kind: LineKind::Full,
            message_kind: MessageKind::General,
            block: None,
            attached: a,
            line_number: 0,
            warnings: Vec::new(),
        }
    }

    fn filter() -> FilterConfig {
        FilterConfig {
            uuid_filter: Vec::new(),
            uuid_strict: true,
            match_blocks: false,
            min_level: None,
            category: None,
            fgrep: None,
            grep: None,
            from_ts: None,
            until_ts: None,
        }
    }

    #[test]
    fn uuid_or_matches_any_needle() {
        let mut f = filter();
        f.uuid_filter = vec!["aaaa".into(), "bbbb".into()];
        assert!(f.matches(&entry("xx-bbbb-yy", "msg", &[])));
        assert!(f.matches(&entry("aaaa-0000", "msg", &[])));
        assert!(!f.matches(&entry("cccc-0000", "msg", &[])));
    }

    #[test]
    fn uuid_strict_ignores_message_body() {
        let mut f = filter();
        f.uuid_filter = vec!["dead".into()];
        // strict: only the uuid field counts, not the message text
        assert!(!f.matches(&entry("0000", "peer dead leg", &[])));
        f.uuid_strict = false;
        assert!(f.matches(&entry("0000", "peer dead leg", &[])));
    }

    #[test]
    fn fgrep_into_blocks_only_with_match_blocks() {
        let mut f = filter();
        f.fgrep = Some("m=audio".into());
        let e = entry("u", "Remote SDP:", &["v=0", "m=audio 5004 RTP/AVP 0"]);
        assert!(!f.matches(&e));
        f.match_blocks = true;
        assert!(f.matches(&e));
    }

    #[test]
    fn for_discovery_clears_category_and_loosens() {
        let mut f = filter();
        f.category = Some("execute".into());
        f.uuid_filter = vec!["seed".into()];
        let d = f.for_discovery();
        assert!(d.category.is_none());
        assert!(!d.uuid_strict);
        assert!(d.match_blocks);
        // seed found in message body survives discovery despite category mismatch
        assert!(d.matches(&entry("0000", "found seed here", &[])));
    }
}
