use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use freeswitch_log_parser::{
    find_uuids, normalize_entry_timestamp, truncate_at_char_boundary, Block, LogLevel,
};

use crate::dialstring::{dial_string_of, print_dial_string};

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

fn write_uuid(out: &mut String, uuid: &str) {
    let (r, g, b) = uuid_truecolor(uuid);
    write!(out, "\x1b[38;2;{r};{g};{b}m{uuid}{RESET}").expect("writing to a String cannot fail");
}

/// Paint UUIDs embedded in `text` with the same per-UUID color the UUID column
/// uses, so a peer leg named mid-message is recognizable at a glance. `resume`
/// restores the caller's color after each match.
fn colorize_uuids<'a>(text: &'a str, resume: &str) -> Cow<'a, str> {
    let mut hits = find_uuids(text).peekable();
    if hits.peek().is_none() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 64);
    let mut last = 0;
    for (start, uuid) in hits {
        out.push_str(&text[last..start]);
        write_uuid(&mut out, uuid);
        out.push_str(resume);
        last = start + uuid.len();
    }
    out.push_str(&text[last..]);
    Cow::Owned(out)
}

/// Paint a dialplan condition's verdict, the one thing worth spotting in a wall
/// of `Regex (PASS|FAIL)` continuation lines.
fn colorize_pass_fail<'a>(text: &'a str, resume: &str) -> Cow<'a, str> {
    if !text.contains("(PASS)") && !text.contains("(FAIL)") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 32);
    let mut rest = text;
    while let Some((idx, verdict, color)) = rest
        .find("(PASS)")
        .map(|i| (i, "(PASS)", BRIGHT_GREEN))
        .into_iter()
        .chain(rest.find("(FAIL)").map(|i| (i, "(FAIL)", RED)))
        .min_by_key(|(i, _, _)| *i)
    {
        out.push_str(&rest[..idx]);
        out.push_str(color);
        out.push_str(verdict);
        out.push_str(RESET);
        out.push_str(resume);
        rest = &rest[idx + verdict.len()..];
    }
    out.push_str(rest);
    Cow::Owned(out)
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
            let mut s = String::new();
            write_uuid(&mut s, &entry.uuid);
            s
        } else {
            entry.uuid.clone()
        };

        let msg = if use_color {
            colorize_uuids(&entry.message, lc)
        } else {
            Cow::Borrowed(entry.message.as_str())
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
        )?;

        if self.show_blocks {
            if let Some(block) = &entry.block {
                self.print_block(w, block, use_color)?;
            }
            if let Some(args) = dial_string_of(&entry.message_kind) {
                let (lbl, val) = if use_color { (CYAN, DIM) } else { ("", "") };
                print_dial_string(w, args, lbl, val, reset)?;
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
            // Continuation lines the parser did not fold into a typed block are
            // the entry's only content — dialplan regex verdicts, EXECUTE traces.
            // Collapsing those to a count leaves nothing readable behind.
            let inline = (self.show_blocks && entry.block.is_none()) || entry.attached.len() == 1;
            if inline {
                for line in &entry.attached {
                    let rendered = if use_color {
                        // Chained through Cow so a line neither pass touches —
                        // the common case — is never copied.
                        match colorize_uuids(line, dim_s) {
                            Cow::Borrowed(s) => colorize_pass_fail(s, dim_s),
                            Cow::Owned(s) => match colorize_pass_fail(&s, dim_s) {
                                Cow::Borrowed(_) => Cow::Owned(s),
                                Cow::Owned(both) => Cow::Owned(both),
                            },
                        }
                    } else {
                        Cow::Borrowed(line)
                    };
                    writeln!(w, "{dim_s}         {rendered}{reset}")?;
                }
            } else {
                writeln!(
                    w,
                    "{dim_s}         ({} attached lines){reset}",
                    entry.attached.len()
                )?;
            }
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
                    writeln!(w, "{bc}         var    {name}: {value}{reset}")?;
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
                    .map(|d| format!(" | {}", truncate_at_char_boundary(d, 100)))
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}

/// Build a case-insensitive multi-needle matcher. One automaton scans a haystack
/// once for every needle, so a `--related` pass carrying hundreds of discovered
/// leg UUIDs costs the same per entry as a single `-u`.
fn build_matcher(needles: &[String]) -> io::Result<Option<AhoCorasick>> {
    if needles.is_empty() {
        return Ok(None);
    }
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(needles)
        .map(Some)
        .map_err(|e| {
            io::Error::other(format!(
                "cannot build a matcher for {} pattern(s): {e}",
                needles.len()
            ))
        })
}

/// Construction parameters for [`FilterConfig::new`]. `Default` lets call sites
/// name only the fields they set, rather than pass nine positionals where two
/// transposed `Option<String>`s would compile and silently invert a date range.
#[derive(Default)]
pub struct FilterParams {
    pub uuid: Vec<String>,
    pub uuid_strict: bool,
    pub match_blocks: bool,
    pub min_level: Option<LogLevel>,
    pub category: Vec<String>,
    pub fgrep: Option<String>,
    pub grep: Option<regex::Regex>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

#[derive(Clone, Default)]
pub struct FilterConfig {
    uuid_ac: Option<AhoCorasick>,
    /// Restrict UUID matching to `entry.uuid` (output pass) vs. also scanning
    /// message and attached lines (discovery pass).
    pub uuid_strict: bool,
    /// Extend fgrep/grep matching into attached/block lines, not just the message.
    pub match_blocks: bool,
    pub min_level: Option<LogLevel>,
    /// Message-kind labels; an entry matches if it carries any of them.
    pub category: Vec<String>,
    fgrep_ac: Option<AhoCorasick>,
    pub grep: Option<regex::Regex>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

impl FilterConfig {
    pub fn new(p: FilterParams) -> io::Result<Self> {
        Ok(FilterConfig {
            uuid_ac: build_matcher(&p.uuid)?,
            uuid_strict: p.uuid_strict,
            match_blocks: p.match_blocks,
            min_level: p.min_level,
            category: p.category,
            fgrep_ac: build_matcher(p.fgrep.as_slice())?,
            grep: p.grep,
            from_ts: p.from_ts,
            until_ts: p.until_ts,
        })
    }

    pub fn set_uuids(&mut self, needles: &[String]) -> io::Result<()> {
        self.uuid_ac = build_matcher(needles)?;
        Ok(())
    }

    pub fn set_fgrep(&mut self, needle: &str) -> io::Result<()> {
        self.fgrep_ac = build_matcher(std::slice::from_ref(&needle.to_string()))?;
        Ok(())
    }

    /// A copy suited to peer-UUID discovery: category cleared (the seed term may
    /// surface under any message kind), UUID matching loosened to message bodies
    /// and attached lines so the seed is found wherever it appears.
    pub fn for_discovery(&self) -> FilterConfig {
        FilterConfig {
            uuid_strict: false,
            match_blocks: true,
            category: Vec::new(),
            ..self.clone()
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

        if let Some(ref ac) = self.uuid_ac {
            let hit = ac.is_match(entry.uuid.as_bytes())
                || (!self.uuid_strict
                    && (ac.is_match(entry.message.as_bytes())
                        || entry.attached.iter().any(|l| ac.is_match(l.as_bytes()))));
            if !hit {
                return false;
            }
        }

        if !self.category.is_empty()
            && !self
                .category
                .iter()
                .any(|c| entry.message_kind.label() == c.as_str())
        {
            return false;
        }

        if let Some(ref ac) = self.fgrep_ac {
            let hit = ac.is_match(entry.message.as_bytes())
                || (self.match_blocks && entry.attached.iter().any(|l| ac.is_match(l.as_bytes())));
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
pub mod tests {
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

    const PEER: &str = "11111111-2222-3333-4444-555555555555";

    fn printer(color: ColorMode, show_blocks: bool) -> EntryPrinter {
        EntryPrinter {
            color,
            show_blocks,
            show_session: false,
            show_filename: false,
            show_line_numbers: false,
        }
    }

    fn render(printer: &EntryPrinter, entry: &LogEntry) -> String {
        let mut out: Vec<u8> = Vec::new();
        printer.print_entry(&mut out, entry, None, None).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn attached_lines_inline_under_blocks() {
        let e = entry(
            "u",
            "Dialplan: parsing",
            &["Regex (PASS) x =~ /y/", "Action set"],
        );
        let out = render(&printer(ColorMode::Never, true), &e);
        assert!(out.contains("Regex (PASS) x =~ /y/"), "{out}");
        assert!(out.contains("Action set"), "{out}");
        assert!(!out.contains("attached lines"), "{out}");
    }

    #[test]
    fn attached_lines_collapse_without_blocks() {
        let e = entry("u", "Dialplan: parsing", &["one", "two"]);
        let out = render(&printer(ColorMode::Never, false), &e);
        assert!(out.contains("(2 attached lines)"), "{out}");
    }

    #[test]
    fn lone_attached_line_always_inline() {
        let e = entry("u", "msg", &["the only continuation"]);
        let out = render(&printer(ColorMode::Never, false), &e);
        assert!(out.contains("the only continuation"), "{out}");
    }

    #[test]
    fn typed_block_keeps_attached_lines_collapsed() {
        // The block already renders this content; printing both duplicates it.
        let mut e = entry(
            "u",
            "CHANNEL_DATA:",
            &["Channel-Name: [x]", "variable_a: [b]"],
        );
        e.block = Some(Block::ChannelData {
            fields: Vec::new(),
            variables: Vec::new(),
        });
        let out = render(&printer(ColorMode::Never, true), &e);
        assert!(out.contains("(2 attached lines)"), "{out}");
    }

    #[test]
    fn embedded_uuid_gets_its_own_color() {
        let e = entry("aaaa", &format!("Peer UUID: {PEER}"), &[]);
        let out = render(&printer(ColorMode::Always, false), &e);
        let (r, g, b) = uuid_truecolor(PEER);
        assert!(
            out.contains(&format!("\x1b[38;2;{r};{g};{b}m{PEER}")),
            "{out}"
        );
    }

    #[test]
    fn embedded_uuid_left_alone_without_color() {
        let e = entry("aaaa", &format!("Peer UUID: {PEER}"), &[]);
        let out = render(&printer(ColorMode::Never, false), &e);
        assert!(out.contains(&format!("Peer UUID: {PEER}")), "{out}");
        assert!(!out.contains("\x1b["), "{out}");
    }

    #[test]
    fn pass_and_fail_are_colored_in_attached_lines() {
        let e = entry(
            "u",
            "Dialplan: parsing",
            &["Regex (PASS) a", "Regex (FAIL) b"],
        );
        let out = render(&printer(ColorMode::Always, true), &e);
        assert!(
            out.contains(&format!("{BRIGHT_GREEN}(PASS){RESET}")),
            "{out}"
        );
        assert!(out.contains(&format!("{RED}(FAIL){RESET}")), "{out}");
    }

    #[test]
    fn long_variable_values_are_not_truncated() {
        let long = "x".repeat(500);
        let mut e = entry("u", "CHANNEL_DATA:", &[]);
        e.block = Some(Block::ChannelData {
            fields: Vec::new(),
            variables: vec![("variable_sip_multipart".to_string(), long.clone())],
        });
        let out = render(&printer(ColorMode::Never, true), &e);
        assert!(out.contains(&long), "{out}");
        assert!(!out.contains("..."), "{out}");
    }

    pub fn filter(p: FilterParams) -> FilterConfig {
        FilterConfig::new(FilterParams {
            uuid_strict: true,
            ..p
        })
        .unwrap()
    }

    #[test]
    fn uuid_or_matches_any_needle() {
        let f = filter(FilterParams {
            uuid: vec!["aaaa".into(), "bbbb".into()],
            ..Default::default()
        });
        assert!(f.matches(&entry("xx-bbbb-yy", "msg", &[])));
        assert!(f.matches(&entry("aaaa-0000", "msg", &[])));
        assert!(!f.matches(&entry("cccc-0000", "msg", &[])));
    }

    #[test]
    fn uuid_match_is_case_insensitive() {
        let f = filter(FilterParams {
            uuid: vec!["AAAABBBB".into()],
            ..Default::default()
        });
        assert!(f.matches(&entry("aaaabbbb-2222-3333-4444-555555555555", "msg", &[])));
    }

    #[test]
    fn uuid_strict_ignores_message_body() {
        let mut f = filter(FilterParams {
            uuid: vec!["dead".into()],
            ..Default::default()
        });
        // strict: only the uuid field counts, not the message text
        assert!(!f.matches(&entry("0000", "peer dead leg", &[])));
        f.uuid_strict = false;
        assert!(f.matches(&entry("0000", "peer dead leg", &[])));
    }

    #[test]
    fn fgrep_into_blocks_only_with_match_blocks() {
        let mut f = filter(FilterParams {
            fgrep: Some("m=audio".into()),
            ..Default::default()
        });
        let e = entry("u", "Remote SDP:", &["v=0", "m=audio 5004 RTP/AVP 0"]);
        assert!(!f.matches(&e));
        f.match_blocks = true;
        assert!(f.matches(&e));
    }

    #[test]
    fn fgrep_is_case_insensitive() {
        let f = filter(FilterParams {
            fgrep: Some("RECEIVING INVITE".into()),
            ..Default::default()
        });
        assert!(f.matches(&entry("u", "receiving invite from 192.0.2.1", &[])));
    }

    #[test]
    fn category_matches_any_of_several() {
        let f = filter(FilterParams {
            category: vec!["execute".into(), "dialplan".into()],
            ..Default::default()
        });
        let mut e = entry("u", "msg", &[]);
        e.message_kind = MessageKind::Dialplan {
            channel: "sofia/internal/1001".to_string(),
            detail: "parsing".to_string(),
        };
        assert!(f.matches(&e));
        e.message_kind = MessageKind::General;
        assert!(!f.matches(&e));
    }

    #[test]
    fn for_discovery_clears_category_and_loosens() {
        let f = filter(FilterParams {
            category: vec!["execute".into()],
            uuid: vec!["seed".into()],
            ..Default::default()
        });
        let d = f.for_discovery();
        assert!(d.category.is_empty());
        assert!(!d.uuid_strict);
        assert!(d.match_blocks);
        // seed found in message body survives discovery despite category mismatch
        assert!(d.matches(&entry("0000", "found seed here", &[])));
    }
}
