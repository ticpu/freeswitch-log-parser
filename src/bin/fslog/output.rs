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
        let uuid = if entry.uuid.is_empty() {
            "-"
        } else {
            &entry.uuid
        };
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

        if let Some(fname) = filename.filter(|_| self.show_filename) {
            write!(w, "{dim}{fname}{reset} ")?;
        }

        if self.show_line_numbers {
            write!(w, "{lc}L{line:>6} ", line = entry.line_number)?;
        }

        writeln!(
            w,
            "{lc}{kind:>9} {level:>7}{reset} {time} {dim}{uuid}{reset} {lc}[{mkind}]{reset} {lc}{msg}{reset}",
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

pub struct FilterConfig {
    pub uuid_filter: Option<String>,
    pub min_level: Option<LogLevel>,
    pub category: Option<String>,
    pub fgrep: Option<String>,
    pub grep: Option<regex::Regex>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

impl FilterConfig {
    pub fn matches(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        if let Some(min) = self.min_level {
            if let Some(level) = entry.level {
                if level < min {
                    return false;
                }
            }
        }

        if let Some(ref filter) = self.uuid_filter {
            if !entry.uuid.to_lowercase().contains(filter) {
                return false;
            }
        }

        if let Some(ref cat) = self.category {
            if entry.message_kind.label() != cat.as_str() {
                return false;
            }
        }

        if let Some(ref pattern) = self.fgrep {
            if !entry
                .message
                .to_lowercase()
                .contains(&pattern.to_lowercase())
            {
                return false;
            }
        }

        if let Some(ref re) = self.grep {
            if !re.is_match(&entry.message) {
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
