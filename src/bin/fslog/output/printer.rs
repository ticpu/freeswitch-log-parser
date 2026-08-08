//! Rendering one entry — header columns, typed blocks, session state and
//! attached lines.

use std::borrow::Cow;
use std::io::{self, Write};

use freeswitch_log_parser::{truncate_at_char_boundary, Block, MessageKind};

use crate::dialstring::{dial_string_of, print_dial_string};

use super::color::*;
use super::ColorMode;

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

        // Markers carry no time, level or UUID, so the entry columns would all be
        // empty. A rule reads as what it is: a break between files or days.
        if matches!(
            entry.message_kind,
            MessageKind::FileChange | MessageKind::DateChange
        ) {
            return writeln!(w, "{dim}── {}{reset}", entry.message);
        }

        let uuid = match &entry.uuid {
            None => format!("{dim}-{reset}"),
            Some(u) if use_color => {
                let mut s = String::new();
                write_uuid(&mut s, u);
                s
            }
            Some(u) => u.clone(),
        };

        // Continuation lines print inline only when nothing else carries the
        // entry's content; a typed block or a bare count already does.
        let inline = !entry.attached.is_empty()
            && ((self.show_blocks && entry.block.is_none()) || entry.attached.len() == 1);

        // With a body to head, the channel goes on the header alone and its data
        // joins the body — otherwise the header would be the one line carrying
        // both, and the block would not read as a column.
        let (head, head_data) = match inline
            .then(|| split_dialplan_line(&entry.message))
            .flatten()
        {
            Some((channel, data)) => (channel, Some(data)),
            None => (entry.message.as_str(), None),
        };

        let msg = if use_color {
            colorize_uuids(head, lc)
        } else {
            Cow::Borrowed(head)
        };

        if let Some(fname) = filename.filter(|_| self.show_filename) {
            write!(w, "{dim}{fname}{reset} ")?;
        }

        if self.show_line_numbers {
            write!(w, "{lc}L{line:>6} ", line = entry.line_number)?;
        }

        // Time and level share the level color: a run of one severity reads as a
        // single band down the left edge. The line kind is Layer 1's business —
        // `[{mkind}]` is what a reader of a call actually wants there.
        writeln!(
            w,
            "{lc}{time:>15} {level:>7}{reset} {uuid} {lc}[{mkind}]{reset} {lc}{msg}{reset}",
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
            if inline {
                for line in head_data.into_iter().chain(&entry.attached) {
                    let line = strip_repeated_prefix(line, entry.uuid.as_deref().unwrap_or(""));
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
            } else if !(self.show_blocks && entry.block.is_some()) {
                // A block already printed above is these same lines, parsed —
                // counting them again says nothing the reader cannot see.
                writeln!(
                    w,
                    "{dim_s}         ({} attached lines){reset}",
                    entry.attached.len()
                )?;
            }
        }

        Ok(())
    }

    /// The codec list, then the streams held or carrying no payload type.
    #[cfg(feature = "sdp")]
    fn sdp_summary_lines(block: &Block) -> Vec<String> {
        use freeswitch_types::sdp::SdpCodecEntry;

        let Some(Ok(codecs)) = block.sdp_codecs() else {
            return Vec::new();
        };
        let mut parts: Vec<String> = codecs
            .entries()
            .map(|e| match e {
                SdpCodecEntry::Rtp(c) => {
                    let mut s = format!("{}/{}", c.name(), c.clock_rate());
                    if let Some(ch) = c.channels() {
                        if ch > 1 {
                            s.push_str(&format!("/{ch}"));
                        }
                    }
                    s
                }
                _ => "T.38".to_string(),
            })
            .collect();
        for payload in codecs.non_codec_payloads() {
            parts.push(payload.to_string());
        }
        for u in codecs.unmapped() {
            parts.push(format!("pt{}?", u.payload_type));
        }

        // A port-0 section keeps its codecs but reaches no codec string, so it is
        // absent from the list above; naming it is how a held stream stays visible.
        let quiet: Vec<String> = codecs
            .sections()
            .iter()
            .filter_map(|s| {
                if s.port() == 0 {
                    Some(format!("held m={} port 0", s.media_type()))
                } else if s.entries().is_empty() && s.unmapped().is_empty() {
                    Some(format!("skipped m={}/{}", s.media_type(), s.proto()))
                } else {
                    None
                }
            })
            .collect();

        let mut lines = Vec::new();
        if !parts.is_empty() {
            lines.push(parts.join(", "));
        }
        if !quiet.is_empty() {
            lines.push(quiet.join(", "));
        }
        lines
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
                #[cfg(feature = "sdp")]
                for summary in Self::sdp_summary_lines(block) {
                    writeln!(w, "{sc}         sdp    {summary}{reset}")?;
                }
                for line in body {
                    writeln!(w, "{sc}         sdp    {line}{reset}")?;
                }
            }
            Block::CodecNegotiation {
                media,
                comparisons,
                matched,
                near_matched,
            } => {
                let cc = if use_color { DIM_YELLOW } else { "" };
                writeln!(
                    w,
                    "{cc}         codec  {media}: {} comparisons, {} matched, {} near{reset}",
                    comparisons.len(),
                    matched.len(),
                    near_matched.len(),
                )?;
                for (offered, local) in comparisons {
                    writeln!(w, "{cc}         codec  {offered}  vs  {local}{reset}")?;
                }
                for c in matched {
                    writeln!(w, "{cc}         codec  MATCH {c}{reset}")?;
                }
                for c in near_matched {
                    writeln!(w, "{cc}         codec  NEAR  {c}{reset}")?;
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
        if let Some(conf) = &session.conference {
            parts.push(format!("conf={}", conf.name));
            if let Some(id) = conf.member_id {
                parts.push(format!("member={id}"));
            }
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

    /// Field-span coverage of the matched entries — which typed values the
    /// parser located, and where.
    pub fn print_field_stats(
        &self,
        w: &mut dyn Write,
        fields: &crate::context::FieldCounts,
        matched: u64,
    ) -> io::Result<()> {
        let total = fields.total();
        if total == 0 {
            return Ok(());
        }
        writeln!(w)?;
        writeln!(
            w,
            "{total} field spans in {}/{matched} entries (message {}, attached {})",
            fields.entries_with_fields, fields.in_message, fields.in_attached,
        )?;
        for (kind, count) in fields.by_kind() {
            writeln!(w, "  {kind:<20} {count}")?;
        }
        Ok(())
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
