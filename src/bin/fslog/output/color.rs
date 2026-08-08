//! ANSI colouring — the palette, the per-UUID hue, and the in-line
//! highlighting of UUIDs and dialplan verdicts.

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};

use freeswitch_log_parser::{find_uuids, LogLevel};

pub(super) const RESET: &str = "\x1b[0m";
pub(super) const RED: &str = "\x1b[31m";
pub(super) const GREEN: &str = "\x1b[32m";
pub(super) const YELLOW: &str = "\x1b[33m";
pub(super) const MAGENTA: &str = "\x1b[35m";
pub(super) const CYAN: &str = "\x1b[36m";
pub(super) const DIM: &str = "\x1b[2m";
pub(super) const DIM_YELLOW: &str = "\x1b[33;2m";
pub(super) const DIM_GREEN: &str = "\x1b[32;2m";
pub(super) const BRIGHT_GREEN: &str = "\x1b[92m";

pub(super) fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
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
pub(super) fn uuid_truecolor(uuid: &str) -> (u8, u8, u8) {
    let mut hasher = DefaultHasher::new();
    uuid.hash(&mut hasher);
    let hue = (hasher.finish() % 360) as f64;
    hsl_to_rgb(hue, 0.30, 0.82)
}

/// Split `Dialplan: <channel> <data>` into the part every line of the block
/// repeats and the part that differs. The channel never contains a space, so the
/// one after it ends the prefix.
pub(super) fn split_dialplan_line(msg: &str) -> Option<(&str, &str)> {
    let tag = ["Dialplan: ", "Chatplan: "]
        .into_iter()
        .find(|t| msg.starts_with(t))?;
    let (_channel, data) = msg[tag.len()..].split_once(' ')?;
    Some((&msg[..msg.len() - data.len() - 1], data))
}

/// Drop what a continuation line repeats from the entry that owns it: its own
/// UUID, and the `Dialplan:`/`Chatplan:` channel the header already names. Every
/// line of a dialplan block carries both, which buries the verdict past column 90
/// where nothing lines up.
pub(super) fn strip_repeated_prefix<'a>(line: &'a str, uuid: &str) -> &'a str {
    let rest = line
        .strip_prefix(uuid)
        .and_then(|r| r.strip_prefix(' '))
        .unwrap_or(line);
    split_dialplan_line(rest).map_or(rest, |(_, data)| data)
}

pub(super) fn write_uuid(out: &mut String, uuid: &str) {
    let (r, g, b) = uuid_truecolor(uuid);
    write!(out, "\x1b[38;2;{r};{g};{b}m{uuid}{RESET}").expect("writing to a String cannot fail");
}

/// Paint UUIDs embedded in `text` with the same per-UUID color the UUID column
/// uses, so a peer leg named mid-message is recognizable at a glance. `resume`
/// restores the caller's color after each match.
pub(super) fn colorize_uuids<'a>(text: &'a str, resume: &str) -> Cow<'a, str> {
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
pub(super) fn colorize_pass_fail<'a>(text: &'a str, resume: &str) -> Cow<'a, str> {
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

pub(super) fn level_color(level: Option<LogLevel>) -> &'static str {
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
