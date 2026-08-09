//! Positional slicers shared by classification and the field-span API — each
//! returns borrowed subslices of the message so spans stay addressable.

/// The subslices an `EXECUTE`/`Execute` line decomposes into. `channel` is
/// empty for the lowercase shape, which carries none.
pub(crate) struct ExecuteParts<'a> {
    pub(crate) depth: u32,
    pub(crate) channel: &'a str,
    pub(crate) application: &'a str,
    pub(crate) arguments: &'a str,
}

pub(crate) fn execute_parts(msg: &str) -> ExecuteParts<'_> {
    let rest = &msg["EXECUTE ".len()..];

    let depth = if rest.starts_with("[depth=") {
        let end = rest.find(']').unwrap_or(0);
        if end > 7 {
            rest[7..end].parse::<u32>().unwrap_or(0)
        } else {
            0
        }
    } else {
        return ExecuteParts {
            depth: 0,
            channel: "",
            application: "",
            arguments: rest,
        };
    };

    let after_bracket = rest.find("] ").map(|p| &rest[p + 2..]).unwrap_or("");

    // Lowercase "Execute [depth=N] app(args)" has no channel.
    // Uppercase "EXECUTE [depth=N] channel app(args)" has channel before app.
    // Detect by checking if first token contains '(' (app) or '/' (channel path).
    let (channel, app_part) = match after_bracket.find(' ') {
        Some(p) => {
            let first_token = &after_bracket[..p];
            if first_token.contains('/') {
                (first_token, &after_bracket[p + 1..])
            } else {
                ("", after_bracket)
            }
        }
        None => ("", after_bracket),
    };

    let (application, arguments) = match app_part.find('(') {
        Some(p) => {
            let app = &app_part[..p];
            let args = if app_part.ends_with(')') {
                &app_part[p + 1..app_part.len() - 1]
            } else {
                &app_part[p + 1..]
            };
            (app, args)
        }
        None => (app_part, ""),
    };

    ExecuteParts {
        depth,
        channel,
        application,
        arguments,
    }
}
/// `(channel, detail)` of a `Dialplan:`/`Chatplan:` line.
pub(crate) fn dialplan_parts(msg: &str) -> (&str, &str) {
    let prefix_len = if msg.starts_with("Chatplan: ") {
        "Chatplan: ".len()
    } else {
        "Dialplan: ".len()
    };
    let rest = &msg[prefix_len..];
    match rest.find(' ') {
        Some(p) => (&rest[..p], &rest[p + 1..]),
        None => (rest, ""),
    }
}
/// The parts of a dialplan `Regex` condition trace, from [`regex_condition_parts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegexCondition<'a> {
    /// The condition's raw `field` attribute, as the dialplan spelled it.
    pub field: &'a str,
    /// The expanded value the condition was tested against.
    pub value: &'a str,
}

/// The parts of a `Regex (PASS|FAIL) [exten] field(value) =~ /expr/ tail`
/// trace — [`MessageKind::Dialplan`](crate::MessageKind::Dialplan)'s `detail`
/// payload; `None` on any other text.
///
/// The field is the dialplan's raw attribute, so it may be a `${…}` API call
/// carrying parentheses of its own: the value's opening paren is matched from
/// the right, never taken as the first one in the head.
pub fn regex_condition_parts(detail: &str) -> Option<RegexCondition<'_>> {
    let after_exten = detail.strip_prefix("Regex (")?.split_once(") [")?.1;
    let head = &after_exten[after_exten.find("] ")? + 2..];
    // A value can carry the separator; an expression realistically cannot.
    let head = &head[..head.rfind(" =~ /")?];
    let close = head.strip_suffix(')')?.len();

    let bytes = head.as_bytes();
    let mut depth = 1u32;
    let mut i = close;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(RegexCondition {
                        field: &head[..i],
                        value: &head[i + 1..close],
                    });
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn parse_bracketed_value(s: &str, prefix_len: usize) -> Option<(&str, &str)> {
    let after_prefix = &s[prefix_len..];
    let colon = after_prefix.find(": ")?;
    let name = &after_prefix[..colon];
    let value_part = &after_prefix[colon + 2..];
    if let Some(inner) = value_part.strip_prefix('[') {
        if let Some(stripped) = inner.strip_suffix(']') {
            Some((name, stripped))
        } else {
            Some((name, inner))
        }
    } else {
        Some((name, value_part))
    }
}
/// The channel token of a `(channel) State ...` line, parentheses excluded.
pub(crate) fn paren_channel(msg: &str) -> Option<&str> {
    let inner = msg.strip_prefix('(')?;
    let close = inner.find(')')?;
    Some(&inner[..close]).filter(|c| !c.is_empty())
}

/// The channel token of a `Hangup <channel> [state] [cause]` line.
pub(crate) fn hangup_channel(msg: &str) -> Option<&str> {
    let rest = msg.strip_prefix("Hangup ")?;
    let bracket = rest.find(" [")?;
    Some(&rest[..bracket]).filter(|c| !c.is_empty())
}

/// The channel token of a `New Channel <channel> [uuid]` line.
pub(crate) fn new_channel_name(msg: &str) -> Option<&str> {
    let rest = msg.strip_prefix("New Channel ")?;
    let bracket = rest.rfind(" [")?;
    Some(&rest[..bracket]).filter(|c| !c.is_empty())
}

pub(crate) fn strip_channel_prefix(msg: &str) -> Option<(&str, &str)> {
    if !msg.starts_with("sofia/") && !msg.starts_with("loopback/") {
        return None;
    }
    let bytes = msg.as_bytes();
    let mut i = 0;
    let mut bracket_depth: u32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => bracket_depth += 1,
            b']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
            }
            b' ' if bracket_depth == 0 => {
                return Some((&msg[..i], &msg[i + 1..]));
            }
            _ => {}
        }
        i += 1;
    }
    None
}
/// The subslices a `SET`/`EXPORT` line decomposes into. `channel` is `None` for
/// `EXPORT`, which names no channel.
pub(crate) struct SetExportParts<'a> {
    pub(crate) channel: Option<&'a str>,
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
}

/// The offset of the `]` closing a value that opened at `from`, matching nested
/// brackets so a value containing one is not cut at it.
fn value_close(msg: &str, from: usize) -> Option<usize> {
    let mut depth = 1u32;
    for (i, b) in msg.as_bytes().iter().enumerate().skip(from) {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn set_export_parts(msg: &str) -> Option<SetExportParts<'_>> {
    // SET|PUSH|UNSHIFT channel [name]=[value]
    // EXPORT (export_vars) [(REMOTE ONLY) ][name]=[value]
    // channel EXPORTING[export_vars] [name]=[value] to event|channel
    // channel setting variable [name]=[value]
    // Find "]=[" which uniquely identifies the [name]=[value] boundary
    let sep_pos = msg.find("]=[")?;
    let name_start = msg[..sep_pos].rfind('[')?;
    let name = &msg[name_start + 1..sep_pos];
    let val_start = sep_pos + 3; // skip "]=["
    let val_end = value_close(msg, val_start).unwrap_or(msg.len());
    let value = &msg[val_start..val_end];

    // Only verb-first shapes name a channel, and not always: `SET GLOBAL` is a
    // scope and `SET [n]=[v]` has no token at all — an endpoint path qualifies.
    let channel = msg
        .strip_prefix("SET ")
        .or_else(|| msg.strip_prefix("PUSH "))
        .or_else(|| msg.strip_prefix("UNSHIFT "))
        .and_then(|rest| {
            let end = rest.find(' ').unwrap_or(rest.len());
            Some(&rest[..end]).filter(|c| c.contains('/') && !c.starts_with('['))
        });

    Some(SetExportParts {
        channel,
        name,
        value,
    })
}
