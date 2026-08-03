//! Expansion of the dial string an application was executed with.
//!
//! A production `bridge()` argument is one unbroken line carrying a global
//! variable block, per-leg variable blocks and several endpoints, which is
//! unreadable as logged. Expanding it is opt-in via `--blocks` because the
//! expansion is several times longer than the line it explains.

use std::io::{self, Write};
use std::str::FromStr;

use freeswitch_log_parser::MessageKind;
use freeswitch_types::commands::endpoint::DialString;
use freeswitch_types::{BridgeDialString, EslArray};

/// The dial-string argument of an EXECUTE trace, when the application takes one.
///
/// `bridge` and `att_xfer` are the applications FreeSWITCH ships whose argument
/// is a channel URL. `originate` is deliberately absent: it is an API command,
/// not an application, so it never appears in an EXECUTE trace.
pub fn dial_string_of(kind: &MessageKind) -> Option<&str> {
    match kind {
        MessageKind::Execute {
            application,
            arguments,
            ..
        } if matches!(application.as_str(), "bridge" | "att_xfer") => Some(arguments),
        _ => None,
    }
}

/// Write the expansion of `arguments`. Silently writes nothing when the argument
/// list does not parse as a dial string — the entry's own message still carries
/// the raw text, so there is nothing to warn about.
pub fn print_dial_string(
    w: &mut dyn Write,
    arguments: &str,
    label_color: &str,
    value_color: &str,
    reset: &str,
) -> io::Result<()> {
    let Ok(dial) = BridgeDialString::from_str(arguments) else {
        return Ok(());
    };

    if let Some(vars) = dial.variables() {
        for (key, value) in vars.iter() {
            print_variable(w, key, value, label_color, value_color, reset)?;
        }
    }

    let groups = dial.groups();
    let total: usize = groups.iter().map(|g| g.len()).sum();
    for (i, group) in groups.iter().enumerate() {
        // `|` separates failover attempts, `,` endpoints that ring together, so
        // the header has to say which of the two the following lines are.
        let simultaneous = |n: usize| match n {
            1 => String::new(),
            n => format!(" ({n} simultaneous)"),
        };
        let header = if groups.len() > 1 {
            format!(
                "failover {} of {}{}",
                i + 1,
                groups.len(),
                simultaneous(group.len())
            )
        } else if total > 1 {
            format!("endpoints{}", simultaneous(total))
        } else {
            "endpoint".to_string()
        };
        writeln!(w, "{label_color}         dial   {header}{reset}")?;
        for ep in group {
            let ext = ep
                .variables()
                .and_then(|v| v.get("presence_id"))
                .map(|id| format!("ext={} ", id.split('@').next().unwrap_or(id)))
                .unwrap_or_default();
            writeln!(w, "{value_color}         dial     {ext}{ep}{reset}")?;
        }
    }

    Ok(())
}

fn print_variable(
    w: &mut dyn Write,
    key: &str,
    value: &str,
    label_color: &str,
    value_color: &str,
    reset: &str,
) -> io::Result<()> {
    // ARRAY:: is how FreeSWITCH packs a repeated header or multi-valued variable
    // into one string; rendering it raw hides how many values are really there.
    match EslArray::parse(value) {
        Ok(arr) if arr.len() > 1 => {
            writeln!(
                w,
                "{label_color}         dial   {key}: ({} entries){reset}",
                arr.len()
            )?;
            for item in arr.items() {
                writeln!(w, "{value_color}         dial     {item}{reset}")?;
            }
        }
        _ => writeln!(
            w,
            "{label_color}         dial   {key}: {value_color}{value}{reset}"
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(arguments: &str) -> String {
        let mut out: Vec<u8> = Vec::new();
        print_dial_string(&mut out, arguments, "", "", "").unwrap();
        String::from_utf8(out).unwrap()
    }

    fn execute(application: &str, arguments: &str) -> MessageKind {
        MessageKind::Execute {
            depth: 0,
            channel: "sofia/internal/1001".to_string(),
            application: application.to_string(),
            arguments: arguments.to_string(),
        }
    }

    #[test]
    fn only_dial_string_applications_expand() {
        assert!(dial_string_of(&execute("bridge", "sofia/gw/1")).is_some());
        assert!(dial_string_of(&execute("att_xfer", "sofia/gw/1")).is_some());
        // Not an application — an API command, so it never reaches an EXECUTE trace.
        assert!(dial_string_of(&execute("originate", "sofia/gw/1")).is_none());
        assert!(dial_string_of(&execute("set", "a=b")).is_none());
        assert!(dial_string_of(&MessageKind::General).is_none());
    }

    #[test]
    fn global_variables_and_single_endpoint() {
        let out = render("{ignore_early_media=true}sofia/gateway/gw/5551234");
        assert!(out.contains("dial   ignore_early_media: true"), "{out}");
        assert!(out.contains("dial   endpoint\n"), "{out}");
        assert!(out.contains("sofia/gateway/gw/5551234"), "{out}");
    }

    #[test]
    fn simultaneous_endpoints_counted() {
        let out =
            render("sofia/internal/1001@pbx.example.test,sofia/internal/1002@pbx.example.test");
        assert!(out.contains("dial   endpoints (2 simultaneous)"), "{out}");
        assert!(
            out.contains("sofia/internal/1001@pbx.example.test"),
            "{out}"
        );
        assert!(
            out.contains("sofia/internal/1002@pbx.example.test"),
            "{out}"
        );
    }

    #[test]
    fn failover_groups_are_numbered() {
        let out = render("sofia/gateway/primary/5551234|sofia/gateway/backup/5551234");
        assert!(out.contains("dial   failover 1 of 2\n"), "{out}");
        assert!(out.contains("dial   failover 2 of 2\n"), "{out}");
    }

    #[test]
    fn simultaneous_endpoints_inside_a_failover_group() {
        let out = render("sofia/gw/a/1,sofia/gw/b/1|sofia/gw/c/1");
        assert!(
            out.contains("dial   failover 1 of 2 (2 simultaneous)"),
            "{out}"
        );
        assert!(out.contains("dial   failover 2 of 2\n"), "{out}");
    }

    #[test]
    fn presence_id_becomes_an_extension_hint() {
        let out = render("[presence_id=1001@pbx.example.test]sofia/internal/1001@pbx.example.test");
        assert!(out.contains("ext=1001 "), "{out}");
    }

    #[test]
    fn array_values_expand_to_one_line_each() {
        let out = render(
            "{sip_h_X-Tag=ARRAY::<urn:example:one>;purpose=first\
             |:<urn:example:two>;purpose=second}sofia/gateway/gw/5551234",
        );
        assert!(out.contains("sip_h_X-Tag: (2 entries)"), "{out}");
        assert!(out.contains("<urn:example:one>;purpose=first"), "{out}");
        assert!(out.contains("<urn:example:two>;purpose=second"), "{out}");
    }

    #[test]
    fn unparseable_arguments_render_nothing() {
        assert_eq!(render(""), "");
    }
}
