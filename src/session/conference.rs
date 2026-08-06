//! Conference membership tracking.
//!
//! `mod_conference` never logs a member id, so the only always-available signal
//! is the conference name, from the `conference` application's EXECUTE trace or
//! from a transfer into an inline `conference:` extension. Member id and
//! FreeSWITCH's own conference UUID reach the log only as channel variables.

use std::collections::{HashMap, HashSet};

use freeswitch_types::variables::ConferenceVariable;

use crate::message::MessageKind;
use crate::stream::LogEntry;

/// A session's membership in one conference.
///
/// `instance` distinguishes successive conferences that share a name; see
/// `docs/design-rationale.md`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceMembership {
    /// Conference name as dialed, e.g. `835`.
    pub name: String,
    /// Profile from `conference(name@profile)`; `None` when the argument omits
    /// it and FreeSWITCH applies its own default.
    pub profile: Option<String>,
    /// UUID of the first channel to join this conference instance.
    pub instance: String,
    /// From the `conference_member_id` channel variable; `None` until a dump
    /// or a variable line carries it.
    pub member_id: Option<u32>,
    /// FreeSWITCH's own conference UUID, from the `conference_uuid` channel
    /// variable; `None` until a dump or a variable line carries it.
    pub conference_uuid: Option<String>,
}

/// Conference a session is joining, as named by a log line.
pub(crate) struct ConferenceTarget {
    pub name: String,
    pub profile: Option<String>,
}

pub(crate) enum ConferenceEvent {
    Join(ConferenceTarget),
    Leave,
}

/// Live conferences, keyed by name. An instance exists only while it has
/// members, so the next join on a reused name opens a new one.
#[derive(Debug, Default)]
pub(crate) struct ConferenceRegistry {
    live: HashMap<String, Instance>,
}

#[derive(Debug)]
struct Instance {
    id: String,
    members: HashSet<String>,
}

impl ConferenceRegistry {
    pub(crate) fn instance_for(&self, name: &str) -> Option<&str> {
        self.live.get(name).map(|i| i.id.as_str())
    }

    pub(crate) fn join(&mut self, name: &str, instance: &str, uuid: &str) {
        self.live
            .entry(name.to_string())
            .or_insert_with(|| Instance {
                id: instance.to_string(),
                members: HashSet::new(),
            })
            .members
            .insert(uuid.to_string());
    }

    pub(crate) fn leave(&mut self, name: &str, uuid: &str) {
        if let Some(instance) = self.live.get_mut(name) {
            instance.members.remove(uuid);
            if instance.members.is_empty() {
                self.live.remove(name);
            }
        }
    }

    pub(crate) fn members<'a>(&'a self, instance: &'a str) -> impl Iterator<Item = &'a str> {
        self.live
            .values()
            .filter(move |i| i.id == instance)
            .flat_map(|i| i.members.iter().map(String::as_str))
    }
}

/// Conference join or leave named by this entry, if any.
pub(crate) fn detect(entry: &LogEntry) -> Option<ConferenceEvent> {
    if entry.message.starts_with("Channel leaving conference") {
        return Some(ConferenceEvent::Leave);
    }
    if let MessageKind::Execute {
        application,
        arguments,
        ..
    } = &entry.message_kind
    {
        if application == "conference" {
            return parse_target(arguments).map(ConferenceEvent::Join);
        }
    }
    parse_transfer(&entry.message).map(ConferenceEvent::Join)
}

/// `Transfer <chan> to <dialplan>[<extension>@<context>]` — the trailing
/// `@context` belongs to the transfer, not to the conference, so it is cut
/// before the extension is read as a conference argument.
fn parse_transfer(msg: &str) -> Option<ConferenceTarget> {
    if !msg.starts_with("Transfer ") {
        return None;
    }
    let start = msg.find("[conference:")? + "[conference:".len();
    let extension = msg[start..].strip_suffix(']')?;
    let extension = match extension.rfind('@') {
        Some(at) => &extension[..at],
        None => extension,
    };
    parse_target(extension)
}

/// Mirrors `mod_conference.c` `conference_function`: `+flags{…}` truncates the
/// argument, a `bridge:` prefix is followed by `name:dialstring`, the pin
/// starts at the first `+`, and the profile is what follows the *last* `@`.
fn parse_target(arguments: &str) -> Option<ConferenceTarget> {
    let mut spec = match arguments.find("+flags{") {
        Some(at) => &arguments[..at],
        None => arguments,
    };
    if let Some(rest) = spec.strip_prefix("bridge:") {
        spec = rest.split_once(':').map(|(name, _)| name)?;
    }
    let spec = spec.trim_start_matches(' ');
    let spec = match spec.split_once('+') {
        Some((name, _pin)) => name,
        None => spec,
    };
    let (name, profile) = match spec.rsplit_once('@') {
        Some((name, profile)) => (name, Some(profile.to_string())),
        None => (spec, None),
    };
    if name.is_empty() {
        return None;
    }
    Some(ConferenceTarget {
        name: name.to_string(),
        profile,
    })
}

/// A `conference_name` variable is a join signal in its own right: a recovered
/// or dumped channel can carry it with no EXECUTE trace anywhere in the log.
pub(crate) fn target_from_variables(vars: &HashMap<String, String>) -> Option<ConferenceTarget> {
    Some(ConferenceTarget {
        name: vars
            .get(ConferenceVariable::ConferenceName.as_str())?
            .clone(),
        profile: None,
    })
}

/// Fill in what only a channel dump can supply, leaving anything already known
/// in place when the variable is absent.
pub(crate) fn refresh(membership: &mut ConferenceMembership, vars: &HashMap<String, String>) {
    if let Some(member_id) = vars
        .get(ConferenceVariable::ConferenceMemberId.as_str())
        .and_then(|v| v.parse().ok())
    {
        membership.member_id = Some(member_id);
    }
    if let Some(uuid) = vars.get(ConferenceVariable::ConferenceUuid.as_str()) {
        membership.conference_uuid = Some(uuid.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(arguments: &str) -> (String, Option<String>) {
        let t = parse_target(arguments).expect("parsed");
        (t.name, t.profile)
    }

    #[test]
    fn bare_name() {
        assert_eq!(target("835"), ("835".to_string(), None));
    }

    #[test]
    fn name_with_profile() {
        assert_eq!(
            target("835@wideband"),
            ("835".to_string(), Some("wideband".to_string()))
        );
    }

    #[test]
    fn pin_is_not_part_of_the_name() {
        assert_eq!(target("835+1234"), ("835".to_string(), None));
        assert_eq!(
            target("835@wideband+1234"),
            ("835".to_string(), Some("wideband".to_string()))
        );
    }

    #[test]
    fn flags_truncate_the_argument() {
        assert_eq!(
            target("835@wideband+flags{mute|deaf}"),
            ("835".to_string(), Some("wideband".to_string()))
        );
    }

    #[test]
    fn bridge_form_names_the_conference_before_the_dialstring() {
        assert_eq!(
            target("bridge:835:sofia/internal/1000"),
            ("835".to_string(), None)
        );
    }

    #[test]
    fn empty_argument_is_not_a_conference() {
        assert!(parse_target("").is_none());
        assert!(parse_target("@wideband").is_none());
    }

    #[test]
    fn transfer_context_is_not_the_profile() {
        let t = parse_transfer("Transfer loopback/tty-a to inline[conference:835@default]")
            .expect("parsed");
        assert_eq!(t.name, "835");
        assert_eq!(t.profile, None);
    }

    #[test]
    fn transfer_keeps_an_explicit_profile() {
        let t = parse_transfer("Transfer loopback/tty-a to inline[conference:835@wideband@public]")
            .expect("parsed");
        assert_eq!(t.name, "835");
        assert_eq!(t.profile.as_deref(), Some("wideband"));
    }

    #[test]
    fn transfer_elsewhere_is_not_a_conference() {
        assert!(parse_transfer("Transfer sofia/internal/1000 to inline[park@default]").is_none());
    }

    #[test]
    fn instance_lives_only_while_it_has_members() {
        let mut reg = ConferenceRegistry::default();
        reg.join("835", "aaaaaaaa-0000-0000-0000-000000000001", "a");
        reg.join("835", "aaaaaaaa-0000-0000-0000-000000000001", "b");
        assert_eq!(
            reg.instance_for("835"),
            Some("aaaaaaaa-0000-0000-0000-000000000001")
        );

        reg.leave("835", "a");
        assert_eq!(
            reg.instance_for("835"),
            Some("aaaaaaaa-0000-0000-0000-000000000001")
        );
        reg.leave("835", "b");
        assert_eq!(reg.instance_for("835"), None);

        reg.join("835", "aaaaaaaa-0000-0000-0000-000000000002", "c");
        assert_eq!(
            reg.instance_for("835"),
            Some("aaaaaaaa-0000-0000-0000-000000000002")
        );
    }

    #[test]
    fn members_are_listed_per_instance() {
        let mut reg = ConferenceRegistry::default();
        reg.join("835", "aaaaaaaa-0000-0000-0000-000000000001", "a");
        reg.join("835", "aaaaaaaa-0000-0000-0000-000000000001", "b");
        reg.join("844", "aaaaaaaa-0000-0000-0000-000000000003", "c");

        let mut members: Vec<&str> = reg
            .members("aaaaaaaa-0000-0000-0000-000000000001")
            .collect();
        members.sort_unstable();
        assert_eq!(members, ["a", "b"]);
        assert_eq!(
            reg.members("aaaaaaaa-0000-0000-0000-000000000003")
                .collect::<Vec<_>>(),
            ["c"]
        );
    }
}
