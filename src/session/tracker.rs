//! Layer 3 per-session state machine.

use std::collections::{HashMap, HashSet};

use crate::message::MessageKind;
use crate::stream::{LogEntry, LogStream, ParseStats, UnclassifiedLine};

use super::conference::{self, ConferenceEvent, ConferenceMembership, ConferenceRegistry};
use super::index::{IndexedFieldChanges, IndexedFields};
use super::loopback;
use super::parse::{
    is_terminal_channel_state, parse_new_channel, parse_originate_channel, parse_originate_success,
};
use super::state::{SessionSnapshot, SessionState};
use super::SessionHook;

/// A [`LogEntry`] paired with the session's state snapshot at that point in time.
#[derive(Debug)]
pub struct EnrichedEntry {
    pub entry: LogEntry,
    /// `None` for system lines (entries with an empty UUID).
    pub session: Option<SessionSnapshot>,
}

/// Layer 3 per-session state machine — tracks per-UUID state (dialplan context,
/// channel state, variables) across entries and yields [`EnrichedEntry`] values.
///
/// Wraps a [`LogStream`] and maintains a `HashMap<String, SessionState>` keyed by UUID.
/// Sessions are never automatically cleaned up; call [`remove_session()`](SessionTracker::remove_session)
/// when a call ends.
pub struct SessionTracker<I> {
    inner: LogStream<I>,
    pub(super) sessions: HashMap<String, SessionState>,
    pub(super) by_channel_name: HashMap<String, HashSet<String>>,
    pub(super) by_pending_target: HashMap<String, String>,
    pub(super) by_other_leg: HashMap<String, String>,
    pub(super) conferences: ConferenceRegistry,
    pre_hook: Option<SessionHook>,
    post_hook: Option<SessionHook>,
}

impl<I: Iterator<Item = String>> SessionTracker<I> {
    /// Wrap a [`LogStream`] to add per-session state tracking.
    pub fn new(inner: LogStream<I>) -> Self {
        SessionTracker {
            inner,
            sessions: HashMap::new(),
            by_channel_name: HashMap::new(),
            by_pending_target: HashMap::new(),
            by_other_leg: HashMap::new(),
            conferences: ConferenceRegistry::default(),
            pre_hook: None,
            post_hook: None,
        }
    }

    /// Register a hook that runs BEFORE built-in field extraction.
    ///
    /// Use this to override how specific fields are extracted. Fields set
    /// by the pre-hook may be preserved by built-in extraction if it uses
    /// `is_none()` guards. Indexed fields set by the hook (`channel_name`,
    /// `other_leg_uuid`) feed cross-session leg correlation like built-in
    /// extraction does.
    pub fn with_pre_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&LogEntry, &mut SessionState) + Send + 'static,
    {
        self.pre_hook = Some(Box::new(hook));
        self
    }

    /// Register a hook that runs AFTER all built-in processing.
    ///
    /// Use this for custom field extraction and relationship detection.
    /// The hook can read fields populated by built-in extraction and
    /// fill gaps with application-specific patterns (e.g., `uuid_bridge`
    /// API results, custom SIP headers). Indexed fields set by the hook
    /// (`channel_name`, `other_leg_uuid`) feed cross-session leg
    /// correlation like built-in extraction does.
    ///
    /// # Example
    ///
    /// ```
    /// use freeswitch_log_parser::{LogStream, SessionTracker, MessageKind};
    ///
    /// let stream = LogStream::new(std::iter::empty::<String>());
    /// let tracker = SessionTracker::new(stream)
    ///     .with_post_hook(|entry, state| {
    ///         if let MessageKind::Execute { application, arguments, .. } = &entry.message_kind {
    ///             if application == "set" && arguments.starts_with("api_result=+OK ") {
    ///                 // extract UUID and set state.other_leg_uuid
    ///             }
    ///         }
    ///     });
    /// ```
    pub fn with_post_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&LogEntry, &mut SessionState) + Send + 'static,
    {
        self.post_hook = Some(Box::new(hook));
        self
    }

    /// All currently tracked sessions, keyed by UUID.
    pub fn sessions(&self) -> &HashMap<String, SessionState> {
        &self.sessions
    }

    /// UUIDs currently in the conference instance named by
    /// [`ConferenceMembership::instance`]. Empty once the last member leaves.
    pub fn conference_members<'a>(&'a self, instance: &'a str) -> impl Iterator<Item = &'a str> {
        self.conferences.members(instance)
    }

    /// Remove and return a session's accumulated state. Call this when a call ends
    /// (e.g. `CS_DESTROY` or hangup) to free memory.
    pub fn remove_session(&mut self, uuid: &str) -> Option<SessionState> {
        let state = self.sessions.remove(uuid)?;
        if let Some(chan) = &state.channel_name {
            if let Some(set) = self.by_channel_name.get_mut(chan) {
                set.remove(uuid);
                if set.is_empty() {
                    self.by_channel_name.remove(chan);
                }
            }
        }
        if let Some(target) = &state.pending_bridge_target {
            self.by_pending_target.remove(target);
        }
        if let Some(other) = &state.other_leg_uuid {
            self.by_other_leg.remove(other);
        }
        if let Some(conf) = &state.conference {
            self.conferences.leave(&conf.name, uuid);
        }
        Some(state)
    }

    /// Delegates to [`LogStream::stats()`].
    pub fn stats(&self) -> &ParseStats {
        self.inner.stats()
    }

    /// Delegates to [`LogStream::drain_unclassified()`].
    pub fn drain_unclassified(&mut self) -> Vec<UnclassifiedLine> {
        self.inner.drain_unclassified()
    }
    /// Conference membership. Called after `update_from_entry` so the channel
    /// variables this reads are already populated. Only `state.conference` is
    /// written here; the registry is updated from the post-hook diff, so a
    /// hook-set membership is registered the same way this one is.
    fn update_conference(&mut self, uuid: &str, entry: &LogEntry) {
        let target = match conference::detect(entry) {
            Some(ConferenceEvent::Leave) => {
                if let Some(state) = self.sessions.get_mut(uuid) {
                    state.conference = None;
                }
                return;
            }
            Some(ConferenceEvent::Join(target)) => Some(target),
            None => None,
        };

        let Some(state) = self.sessions.get(uuid) else {
            return;
        };
        let Some(target) = target.or_else(|| conference::target_from_variables(&state.variables))
        else {
            if let Some(state) = self.sessions.get_mut(uuid) {
                let SessionState {
                    conference,
                    variables,
                    ..
                } = state;
                if let Some(membership) = conference {
                    conference::refresh(membership, variables);
                }
            }
            return;
        };

        // Staying in the same conference keeps the instance already recorded;
        // otherwise adopt the live instance for that name, or open one keyed on
        // this session because it is the first member.
        let instance = match state.conference.as_ref() {
            Some(current) if current.name == target.name => current.instance.clone(),
            _ => self
                .conferences
                .instance_for(&target.name)
                .map(str::to_string)
                .unwrap_or_else(|| uuid.to_string()),
        };

        let Some(state) = self.sessions.get_mut(uuid) else {
            return;
        };
        let SessionState {
            conference,
            variables,
            ..
        } = state;
        let joining_elsewhere = conference.as_ref().is_none_or(|c| c.name != target.name);
        if joining_elsewhere {
            *conference = Some(ConferenceMembership {
                name: target.name,
                profile: target.profile.clone(),
                instance,
                member_id: None,
                conference_uuid: None,
            });
        }
        let Some(membership) = conference.as_mut() else {
            return;
        };
        if target.profile.is_some() {
            membership.profile = target.profile;
        }
        conference::refresh(membership, variables);
    }

    /// The A leg of the loopback whose B leg just appeared. Shares the
    /// originate fallback's ambiguity guard: concurrent loopbacks to the same
    /// destination produce identical names, and linking the wrong pair is worse
    /// than linking none.
    fn loopback_a_leg(&self, b_channel: &str, b_uuid: &str) -> Option<String> {
        let a_channel = loopback::a_leg_name(b_channel)?;
        let candidates: Vec<&String> = self
            .by_channel_name
            .get(&a_channel)?
            .iter()
            .filter(|u| *u != b_uuid)
            .filter(|u| {
                self.sessions
                    .get(*u)
                    .map(|s| !is_terminal_channel_state(s.channel_state.as_deref()))
                    .unwrap_or(false)
            })
            .collect();
        match candidates.as_slice() {
            [a_uuid] => Some((*a_uuid).clone()),
            _ => None,
        }
    }

    /// Cross-session leg linking. Called after `update_from_entry` so per-session
    /// state (bridge target, channel name) is already populated.
    fn link_legs(&mut self, uuid: &str, entry: &LogEntry) {
        // 1. "Originate Resulted in Success ... Peer UUID: BLEG" — authoritative
        if entry.message.contains("Originate Resulted in Success") {
            let a_uuid = uuid.to_string();
            if let Some(peer_uuid) = parse_originate_success(&entry.message) {
                let a_old_pending = self
                    .sessions
                    .get(&a_uuid)
                    .and_then(|s| s.pending_bridge_target.clone());

                let mut a_old_leg = None;
                if let Some(a_state) = self.sessions.get_mut(&a_uuid) {
                    a_old_leg = a_state.other_leg_uuid.replace(peer_uuid.clone());
                    a_state.pending_bridge_target = None;
                }
                self.index_other_leg(&a_uuid, a_old_leg, &peer_uuid);
                if let Some(old_target) = a_old_pending {
                    self.by_pending_target.remove(&old_target);
                }

                let b_state = self.sessions.entry(peer_uuid.clone()).or_default();
                let b_old_leg = b_state.other_leg_uuid.replace(a_uuid.clone());
                self.index_other_leg(&peer_uuid, b_old_leg, &a_uuid);
            } else if let Some(chan) = parse_originate_channel(&entry.message) {
                // Fallback for FS builds without `Peer UUID:` suffix (e.g. 1.10.5-dev):
                // link via unique non-terminated b-leg session whose channel_name
                // matches. Candidates in terminal states are stragglers; if zero or
                // multiple live candidates remain, skip (correctness over coverage).
                let candidates: Vec<String> = self
                    .by_channel_name
                    .get(chan)
                    .map(|set| {
                        set.iter()
                            .filter(|u| *u != &a_uuid)
                            .filter(|u| {
                                self.sessions
                                    .get(*u)
                                    .map(|s| !is_terminal_channel_state(s.channel_state.as_deref()))
                                    .unwrap_or(false)
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();

                if let [b_uuid] = candidates.as_slice() {
                    let b_uuid = b_uuid.clone();
                    let a_old_pending = self
                        .sessions
                        .get(&a_uuid)
                        .and_then(|s| s.pending_bridge_target.clone());

                    let mut a_old_leg = None;
                    if let Some(a_state) = self.sessions.get_mut(&a_uuid) {
                        a_old_leg = a_state.other_leg_uuid.replace(b_uuid.clone());
                        a_state.pending_bridge_target = None;
                    }
                    let mut b_old_leg = None;
                    if let Some(b_state) = self.sessions.get_mut(&b_uuid) {
                        b_old_leg = b_state.other_leg_uuid.replace(a_uuid.clone());
                    }

                    self.index_other_leg(&a_uuid, a_old_leg, &b_uuid);
                    self.index_other_leg(&b_uuid, b_old_leg, &a_uuid);
                    if let Some(old_target) = a_old_pending {
                        self.by_pending_target.remove(&old_target);
                    }
                }
            }
            return;
        }

        // 2. New Channel on this UUID — check if any other session has a pending bridge
        //    with origination_uuid matching this UUID, or target matching this channel name.
        if let MessageKind::ChannelLifecycle { detail } = &entry.message_kind {
            if let Some(channel_name) = parse_new_channel(detail) {
                let b_uuid = uuid.to_string();

                // O(1) index lookups instead of full scan
                let a_uuid_found = self
                    .by_other_leg
                    .get(&b_uuid)
                    .cloned()
                    .or_else(|| self.by_pending_target.get(&channel_name).cloned())
                    .or_else(|| self.loopback_a_leg(&channel_name, &b_uuid))
                    .filter(|a| a != &b_uuid);

                if let Some(a_uuid) = a_uuid_found {
                    let a_old_pending = self
                        .sessions
                        .get(&a_uuid)
                        .and_then(|s| s.pending_bridge_target.clone());

                    let mut a_old_leg = None;
                    if let Some(a_state) = self.sessions.get_mut(&a_uuid) {
                        a_old_leg = a_state.other_leg_uuid.replace(b_uuid.clone());
                        a_state.pending_bridge_target = None;
                    }
                    let mut b_old_leg = None;
                    if let Some(b_state) = self.sessions.get_mut(&b_uuid) {
                        b_old_leg = b_state.other_leg_uuid.replace(a_uuid.clone());
                    }

                    self.index_other_leg(&a_uuid, a_old_leg, &b_uuid);
                    self.index_other_leg(&b_uuid, b_old_leg, &a_uuid);
                    if let Some(old_target) = a_old_pending {
                        self.by_pending_target.remove(&old_target);
                    }
                }
            }
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for SessionTracker<I> {
    type Item = EnrichedEntry;

    fn next(&mut self) -> Option<EnrichedEntry> {
        let entry = self.inner.next()?;

        if entry.uuid.is_empty() {
            return Some(EnrichedEntry {
                entry,
                session: None,
            });
        }

        let uuid = entry.uuid.clone();
        let state = self.sessions.entry(uuid.clone()).or_default();

        // Snapshot indexed fields before the pre-hook and diff after the
        // post-hook so hook-set fields maintain the cross-session indexes
        // exactly like built-in extraction.
        let old = IndexedFields::of(state);

        if let Some(hook) = &self.pre_hook {
            hook(&entry, state);
        }

        state.update_from_entry(&entry);

        self.update_conference(&uuid, &entry);
        self.link_legs(&uuid, &entry);

        // `entry().or_default()` rather than an unwrapped lookup: the session was
        // inserted above and nothing here removes it, but re-asserting that with a
        // panic buys nothing when the map can simply hand back the same state.
        if let Some(hook) = &self.post_hook {
            let state = self.sessions.entry(uuid.clone()).or_default();
            hook(&entry, state);
        }

        let state = self.sessions.entry(uuid.clone()).or_default();
        let changes = IndexedFieldChanges::diff(old, state);
        let snapshot = state.snapshot();
        self.apply_index_changes(&uuid, &changes);

        Some(EnrichedEntry {
            entry,
            session: Some(snapshot),
        })
    }
}
