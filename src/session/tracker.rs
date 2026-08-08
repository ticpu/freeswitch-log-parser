//! Layer 3 per-session state machine.

use std::collections::{HashMap, HashSet};

use crate::message::MessageKind;
use crate::stream::{LogEntry, LogStream, ParseStats, UnclassifiedLine};

use super::conference::{self, ConferenceEvent, ConferenceMembership, ConferenceRegistry};
use super::index::{deindex, IndexedFieldChanges, IndexedFields};
use super::loopback;
use super::parse::{parse_new_channel, parse_originate_channel, parse_originate_success};
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
    /// Bridge target name to the sessions waiting on it. A target string repeats
    /// across concurrent calls, so this is a set — a lone live candidate links,
    /// several link nothing.
    pub(super) by_pending_target: HashMap<String, HashSet<String>>,
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
        // Removal is the every-field-to-None diff, so it goes through the same
        // bracket as every other mutation rather than unwinding each index by
        // hand — a field indexed later cannot then be forgotten here.
        let changes =
            IndexedFieldChanges::diff(IndexedFields::of(&state), &SessionState::default());
        self.apply_index_changes(uuid, &changes);
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

    /// The one live session among `candidates` other than `exclude`, or `None`
    /// when the log leaves the choice ambiguous. Sessions in a terminal state are
    /// stragglers from earlier calls and never count.
    fn sole_live_leg(&self, candidates: &HashSet<String>, exclude: &str) -> Option<String> {
        let mut live = candidates
            .iter()
            .filter(|u| u.as_str() != exclude)
            .filter(|u| {
                self.sessions
                    .get(*u)
                    .map(|s| !s.is_terminal())
                    .unwrap_or(false)
            });
        match (live.next(), live.next()) {
            (Some(only), None) => Some(only.clone()),
            _ => None,
        }
    }

    /// The one live session answering to `channel`, other than `exclude`.
    fn unique_live_leg(&self, channel: &str, exclude: &str) -> Option<String> {
        self.sole_live_leg(self.by_channel_name.get(channel)?, exclude)
    }

    /// The one live session waiting on bridge target `target`, other than `exclude`.
    fn unique_pending_leg(&self, target: &str, exclude: &str) -> Option<String> {
        self.sole_live_leg(self.by_pending_target.get(target)?, exclude)
    }

    /// The A leg of the loopback whose B leg just appeared. Concurrent loopbacks
    /// to the same destination produce identical names, so this inherits the
    /// ambiguity guard rather than guessing between them.
    fn loopback_a_leg(&self, b_channel: &str, b_uuid: &str) -> Option<String> {
        let a_channel = loopback::a_leg_name(b_channel)?;
        self.unique_live_leg(&a_channel, b_uuid)
    }

    /// Point two legs at each other, retire the A leg's pending bridge target,
    /// and bring both directions of `by_other_leg` in line.
    ///
    /// The diff bracket around `next()` would reindex whichever leg produced the
    /// entry, but not its peer — indexing both here keeps the pair symmetric
    /// whichever side the log spoke from.
    fn link_pair(&mut self, a_uuid: &str, b_uuid: &str) {
        let a_old_pending = self
            .sessions
            .get(a_uuid)
            .and_then(|s| s.pending_bridge_target.clone());

        let a_state = self.sessions.entry(a_uuid.to_string()).or_default();
        let a_old_leg = a_state.other_leg_uuid.replace(b_uuid.to_string());
        a_state.pending_bridge_target = None;

        let b_state = self.sessions.entry(b_uuid.to_string()).or_default();
        let b_old_leg = b_state.other_leg_uuid.replace(a_uuid.to_string());

        self.index_other_leg(a_uuid, a_old_leg, b_uuid);
        self.index_other_leg(b_uuid, b_old_leg, a_uuid);
        if let Some(old_target) = a_old_pending {
            deindex(&mut self.by_pending_target, &old_target, a_uuid);
        }
    }

    /// Cross-session leg linking. Called after `update_from_entry` so per-session
    /// state (bridge target, channel name) is already populated.
    fn link_legs(&mut self, uuid: &str, entry: &LogEntry) {
        // "Originate Resulted in Success ... Peer UUID: BLEG" — authoritative
        if entry.message.contains("Originate Resulted in Success") {
            if let Some(peer_uuid) = parse_originate_success(&entry.message) {
                self.link_pair(uuid, &peer_uuid);
            } else if let Some(chan) = parse_originate_channel(&entry.message) {
                // Builds whose originate line omits the `Peer UUID:` suffix leave
                // the channel name as the only handle on the B leg.
                if let Some(b_uuid) = self.unique_live_leg(chan, uuid) {
                    self.link_pair(uuid, &b_uuid);
                }
            }
            return;
        }

        // New Channel on this UUID — another session may have been waiting for it,
        // either by forced origination UUID or by the target it named.
        if let MessageKind::ChannelLifecycle { detail } = &entry.message_kind {
            if let Some(channel_name) = parse_new_channel(detail) {
                let a_uuid = self
                    .by_other_leg
                    .get(uuid)
                    .cloned()
                    .or_else(|| self.unique_pending_leg(&channel_name, uuid))
                    .or_else(|| self.loopback_a_leg(&channel_name, uuid))
                    .filter(|a| a.as_str() != uuid);

                if let Some(a_uuid) = a_uuid {
                    self.link_pair(&a_uuid, uuid);
                }
            }
        }
    }
}

impl<I: Iterator<Item = String>> Iterator for SessionTracker<I> {
    type Item = EnrichedEntry;

    fn next(&mut self) -> Option<EnrichedEntry> {
        let mut entry = self.inner.next()?;

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

        let unreadable = state.update_from_entry(&entry);

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
        entry.warnings.extend(unreadable);

        Some(EnrichedEntry {
            entry,
            session: Some(snapshot),
        })
    }
}
