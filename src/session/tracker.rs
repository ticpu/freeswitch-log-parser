//! Layer 3 per-session state machine.

use std::collections::{HashMap, HashSet};

use crate::message::{LifecycleEvent, MessageKind};
use crate::stream::{LogEntry, LogStream, ParseStats, UnclassifiedLine};

use super::conference::{
    self, ConferenceEvent, ConferenceMembership, ConferenceRegistry, ConferenceTarget,
};
use super::index::IndexedFields;
use super::loopback;
use super::parse::parse_new_channel;
use super::state::{SessionSnapshot, SessionState};
use super::SessionHook;

/// A [`LogEntry`] paired with the session's state snapshot at that point in time.
#[derive(Debug)]
pub struct EnrichedEntry {
    pub entry: LogEntry,
    /// `None` exactly when `entry.uuid` is `None` — system lines carry no session.
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
        self.apply_index_changes(uuid, IndexedFields::of(&state), IndexedFields::default());
        // The peer's own pointer at this session is not in that diff, and left
        // standing it back-links the next channel to reuse the uuid.
        self.by_other_leg.remove(uuid);
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
        let joined = match conference::detect(entry) {
            Some(ConferenceEvent::Leave) => {
                if let Some(state) = self.sessions.get_mut(uuid) {
                    state.conference = None;
                }
                return;
            }
            Some(ConferenceEvent::Join(target)) => Some(target),
            None => None,
        };

        let seat = self.conference_seat(uuid, joined);
        if let Some(state) = self.sessions.get_mut(uuid) {
            seat_conference(state, seat);
        }
    }

    /// The conference this entry puts `uuid` in, paired with the instance
    /// identity to use. Staying in the same conference keeps the instance
    /// already recorded; otherwise adopt the live instance for that name, or
    /// open one keyed on this session because it is the first member.
    fn conference_seat(
        &self,
        uuid: &str,
        joined: Option<ConferenceTarget>,
    ) -> Option<(ConferenceTarget, String)> {
        let state = self.sessions.get(uuid)?;
        let target = joined.or_else(|| conference::target_from_variables(&state.variables))?;
        let instance = match state.conference.as_ref() {
            Some(current) if current.name == target.name => current.instance.clone(),
            _ => self
                .conferences
                .instance_for(&target.name)
                .map(str::to_string)
                .unwrap_or_else(|| uuid.to_string()),
        };
        Some((target, instance))
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

    /// Point two legs at each other and retire the A leg's pending bridge target.
    ///
    /// The diff bracket around `next()` covers whichever leg produced the entry
    /// and neither the peer nor, on the back-link path, the A leg — so each side
    /// takes a bracket of its own and one mechanism maintains every index.
    fn link_pair(&mut self, a_uuid: &str, b_uuid: &str) {
        self.mutate_indexed(a_uuid, |a| {
            a.other_leg_uuid = Some(b_uuid.to_string());
            a.pending_bridge_target = None;
        });
        self.mutate_indexed(b_uuid, |b| {
            b.other_leg_uuid = Some(a_uuid.to_string());
        });
    }

    /// Cross-session leg linking. Called after `update_from_entry` so per-session
    /// state (bridge target, channel name) is already populated.
    fn link_legs(&mut self, uuid: &str, entry: &LogEntry) {
        match &entry.message_kind {
            MessageKind::OriginateSuccess {
                peer_uuid: Some(peer),
                ..
            } => self.link_pair(uuid, peer),
            // Builds whose originate line omits the `Peer UUID:` suffix leave the
            // channel name as the only handle on the B leg.
            MessageKind::OriginateSuccess {
                channel,
                peer_uuid: None,
            } => {
                if let Some(b_uuid) = self.unique_live_leg(channel, uuid) {
                    self.link_pair(uuid, &b_uuid);
                }
            }
            // New Channel on this UUID — another session may have been waiting for
            // it, either by forced origination UUID or by the target it named.
            MessageKind::ChannelLifecycle {
                event: LifecycleEvent::NewChannel,
                detail,
            } => {
                if let Some(channel_name) = parse_new_channel(detail) {
                    let a_uuid = self
                        .by_other_leg
                        .get(uuid)
                        .cloned()
                        .or_else(|| self.unique_pending_leg(channel_name, uuid))
                        .or_else(|| self.loopback_a_leg(channel_name, uuid))
                        .filter(|a| a.as_str() != uuid);

                    if let Some(a_uuid) = a_uuid {
                        self.link_pair(&a_uuid, uuid);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Seat the session in the conference resolved for it, then refresh whatever
/// membership it holds against its variables.
fn seat_conference(state: &mut SessionState, seat: Option<(ConferenceTarget, String)>) {
    let SessionState {
        conference,
        variables,
        ..
    } = state;
    if let Some((target, instance)) = seat {
        if conference.as_ref().is_none_or(|c| c.name != target.name) {
            *conference = Some(ConferenceMembership {
                name: target.name,
                profile: target.profile.clone(),
                instance,
                member_id: None,
                conference_uuid: None,
            });
        }
        if let (Some(membership), Some(profile)) = (conference.as_mut(), target.profile) {
            membership.profile = Some(profile);
        }
    }
    if let Some(membership) = conference.as_mut() {
        conference::refresh(membership, variables);
    }
}

impl<I: Iterator<Item = String>> Iterator for SessionTracker<I> {
    type Item = EnrichedEntry;

    fn next(&mut self) -> Option<EnrichedEntry> {
        let mut entry = self.inner.next()?;

        let Some(uuid) = entry.uuid.clone() else {
            return Some(EnrichedEntry {
                entry,
                session: None,
            });
        };

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

        let post_hook = self.post_hook.as_ref();
        // Inserted above, and nothing between here removes a session.
        let state = self
            .sessions
            .get_mut(&uuid)
            .expect("the session this entry opened is still tracked");
        if let Some(hook) = post_hook {
            hook(&entry, state);
        }

        let new = IndexedFields::of(state);
        let snapshot = state.snapshot();
        self.apply_index_changes(&uuid, old, new);
        entry.warnings.extend(unreadable);

        Some(EnrichedEntry {
            entry,
            session: Some(snapshot),
        })
    }
}
