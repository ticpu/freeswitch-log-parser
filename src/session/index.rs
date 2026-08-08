//! Secondary lookup indexes, maintained by diffing the fields that back them
//! across every mutation source rather than by setters.

use std::collections::{HashMap, HashSet};

use super::conference::ConferenceMembership;
use super::state::SessionState;
use super::tracker::SessionTracker;

/// Drop `uuid` from the set under `key`, and the key itself once it is empty —
/// a lingering empty set would read as a live candidate list.
pub(super) fn deindex(map: &mut HashMap<String, HashSet<String>>, key: &str, uuid: &str) {
    if let Some(set) = map.get_mut(key) {
        set.remove(uuid);
        if set.is_empty() {
            map.remove(key);
        }
    }
}

/// Changes to indexed fields, diffed across hooks and built-in extraction
/// for index maintenance.
#[derive(Default)]
pub(super) struct IndexedFieldChanges {
    channel_name: Option<(Option<String>, Option<String>)>,
    pending_bridge_target: Option<(Option<String>, Option<String>)>,
    other_leg_uuid: Option<(Option<String>, Option<String>)>,
    conference: Option<(Option<ConferenceMembership>, Option<ConferenceMembership>)>,
}

/// Indexed fields as they stood before the pre-hook, held for the post-hook diff.
#[derive(Default)]
pub(super) struct IndexedFields {
    channel_name: Option<String>,
    pending_bridge_target: Option<String>,
    other_leg_uuid: Option<String>,
    conference: Option<ConferenceMembership>,
}

impl IndexedFields {
    pub(super) fn of(state: &SessionState) -> Self {
        IndexedFields {
            channel_name: state.channel_name.clone(),
            pending_bridge_target: state.pending_bridge_target.clone(),
            other_leg_uuid: state.other_leg_uuid.clone(),
            conference: state.conference.clone(),
        }
    }
}

impl IndexedFieldChanges {
    pub(super) fn diff(old: IndexedFields, state: &SessionState) -> Self {
        let IndexedFields {
            channel_name: old_channel_name,
            pending_bridge_target: old_pending_bridge_target,
            other_leg_uuid: old_other_leg_uuid,
            conference: old_conference,
        } = old;
        let mut changes = IndexedFieldChanges::default();
        if state.conference != old_conference {
            changes.conference = Some((old_conference, state.conference.clone()));
        }
        if state.channel_name != old_channel_name {
            changes.channel_name = Some((old_channel_name, state.channel_name.clone()));
        }
        if state.pending_bridge_target != old_pending_bridge_target {
            changes.pending_bridge_target = Some((
                old_pending_bridge_target,
                state.pending_bridge_target.clone(),
            ));
        }
        if state.other_leg_uuid != old_other_leg_uuid {
            changes.other_leg_uuid = Some((old_other_leg_uuid, state.other_leg_uuid.clone()));
        }
        changes
    }
}

impl<I: Iterator<Item = String>> SessionTracker<I> {
    pub(super) fn apply_index_changes(&mut self, uuid: &str, changes: &IndexedFieldChanges) {
        if let Some((old, new)) = &changes.channel_name {
            if let Some(old_name) = old {
                deindex(&mut self.by_channel_name, old_name, uuid);
            }
            if let Some(new_name) = new {
                self.by_channel_name
                    .entry(new_name.clone())
                    .or_default()
                    .insert(uuid.to_string());
            }
        }
        if let Some((old, new)) = &changes.pending_bridge_target {
            if let Some(old_target) = old {
                deindex(&mut self.by_pending_target, old_target, uuid);
            }
            if let Some(new_target) = new {
                self.by_pending_target
                    .entry(new_target.clone())
                    .or_default()
                    .insert(uuid.to_string());
            }
        }
        if let Some((old, new)) = &changes.other_leg_uuid {
            match new {
                Some(new_leg) => self.index_other_leg(uuid, old.clone(), new_leg),
                None => {
                    if let Some(old_leg) = old {
                        self.by_other_leg.remove(old_leg);
                    }
                }
            }
        }
        if let Some((old, new)) = &changes.conference {
            let same_instance =
                matches!((old, new), (Some(o), Some(n)) if o.instance == n.instance);
            if !same_instance {
                if let Some(old_conf) = old {
                    self.conferences.leave(&old_conf.name, uuid);
                }
                if let Some(new_conf) = new {
                    self.conferences
                        .join(&new_conf.name, &new_conf.instance, uuid);
                }
            }
        }
    }

    /// Record `uuid`'s `other_leg_uuid` transition in `by_other_leg`,
    /// removing the superseded key so a stale entry cannot mislink a later
    /// `New Channel` back-link. Every write to the index goes through here.
    pub(super) fn index_other_leg(&mut self, uuid: &str, old_leg: Option<String>, new_leg: &str) {
        if let Some(old) = old_leg {
            if old != new_leg {
                self.by_other_leg.remove(&old);
            }
        }
        self.by_other_leg
            .insert(new_leg.to_string(), uuid.to_string());
    }
}
