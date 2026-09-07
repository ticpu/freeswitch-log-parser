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

/// One indexed field on either side of the mutation bracket.
pub(super) struct Change<T> {
    old: Option<T>,
    new: Option<T>,
}

/// Move `uuid` between the sets a set-valued index keys by name.
fn reindex(map: &mut HashMap<String, HashSet<String>>, uuid: &str, change: Change<String>) {
    if change.old == change.new {
        return;
    }
    if let Some(old) = change.old {
        deindex(map, &old, uuid);
    }
    if let Some(new) = change.new {
        map.entry(new).or_default().insert(uuid.to_string());
    }
}

/// Indexed fields as they stood at one end of the bracket.
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

impl<I: Iterator<Item = String>> SessionTracker<I> {
    /// Bring every index in line with one bracket's worth of mutation.
    pub(super) fn apply_index_changes(
        &mut self,
        uuid: &str,
        old: IndexedFields,
        new: IndexedFields,
    ) {
        reindex(
            &mut self.by_channel_name,
            uuid,
            Change {
                old: old.channel_name,
                new: new.channel_name,
            },
        );
        reindex(
            &mut self.by_pending_target,
            uuid,
            Change {
                old: old.pending_bridge_target,
                new: new.pending_bridge_target,
            },
        );

        let leg = Change {
            old: old.other_leg_uuid,
            new: new.other_leg_uuid,
        };
        if leg.old != leg.new {
            match leg.new {
                Some(new_leg) => self.index_other_leg(uuid, leg.old, &new_leg),
                None => {
                    if let Some(old_leg) = leg.old {
                        self.deindex_other_leg(&old_leg, uuid);
                    }
                }
            }
        }

        let conference = Change {
            old: old.conference,
            new: new.conference,
        };
        // The registry keys on the name and identifies on the instance, so the
        // seat is the pair: a name change carrying the instance forward still
        // moves the session, and only profile or member id moving is churn.
        let same_seat = matches!(
            (&conference.old, &conference.new),
            (Some(o), Some(n)) if o.name == n.name && o.instance == n.instance
        );
        if !same_seat {
            if let Some(old_conf) = conference.old {
                self.conferences.leave(&old_conf.name, uuid);
            }
            if let Some(new_conf) = conference.new {
                self.conferences
                    .join(&new_conf.name, &new_conf.instance, uuid);
            }
        }
    }

    /// Record `uuid`'s `other_leg_uuid` transition in `by_other_leg`,
    /// removing the superseded key so a stale entry cannot mislink a later
    /// `New Channel` back-link. Every write to the index goes through here.
    pub(super) fn index_other_leg(&mut self, uuid: &str, old_leg: Option<String>, new_leg: &str) {
        if let Some(old) = old_leg {
            if old != new_leg {
                self.deindex_other_leg(&old, uuid);
            }
        }
        self.by_other_leg
            .insert(new_leg.to_string(), uuid.to_string());
    }

    /// Drop `key` only while it still names `uuid`: a later pair may have
    /// re-pointed it at another session, whose link this would otherwise cut.
    pub(super) fn deindex_other_leg(&mut self, key: &str, uuid: &str) {
        if self.by_other_leg.get(key).is_some_and(|u| u == uuid) {
            self.by_other_leg.remove(key);
        }
    }
}
