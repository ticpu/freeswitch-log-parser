//! The one rule for reading an environment variable.

use anyhow::Context;

/// A variable's value, or `None` when it is not set.
///
/// Set but not valid Unicode is a misconfiguration, not an absent setting:
/// falling back would run with something other than what the operator asked for
/// and say nothing about it.
pub fn var(name: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {name}")),
    }
}
