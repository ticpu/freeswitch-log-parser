//! [`VarName`], the channel-variable name a classified message carries.

use std::fmt;

use freeswitch_types::VARIABLE_PREFIX;

/// The name of a FreeSWITCH channel variable, stored bare.
///
/// A dump spells its keys `variable_sip_call_id` while every other narration
/// (`set`, `export`, `CoreSession::setVariable`) spells the same variable
/// `sip_call_id`. This type holds the bare spelling once, and [`Display`] and
/// [`to_prefixed`](Self::to_prefixed) render the dump's form for a reader.
///
/// It deliberately does not compare against `&str`. A consumer written against
/// the prefixed spelling — `name == "variable_sip_call_id"`, or a
/// `starts_with("variable_")` filter — is the mistake this type exists to turn
/// into a compile error rather than a match that silently stops firing. Compare
/// against [`bare`](Self::bare), or against a `freeswitch-types` variable enum's
/// `as_str`.
///
/// [`Display`]: std::fmt::Display
// No Deref, AsRef<str>, Borrow<str> or PartialEq<str>: any of them restores the
// silent `name == "variable_x"` comparison this type was introduced to break.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarName(String);

impl VarName {
    /// Wrap a name already stripped of the `variable_` prefix.
    pub fn new(bare: impl Into<String>) -> Self {
        VarName(bare.into())
    }

    /// Wrap a name that may carry the `variable_` prefix, stripping it if so.
    pub fn from_prefixed(name: &str) -> Self {
        VarName(
            name.strip_prefix(VARIABLE_PREFIX)
                .unwrap_or(name)
                .to_string(),
        )
    }

    /// The bare name, as `set` and the variable enums spell it.
    pub fn bare(&self) -> &str {
        &self.0
    }

    /// The prefixed name, as a CHANNEL_DATA dump spells it.
    pub fn to_prefixed(&self) -> String {
        freeswitch_types::variable_key(&self.0)
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{VARIABLE_PREFIX}{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_prefixed_strips_once() {
        assert_eq!(
            VarName::from_prefixed("variable_sip_call_id").bare(),
            "sip_call_id"
        );
        assert_eq!(VarName::from_prefixed("sip_call_id").bare(), "sip_call_id");
        assert_eq!(
            VarName::from_prefixed("variable_variable_odd").bare(),
            "variable_odd"
        );
    }

    #[test]
    fn renders_the_prefixed_spelling() {
        let name = VarName::new("sip_call_id");
        assert_eq!(name.to_string(), "variable_sip_call_id");
        assert_eq!(name.to_prefixed(), "variable_sip_call_id");
    }
}
