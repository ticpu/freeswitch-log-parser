//! The fixed-width tokens the log spells out — a session UUID, a rotation
//! stamp, an entry timestamp — are each one character class with separators at
//! known offsets, recognised positionally rather than by regex.

/// A fixed-width token's shape: `len` bytes of `filler`, except at the offsets
/// `separators` names, which hold their exact byte.
pub(crate) struct Mask {
    pub(crate) len: usize,
    pub(crate) separators: &'static [(usize, u8)],
    pub(crate) filler: fn(&u8) -> bool,
}

impl Mask {
    pub(crate) fn matches_at(&self, bytes: &[u8], offset: usize) -> bool {
        let Some(token) = bytes.get(offset..offset + self.len) else {
            return false;
        };
        token.iter().enumerate().all(|(i, b)| {
            match self.separators.iter().find(|(at, _)| *at == i) {
                Some((_, sep)) => b == sep,
                None => (self.filler)(b),
            }
        })
    }
}
