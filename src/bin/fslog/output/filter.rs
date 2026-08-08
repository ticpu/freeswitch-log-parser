//! Entry filtering — the needle automatons, the scope rules, and the wider
//! scope that would have admitted a rejected entry.

use std::io;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use freeswitch_log_parser::{find_uuids, normalize_entry_timestamp, Block, LogLevel};

/// Build a case-insensitive multi-needle matcher. One automaton scans a haystack
/// once for every needle, so a `--related` pass carrying hundreds of discovered
/// leg UUIDs costs the same per entry as a single `-u`.
fn build_matcher(needles: &[String]) -> io::Result<Option<AhoCorasick>> {
    if needles.is_empty() {
        return Ok(None);
    }
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(needles)
        .map(Some)
        .map_err(|e| {
            io::Error::other(format!(
                "cannot build a matcher for {} pattern(s): {e}",
                needles.len()
            ))
        })
}

/// Construction parameters for [`FilterConfig::new`]. `Default` lets call sites
/// name only the fields they set, rather than pass nine positionals where two
/// transposed `Option<String>`s would compile and silently invert a date range.
#[derive(Default)]
pub struct FilterParams {
    pub uuid: Vec<String>,
    pub uuid_strict: bool,
    pub match_blocks: bool,
    pub min_level: Option<LogLevel>,
    pub category: Vec<String>,
    pub fgrep: Option<String>,
    pub grep: Option<regex::Regex>,
    pub codec: Vec<String>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

/// The wider scope that would have admitted an entry the filter rejected on a
/// scope boundary alone. Ordered as the buckets are tried, and exclusive: an
/// entry lands in at most one, so the counts sum to what the wider run shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hidden {
    /// The pattern is in the channel-UUID column, which pattern search skips.
    PatternInUuid,
    /// The pattern is in an attached block line, reachable with `--match-blocks`.
    PatternInBlocks,
    /// A `-u` needle is in the message or an attached line, not the UUID column.
    UuidInBody,
}

pub enum Verdict {
    Match,
    Hidden(Hidden),
    Reject,
}

#[derive(Clone, Default)]
pub struct FilterConfig {
    uuid_ac: Option<AhoCorasick>,
    /// The `-u` needles behind `uuid_ac`, kept so a suggested command can be
    /// checked against what is already in effect.
    uuid_needles: Vec<String>,
    /// Restrict UUID matching to `entry.uuid` (output pass) vs. also scanning
    /// message and attached lines (discovery pass).
    pub uuid_strict: bool,
    /// Extend fgrep/grep matching into attached/block lines, not just the message.
    pub match_blocks: bool,
    pub min_level: Option<LogLevel>,
    /// Message-kind labels; an entry matches if it carries any of them.
    pub category: Vec<String>,
    fgrep_ac: Option<AhoCorasick>,
    fgrep_needle: Option<String>,
    pub grep: Option<regex::Regex>,
    /// `grep` recompiled case-insensitively. The UUID-column probe advertises
    /// `-u`, which is case-insensitive, so probing with the case-sensitive regex
    /// would report zero for an uppercase-hex pattern against a lowercase log —
    /// the case most in need of the count.
    grep_ci: Option<regex::Regex>,
    /// Codec names, lowercased; an entry matches if its negotiation or SDP
    /// block names any of them.
    pub codec: Vec<String>,
    pub from_ts: Option<String>,
    pub until_ts: Option<String>,
}

/// Recompile a pattern with the case-insensitivity `-u` matching has, keeping
/// any inline flags the operator wrote.
fn case_insensitive(re: &regex::Regex) -> io::Result<regex::Regex> {
    regex::RegexBuilder::new(re.as_str())
        .case_insensitive(true)
        .build()
        .map_err(|e| io::Error::other(format!("cannot build a case-insensitive probe: {e}")))
}

impl FilterConfig {
    pub fn new(p: FilterParams) -> io::Result<Self> {
        Ok(FilterConfig {
            uuid_ac: build_matcher(&p.uuid)?,
            uuid_needles: p.uuid,
            uuid_strict: p.uuid_strict,
            match_blocks: p.match_blocks,
            min_level: p.min_level,
            category: p.category,
            fgrep_ac: build_matcher(p.fgrep.as_slice())?,
            fgrep_needle: p.fgrep,
            grep_ci: p.grep.as_ref().map(case_insensitive).transpose()?,
            grep: p.grep,
            codec: p.codec.iter().map(|c| c.to_lowercase()).collect(),
            from_ts: p.from_ts,
            until_ts: p.until_ts,
        })
    }

    pub fn set_uuids(&mut self, needles: &[String]) -> io::Result<()> {
        self.uuid_ac = build_matcher(needles)?;
        self.uuid_needles = needles.to_vec();
        Ok(())
    }

    pub fn set_fgrep(&mut self, needle: &str) -> io::Result<()> {
        self.fgrep_ac = build_matcher(std::slice::from_ref(&needle.to_string()))?;
        self.fgrep_needle = Some(needle.to_string());
        Ok(())
    }

    pub fn uuid_needle_count(&self) -> usize {
        self.uuid_needles.len()
    }

    /// A UUID named anywhere in the pattern, so a `PatternInUuid` report can name
    /// the command instead of only the flag — `--grep 'Hangup on <uuid>'` is the
    /// case that matters. `None` when the pattern names none, or when that UUID
    /// is already a `-u` needle and the suggestion would change nothing.
    pub fn suggested_uuid(&self) -> Option<&str> {
        let sources = self
            .fgrep_needle
            .as_deref()
            .into_iter()
            .chain(self.grep.as_ref().map(|re| re.as_str()));
        let uuid = sources.flat_map(find_uuids).map(|(_, u)| u).next()?;
        let known = self
            .uuid_needles
            .iter()
            .any(|n| n.eq_ignore_ascii_case(uuid));
        (!known).then_some(uuid)
    }

    /// A copy suited to peer-UUID discovery: category cleared (the seed term may
    /// surface under any message kind), UUID matching loosened to message bodies
    /// and attached lines so the seed is found wherever it appears.
    pub fn for_discovery(&self) -> FilterConfig {
        FilterConfig {
            uuid_strict: false,
            match_blocks: true,
            category: Vec::new(),
            ..self.clone()
        }
    }

    /// Whether the entry's media blocks name one of the wanted codecs.
    fn codec_matches(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        let wanted = |name: &str| {
            let name = name.to_lowercase();
            self.codec.iter().any(|c| name.contains(c.as_str()))
        };
        match &entry.block {
            Some(Block::CodecNegotiation {
                comparisons,
                matched,
                near_matched,
                ..
            }) => {
                comparisons
                    .iter()
                    .any(|(o, l)| wanted(&o.name) || wanted(&l.name))
                    || matched.iter().chain(near_matched).any(|c| wanted(&c.name))
            }
            #[cfg(feature = "sdp")]
            Some(block @ Block::Sdp { .. }) => match block.sdp_codecs() {
                // Every section, not the negotiable ones: an offer on a stream the
                // peer then held is exactly what this flag is used to find.
                Some(Ok(codecs)) => {
                    codecs
                        .sections()
                        .iter()
                        .flat_map(|s| s.entries())
                        .any(|e| match e {
                            freeswitch_types::sdp::SdpCodecEntry::Rtp(c) => wanted(c.name()),
                            _ => false,
                        })
                }
                // A body that will not parse cannot claim a codec either way.
                _ => false,
            },
            _ => false,
        }
    }

    fn level_ok(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        match (self.min_level, entry.level) {
            (Some(min), Some(level)) => level >= min,
            _ => true,
        }
    }

    fn category_ok(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        self.category.is_empty()
            || self
                .category
                .iter()
                .any(|c| entry.message_kind.label() == c.as_str())
    }

    fn codec_ok(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        self.codec.is_empty() || self.codec_matches(entry)
    }

    fn window_ok(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        if (self.from_ts.is_none() && self.until_ts.is_none()) || entry.timestamp.is_empty() {
            return true;
        }
        let entry_ts = normalize_entry_timestamp(&entry.timestamp);
        if let Some(ref from) = self.from_ts {
            if entry_ts.as_str() < from.as_str() {
                return false;
            }
        }
        if let Some(ref until) = self.until_ts {
            if entry_ts.as_str() > until.as_str() {
                return false;
            }
        }
        true
    }

    /// `body` widens the UUID needles past `entry.uuid` into the message and
    /// attached lines — the scope `--related`'s discovery pass runs at.
    fn uuid_ok_scoped(&self, entry: &freeswitch_log_parser::LogEntry, body: bool) -> bool {
        match self.uuid_ac {
            None => true,
            Some(ref ac) => {
                ac.is_match(entry.uuid.as_deref().unwrap_or("").as_bytes())
                    || (body
                        && (ac.is_match(entry.message.as_bytes())
                            || entry.attached.iter().any(|l| ac.is_match(l.as_bytes()))))
            }
        }
    }

    /// `--fgrep` and `--grep` are conjuncts, so the scope is parameterised once
    /// for both: widening that only one of them reaches admits nothing.
    fn pattern_ok_scoped(&self, entry: &freeswitch_log_parser::LogEntry, blocks: bool) -> bool {
        if let Some(ref ac) = self.fgrep_ac {
            let hit = ac.is_match(entry.message.as_bytes())
                || (blocks && entry.attached.iter().any(|l| ac.is_match(l.as_bytes())));
            if !hit {
                return false;
            }
        }
        if let Some(ref re) = self.grep {
            let hit = re.is_match(&entry.message)
                || (blocks && entry.attached.iter().any(|l| re.is_match(l)));
            if !hit {
                return false;
            }
        }
        true
    }

    /// Everything but the two scoped predicates: what a wider *scope* cannot
    /// bring back.
    fn others_ok(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        self.level_ok(entry)
            && self.category_ok(entry)
            && self.codec_ok(entry)
            && self.window_ok(entry)
    }

    /// Whether the pattern sits in the channel-UUID column, asked with the
    /// semantics of the `-u` this would advertise rather than the pattern's own.
    fn pattern_in_uuid_column(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        let uuid = entry.uuid.as_deref().unwrap_or("");
        if let Some(ref ac) = self.fgrep_ac {
            if !ac.is_match(uuid.as_bytes()) {
                return false;
            }
        }
        match self.grep_ci {
            Some(ref re) => re.is_match(uuid),
            None => true,
        }
    }

    pub fn matches(&self, entry: &freeswitch_log_parser::LogEntry) -> bool {
        self.others_ok(entry)
            && self.uuid_ok_scoped(entry, !self.uuid_strict)
            && self.pattern_ok_scoped(entry, self.match_blocks)
    }

    /// Classify an entry in one pass, so a rejection that turned only on a scope
    /// boundary can be counted under the flag that widens to it. Only entries
    /// every other predicate accepted are bucketed: a `--level` or date-window
    /// rejection is not something a wider scope would reveal, and pointing at a
    /// flag that cannot admit the entry is the silence this exists to end.
    ///
    /// An entry failing both scoped predicates is left unbucketed — no single
    /// flag brings it back — which is also what keeps the buckets exclusive.
    pub fn verdict(&self, entry: &freeswitch_log_parser::LogEntry) -> Verdict {
        if !self.others_ok(entry) {
            return Verdict::Reject;
        }
        let uuid_ok = self.uuid_ok_scoped(entry, !self.uuid_strict);
        let pattern_ok = self.pattern_ok_scoped(entry, self.match_blocks);
        match (uuid_ok, pattern_ok) {
            (true, true) => Verdict::Match,
            (true, false) => {
                if self.pattern_in_uuid_column(entry) {
                    Verdict::Hidden(Hidden::PatternInUuid)
                } else if !self.match_blocks && self.pattern_ok_scoped(entry, true) {
                    Verdict::Hidden(Hidden::PatternInBlocks)
                } else {
                    Verdict::Reject
                }
            }
            (false, true) => {
                if self.uuid_strict && self.uuid_ok_scoped(entry, true) {
                    Verdict::Hidden(Hidden::UuidInBody)
                } else {
                    Verdict::Reject
                }
            }
            (false, false) => Verdict::Reject,
        }
    }
}
