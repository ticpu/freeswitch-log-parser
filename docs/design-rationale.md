# Design Rationale

Why this library exists and the parsing decisions behind it.

## Standalone library over fluent-bit regex + Lua state

FreeSWITCH's log format is deceptively complex. A naive grep works for quick
searches, but any tool that needs to correlate log lines to a specific call
session needs to understand the format structurally.

The fluent-bit configuration at CAUCA uses a regex parser that misses the
idle percentage field entirely, then a Lua filter script that tracks
`last_uuid` and `last_timestamp` state across lines to fill in gaps. The
regex has four alternations and still fails on truncated buffer lines. The
Lua script works but is fragile, untestable in isolation, and tied to
fluent-bit's filter API.

This crate extracts the parsing logic into a standalone, well-tested Rust
library usable by any consumer: an AI triage tool, a fluent-bit
replacement, an Elasticsearch uploader, or a CLI grep tool.

## Three-layer architecture

The parser follows the same iterator-adapter composition pattern proven in
the `freeswitch-sofia-trace-parser` crate: each layer wraps the previous
one, can be used independently, and never discards raw data.

```
Layer 1: parse_line()          &str → RawLine<'a>              (stateless, zero-alloc)
          ↓
Layer 2: LogStream<I>          Iterator<String> → LogEntry      (structural state machine)
          ↓
Layer 3: SessionTracker<I>     LogStream<I> → EnrichedEntry     (per-UUID state machine)
```

The three-layer split exists because consumers have different needs:

- A grep tool only needs layer 1 — match lines by UUID prefix
- A fluent-bit replacement needs layer 2 — every record needs
  uuid/timestamp and classified message type
- An Elasticsearch indexer needs layer 3 — structured documents with
  session context propagated across entries

Every `LogEntry` carries both `block: Option<Block>` (typed, parsed view)
and `attached: AttachedLines` (raw continuation lines). The consumer always
has access to both representations. This follows the same transparency
principle as `freeswitch-sofia-trace-parser`, where raw frame bytes are
always available alongside parsed SIP messages.

## No regex

The line parser uses positional byte checks, not regex. UUIDs are validated
character-by-character: hex digits at known positions, dashes at positions
8, 13, 18, 23. Timestamps are validated by checking for digit-dash patterns
at known offsets. Log levels are matched from a bracketed string after the
idle percentage field.

This is deliberate:

1. **Performance** — this parser runs on production servers scanning
   compressed log files. `LazyLock<Regex>` would work but byte checks are
   faster for fixed-position fields.

2. **Minimal dependencies** — the crate's only dependency is
   `freeswitch-types` (shared typed enums). Adding `regex` for something
   that's fundamentally positional parsing would be wrong.

3. **Testability** — positional logic has obvious edge cases that map to
   specific test cases. Regex alternations hide failure modes.

## Extensible relationship detection

`SessionTracker` links peer call legs via `other_leg_uuid`. The built-in
patterns cover what vanilla FreeSWITCH logs on its own: the channel fields and
variables that name a peer, the originate result line, the endpoints whose leg
naming implies the pairing, and a channel-name fallback for builds whose
originate line omits the peer UUID.

A candidate the log does not disambiguate is left unlinked. Channel names and
bridge targets both repeat across concurrent calls, so a discovery path keyed on
either must find exactly one live, non-terminal candidate or link nothing: a
wrong pairing propagates silently into every consumer's correlation, while a
missing one is visible as absence.

Consumers have application-specific patterns the library can't anticipate:
Lua `uuid_bridge` API results (`set(api_result=+OK <uuid>)`), custom SIP
headers (`sip_h_X-*`), or proprietary bridging commands. Without extensibility,
consumers must either fork the parser, duplicate relationship tracking in
post-processing, or request upstream changes for each pattern.

`with_pre_hook()`/`with_post_hook()` let consumers inject custom detection
without any of those costs. The post-hook runs after built-in detection,
filling gaps rather than replacing core logic; the pre-hook runs before it,
so hook-seeded state (a channel name, a pending bridge target) is visible to
the built-in patterns of the same entry. This keeps the library focused on
vanilla FreeSWITCH while remaining useful to deployments with custom
bridging infrastructure.

## Conference identity is per instance, not per name

A conference name is reused as soon as the previous conference of that name is
torn down, so membership keyed on the name alone merges calls that never shared
a room. The tracker mints an instance identity instead — the UUID of the first
channel to join while the name has no live members — and drops it when the last
member leaves, so the next join on that name opens a new one. FreeSWITCH's own
conference UUID is carried alongside rather than used as the key: it reaches the
log only through a channel dump, and the identity has to hold for logs where
none is ever taken.

## Typed views of a block body are parsed on demand

A block keeps its raw lines and offers the typed reading as a method, rather than
holding a parsed field alongside them. Storing the parse would make a public
enum's shape depend on whichever cargo feature supplied the parser, and would pay
for every body whether or not the consumer looks — SDP bodies are among the
largest things in the log and most consumers never open them. It would also give
the block two representations that can disagree, when the raw lines are the ones
the transparency principle promises stay authoritative.

## Downstream re-derivations belong on the public surface

Helpers a consumer can only write by re-deriving parser knowledge — which channel
variables carry a peer leg's UUID, how a UUID is spelled inside a message body, how a
bridge argument yields its origination UUID, how a rotated log's filename encodes its
stamp — are public API rather than each binary's private business. Two consumers had
already forked every one of them, and the forks drifted the way forks do: one copy's UUID
pattern accepted only lowercase hex, so an uppercase-hex peer UUID was invisible to that
binary's relationship discovery and to no other. Promoting them also stops the no-regex
decision from leaking, since a consumer that must find a UUID inside a message reaches for
a regex crate unless the parser offers the positional scanner it already uses internally.
Deployment-specific variable names stay out: the peer-variable walk takes a caller
predicate, so a site with its own correlation variables extends the allowlist without
forking the walk.

## Field spans emit only what classification already isolated

The span API never scans free text for addresses, URIs, or numbers — a kind is
emitted only at positions the classifier already isolates, so every span is as
trustworthy as the classification itself. General pattern-matching stays in the
consumer's backstop, labelled best-effort there; a scanner here would promote the
weakest detection to the trusted surface. Which channel variables carry sensitive
values is likewise not this crate's call — the variable vocabulary lives in
`freeswitch-types`. Nested spans are deliberate (an address inside a channel name,
an identifier that is itself a UUID), so the applier treats a contained replacement
as absorbed by the outer one and only partial overlap as an error.

## Index maintenance by diffing, not setters

Hooks receive `&mut SessionState` and set fields directly — but three of
those fields (`channel_name`, `pending_bridge_target`, `other_leg_uuid`)
back secondary lookup indexes, and a hook-set value that never reaches its
index silently breaks cross-session linking (a hook-set `other_leg_uuid` is
invisible to the later New-Channel back-link lookup). Setter methods would
keep the indexes in lockstep but forfeit the transparent field access the
hook API promises. Instead the tracker snapshots the indexed fields before
the pre-hook and diffs them after the post-hook, so one bracket covers every
mutation source — pre-hook, built-in extraction, leg linking, post-hook —
rather than trusting each mutation site to remember its index.

## Typed UTF-8 decode at the input boundary

`mod_logfile`'s 2 KiB write buffer truncates mid-record, and the same cut also
chops a multi-byte codepoint — the byte-level twin of the record-level collision
`lines_split` already models. The library is a `String` consumer, so decoding
happened in callers: the strict `BufRead::lines()` reader we advertised panicked
on the truncated codepoint, and every consumer that wanted to survive it re-forked
a lossy reader. The fork was lossy-blind — it couldn't tell a benign truncation
(a valid lead followed only by valid continuations, cut short) from genuine
corruption (a byte that can't start or continue any sequence), so a downstream
scanner marked whole files unclean on either and re-scanned them forever. Layer 0
owns the decode and types the two cases apart (`Utf8Decode::TruncatedCodepoint`
vs `InvalidBytes`) because the consumer's keep/re-scan decision hinges on exactly
that distinction; collapsing both to `io::ErrorKind::InvalidData` is what forced
the re-derivation in the first place. The recovery count stays at Layer 0 rather
than `ParseStats`: the convenience `.map(|d| d.text)` path drops the verdict
before `LogStream` sees it, and threading it through would either break the
`Iterator<Item = String>` contract or fork a parallel constructor — the verdict
belongs where the bytes are read.

## Parse warnings are a closed set of named kinds

Every anomaly a layer can attach to an entry is a distinct variant, and none
carries a free-form message. A consumer decides per kind whether the entry is
still trustworthy — a record the log buffer cut short and a codec token the
parser could not read call for different handling — and the line excerpt a
warning carries is deliberately truncated, so its text cannot be matched on to
recover the kind. A catch-all variant would push that discrimination back into
the text.

Warnings are not the stream's alone. A reading only the per-session layer
attempts fails where only that layer can see it, and the vocabularies those
readings resolve against carry drift checks on FreeSWITCH source, so a value
none of them knows is evidence rather than noise. Such a warning lands on the
entry beside the stream's own, because a separate per-session channel would give
a consumer two places to look for one question. The failed reading never
regresses the state it was for: the last value that did resolve stands.

## An entry's size is bounded by the log, not by the parser

Continuation lines join the entry ahead of them under no per-entry limit, so a
run that never presents a primary line grows a single entry for as long as the
run lasts. `mod_logfile`'s write budget bounds one physical line, not how many
of them a session emits before the next primary. The attached buffer addresses
its lines with `u32` offsets, so exhausting that range is an outcome the stream
has to report rather than an impossibility it may assume: appending is fallible,
and overflow finalizes the entry with a warning instead of aborting the parse.
