# Design Rationale

Why this library exists and the parsing decisions behind it.

## Why a dedicated parser

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
and `attached: Vec<String>` (raw continuation lines). The consumer always
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

2. **No dependencies** — the crate has zero dependencies. Adding `regex`
   for something that's fundamentally positional parsing would be wrong.

3. **Testability** — positional logic has obvious edge cases that map to
   specific test cases. Regex alternations hide failure modes.

## Extensible relationship detection

`SessionTracker` links bridged call legs via `other_leg_uuid`. Five built-in
patterns cover vanilla FreeSWITCH: `Other-Leg-Unique-ID` field, `bridge()`
with `origination_uuid`, `Originate Resulted in Success` with `Peer UUID:`,
channel-name fallback for older FS builds, and new-channel matching against
pending bridge targets.

Consumers have application-specific patterns the library can't anticipate:
Lua `uuid_bridge` API results (`set(api_result=+OK <uuid>)`), custom SIP
headers (`sip_h_X-*`), or proprietary bridging commands. Without extensibility,
consumers must either fork the parser, duplicate relationship tracking in
post-processing, or request upstream changes for each pattern.

`with_relationship_hook()` lets consumers inject custom detection without any
of those costs. The hook runs after built-in detection, filling gaps rather
than replacing core logic. This keeps the library focused on vanilla FreeSWITCH
while remaining useful to deployments with custom bridging infrastructure.

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
