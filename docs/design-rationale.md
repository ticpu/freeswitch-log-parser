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
library usable by any consumer: the SIP trace analyzer's AI tool, a
fluent-bit replacement, an Elasticsearch uploader, or a CLI grep tool.

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
