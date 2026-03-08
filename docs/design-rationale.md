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

## FreeSWITCH log line anatomy

FreeSWITCH's `mod_logfile` and console logger emit lines through
`switch_log_printf()`, which formats into a fixed-size buffer. The format
depends on context — whether a session (channel) is active, whether the
message fits the buffer, and whether the line is part of a multi-line dump.

Five distinct line shapes appear in production logs:

**Format A — Full timestamped line with session UUID.** This is the most
common format for lines produced while a channel is active:

```
8a32f49e-d579-4cc2-93bc-acfca08cc6bb 2025-12-15 15:56:29.854534 95.97% [DEBUG] sofia.c:7624 Channel entering state [received][100]
│                                    │                           │      │       │            └ message
│                                    │                           │      │       └ source file:line
│                                    │                           │      └ log level
│                                    │                           └ idle percentage (scheduler)
│                                    └ timestamp (microsecond precision)
└ channel UUID (session identifier)
```

The idle percentage comes from `switch_core.c`'s idle tracking — it
represents how much time the core scheduler spends waiting rather than
processing. It's a system health indicator, not per-call.

**Format B — System line (no UUID).** Lines logged outside any channel
context — system events, event socket commands, module lifecycle:

```
2025-12-15 15:56:29.914545 95.90% [INFO] mod_event_socket.c:1772 Event Socket Command from ::1:37130: api show calls as xml
```

Same fields as Format A minus the UUID prefix.

**Format C — UUID continuation (no timestamp).** Lines that belong to a
session but were emitted by code paths that don't call `switch_log_printf`
with the timestamp/level format. These include dialplan processing output,
EXECUTE traces, and CHANNEL_DATA variable dumps:

```
8a32f49e-d579-4cc2-93bc-acfca08cc6bb Dialplan: sofia/esinet1-v4-tcp/host.example.com parsing [public->global] continue=true
8a32f49e-d579-4cc2-93bc-acfca08cc6bb EXECUTE [depth=0] sofia/esinet1-v4-tcp/host.example.com db(insert/...)
8a32f49e-d579-4cc2-93bc-acfca08cc6bb Channel-State: [CS_EXECUTE]
8a32f49e-d579-4cc2-93bc-acfca08cc6bb variable_sip_call_id: [abc123@192.0.2.1]
```

The UUID is present but there's no timestamp, log level, or source. These
lines inherit the timestamp from the last full log line.

**Format D — Bare continuation (no UUID, no timestamp).** When a
CHANNEL_DATA dump or multi-line variable value exceeds the per-line UUID
prefix budget, subsequent lines lose the UUID prefix entirely:

```
variable_switch_r_sdp: [v=0
o=- 4119353882 1610586684 IN IP4 192.0.2.1
s=-
c=IN IP4 192.0.2.1
t=0 0
m=audio 47758 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
]
```

These lines inherit both UUID and timestamp from context. They occur because
`switch_log_printf` formats the CHANNEL_DATA block line-by-line, and at
some point the UUID prefix stops being emitted — likely when the output
transitions from the structured dump code to raw variable printing.

**Format E — Truncated buffer collision.** The most surprising format.
`switch_log_printf` uses a fixed-size `char[]` buffer. When a CHANNEL_DATA
variable dump is being written and the buffer fills, the variable name gets
truncated and a new log entry's UUID appears mid-token:

```
varia3231989a-c8fb-42c3-9078-b9d6b1482fa7 EXECUTE [depth=0] sofia/internal-v6/1221@[fd51:2050:2220:198::10] export(...)
```

Here `variable_` was being written, only `varia` fit, and then
`3231989a-...` is the UUID of the next log entry. The prefix is garbage from
the previous buffer's truncated output. The UUID is extractable by scanning
for the pattern within the line. The prefix length varies — we've observed
`varia`, `variab`, `var`, and `variable` prefixes before the UUID.

## Two-layer architecture

The parser is split into two layers that can be used independently:

**Layer 1: Stateless line parser** (`parse_line`). Takes a single `&str`
line, returns a `RawLine` with whatever fields are directly extractable.
No allocation, no state, no context from other lines. This is the unit
that gets the most test coverage — every line format and edge case has a
dedicated test.

**Layer 2: Stateful stream parser** (`LogStream`). An iterator adapter that
wraps any `Iterator<Item = String>`, maintains `last_uuid` and
`last_timestamp` context, and yields `LogEntry` structs where every entry
has a UUID and timestamp (inherited if the line didn't have its own). It also
collects multi-line continuations into `attached` data on the parent entry.

The two-layer split exists because consumers have different needs:

- A grep tool only needs layer 1 — match lines by UUID prefix
- A fluent-bit filter needs layer 2 — every record needs uuid/timestamp
- An Elasticsearch indexer needs layer 2 — structured documents with
  attached data for CHANNEL_DATA blocks

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

## Stateful stream: continuation grouping

The `LogStream` iterator buffers one entry at a time. When it sees a new
"primary" line (Full, System, or Truncated), it yields the buffered entry
and starts a new one. Continuation lines (UuidContinuation with same UUID,
BareContinuation, Empty) are appended to the buffered entry's `attached`
vec.

A UUID continuation with a *different* UUID also triggers yielding the
buffered entry and starting a new one — the UUID change means we've moved
to a different session's output.

This means the iterator always yields entries one behind the current parse
position. The final entry is yielded when the underlying line iterator is
exhausted.

## UUID tracking across truncated lines

Format E (truncated collision) lines are tricky because the UUID appears
at an unpredictable position. The parser scans for the UUID pattern
character-by-character. Once found, the rest of the line after the UUID
is treated as the message. The garbage prefix is discarded.

The stream parser treats truncated lines as primary lines — they start a
new entry and update `last_uuid`. This is correct because the truncation
marks the boundary between two sessions' output: the truncated variable
belonged to the previous session, and the UUID/message belongs to the new
one.

## LogLevel ordering

`LogLevel` derives `PartialOrd` and `Ord` with variants ordered from least
to most severe: Debug < Info < Notice < Warning < Err < Crit < Alert <
Console. This allows `level >= LogLevel::Info` for filtering, matching the
syslog severity convention (inverted from syslog's numeric values, but
natural for Rust's `>=` operator).
