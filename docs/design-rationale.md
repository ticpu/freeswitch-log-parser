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

**Layer 1: Stateless line parser** (`parse_line`). Takes a single `&str`
line, returns a `RawLine` with whatever fields are directly extractable.
No allocation, no state, no context from other lines. This is the unit
that gets the most test coverage — every line format and edge case has a
dedicated test.

**Layer 2: Structural state machine** (`LogStream`). An iterator adapter
that wraps any `Iterator<Item = String>`. Maintains `last_uuid` and
`last_timestamp` context, classifies messages into semantic types
(`MessageKind`), detects multi-line block boundaries (CHANNEL_DATA dumps,
SDP bodies), and yields `LogEntry` structs with both typed `Block` content
and raw `attached` lines. The state machine tracks whether it's currently
inside a CHANNEL_DATA dump, an SDP body, or idle — transitions are driven
by line classification and UUID continuity.

**Layer 3: Per-session state machine** (`SessionTracker`). An iterator
adapter wrapping `LogStream`. Maintains a `HashMap<String, SessionState>`
keyed by UUID, propagating learned context (dialplan context, channel
state, variables) across entries for the same call session. Yields
`EnrichedEntry` structs containing both the raw `LogEntry` and a
`SessionSnapshot` of what was known about the session at that point.

The three-layer split exists because consumers have different needs:

- A grep tool only needs layer 1 — match lines by UUID prefix
- A fluent-bit replacement needs layer 2 — every record needs
  uuid/timestamp and classified message type
- An Elasticsearch indexer needs layer 3 — structured documents with
  session context propagated across entries

## Message classification

Layer 2 classifies the message portion of each log line into semantic
types via `classify_message()`. This is a pure function — no state, no
allocation beyond the returned enum — that uses positional byte checks:

- `EXECUTE [depth=N] channel app(args)` — dialplan execution trace
- `Dialplan: channel ...` — dialplan processing output
- `CHANNEL_DATA` — start of a channel variable dump block
- `Channel-Name: [value]` — channel field within a dump
- `variable_name: [value]` — channel variable within a dump
- `Local SDP:` / `Remote SDP:` — start of an SDP body block
- `State Change ...` — channel state transition
- Everything else — `General`

The classifier is exposed as a public function so Layer 1 consumers can
call it directly on `RawLine.message` without using the stream parser.

## Block detection and multi-line reassembly

The stream state machine (`LogStream`) uses an explicit `StreamState` enum
to track block boundaries:

```
StreamState::Idle
    → sees CHANNEL_DATA primary line → StreamState::InChannelData
    → sees SDP marker primary line   → StreamState::InSdp

StreamState::InChannelData
    → continuation with Channel-X or variable_ → accumulate into block
    → bare continuation while variable value is "open" ([ without ]) → append to value
    → primary line or different UUID → finalize Block::ChannelData, yield, transition

StreamState::InSdp
    → continuation matching SDP line patterns → accumulate into body
    → primary line or non-SDP content → finalize Block::Sdp, yield, transition
```

Multi-line variable values (like `variable_switch_r_sdp: [v=0` followed
by SDP lines and `]`) are reassembled: the parser tracks open brackets
and concatenates continuation lines into the variable's value with `\n`
separators. The raw lines remain in `attached` for consumers who need the
original format.

Every `LogEntry` carries both `block: Option<Block>` (typed, parsed view)
and `attached: Vec<String>` (raw continuation lines). The consumer always
has access to both representations. This follows the same transparency
principle as `freeswitch-sofia-trace-parser`, where raw frame bytes are
always available alongside parsed SIP messages.

## Unclassified data tracking

Following the three-tier tracking pattern from `freeswitch-sofia-trace-parser`
(where it's called `SkipTracking`), the log parser tracks lines that
couldn't be fully classified:

- `UnclassifiedTracking::CountOnly` — default, zero allocation. Just
  increment `lines_unclassified` counter.
- `UnclassifiedTracking::TrackLines` — record line number and reason
  for each unclassified line.
- `UnclassifiedTracking::CaptureData` — like `TrackLines` plus the
  actual line content.

`ParseStats` accumulates `lines_processed`, `lines_unclassified`, and
(when tracking is enabled) a `Vec<UnclassifiedLine>` with reasons like
`OrphanContinuation` (bare line with no pending entry) or
`TruncatedField` (partially parsed EXECUTE or variable).

Stats bubble up through layers: `SessionTracker.stats()` delegates to
`LogStream.stats()`. The consumer at any layer can account for every
input line.

## Per-session state propagation

Layer 3's `SessionTracker` maintains a `SessionState` per UUID containing:

- `channel_name`, `channel_state` — from CHANNEL_DATA blocks
- `dialplan_context`, `dialplan_from`, `dialplan_to` — from dialplan
  processing messages ("Processing X→Y in context Z")
- `variables: HashMap<String, String>` — all variables learned from
  CHANNEL_DATA dumps, `set()`, `export()`, and variable lines

The variables map is generic — the library stores everything it encounters.
Business-specific lookups (like `variables["ngcs_incident_id"]` or
`variables["sip_call_id"]`) are the consumer's responsibility. No
application-specific logic lives in the library.

Sessions are never automatically cleaned up. The consumer calls
`remove_session(uuid)` when a call ends (detected via channel state
`CS_DESTROY` or a hangup message). This is transparent — the library
doesn't make retention policy decisions.

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

The `LogStream` iterator buffers one entry at a time and maintains an
explicit `StreamState` (Idle, InChannelData, InSdp). When it sees a new
"primary" line (Full, System, or Truncated), it finalizes any in-progress
block, yields the buffered entry, and starts a new one. Continuation lines
(UuidContinuation with same UUID, BareContinuation, Empty) are both
appended to the raw `attached` vec and routed to the appropriate block
accumulator based on the current state.

A UUID continuation with a *different* UUID also triggers yielding the
buffered entry and starting a new one — the UUID change means we've moved
to a different session's output.

EXECUTE UUID continuations are treated as primary lines — they yield the
previous pending entry and start a new one. This separates execution
traces from their parent CHANNEL_DATA blocks, matching the production
semantics where each EXECUTE is a distinct event.

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
