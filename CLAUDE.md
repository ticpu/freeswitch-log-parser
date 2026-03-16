# Claude Code Development Notes

## Project Overview

Library crate for parsing FreeSWITCH log files. Three-layer design:
- **Layer 1**: Stateless line parser (`parse_line`) — classifies individual lines, extracts fields
- **Layer 2**: Structural state machine (`LogStream`) — groups continuations, classifies messages (`MessageKind`), detects block boundaries (CHANNEL_DATA, SDP), tracks unclassified lines
- **Layer 3**: Per-session state machine (`SessionTracker`) — tracks per-UUID state (dialplan context, channel state, variables), propagates context across entries

Single dependency: `freeswitch-types` (same author) for typed enums (`CallDirection`, `ChannelState`, `CallState`). No regex — all positional byte parsing.

## Architecture

See `docs/design-rationale.md` for design reasoning: why a dedicated parser, why no regex, and why the three-layer split.

### Key Files

- `src/level.rs` — `LogLevel` enum with `FromStr`/`Display`/`Ord`
- `src/line.rs` — `parse_line()` stateless parser, `RawLine`, `LineKind`
- `src/message.rs` — `classify_message()` pure function, `MessageKind`, `SdpDirection`
- `src/stream.rs` — `LogStream` state machine, `LogEntry`, `Block`, `ParseStats`, `UnclassifiedTracking`
- `src/session.rs` — `SessionTracker`, `SessionState`, `EnrichedEntry`, `SessionSnapshot`
- `src/lib.rs` — public API re-exports

## FreeSWITCH Log Format

Five distinct line shapes appear in production logs:

**Format A — Full timestamped line with session UUID.** Most common for lines produced while a channel is active:

```
UUID YYYY-MM-DD HH:MM:SS.UUUUUU CC.CC% [LEVEL] source:line message
│                                │      │       │            └ message
│                                │      │       └ source file:line
│                                │      └ log level
│                                └ idle percentage (scheduler health, not per-call)
└ channel UUID (session identifier)
```

**Format B — System line (no UUID).** Lines logged outside any channel context — system events, event socket commands, module lifecycle. Same fields as Format A minus the UUID prefix.

**Format C — UUID continuation (no timestamp).** Lines from subsystems that don't use timestamp/level format — dialplan processing, EXECUTE traces, CHANNEL_DATA variable dumps:

```
UUID Dialplan: channel parsing [context->extension] continue=true
UUID EXECUTE [depth=0] channel app(args)
UUID Channel-State: [CS_EXECUTE]
UUID variable_sip_call_id: [value]
```

Inherits timestamp from the last full log line.

**Format D — Bare continuation (no UUID, no timestamp).** When multi-line values exceed the per-line UUID prefix budget. Occurs in CHANNEL_DATA dumps when `switch_event_serialize()` produces multi-line output (e.g., embedded SDP in a variable value). `mod_logfile` splits `node->data` by newlines and prepends the session UUID to each line — when the UUID prepend is disabled or the line lacks session context, the UUID is absent. Inherits both UUID and timestamp from context.

**Format E — Truncated buffer collision.** `mod_logfile` uses a fixed 2048-byte buffer (`mod_logfile.c:299`) for UUID prepend:

```c
char buf[2048];
switch_snprintf(buf, sizeof(buf), "%s %s\n", node->userdata, lines[i]);
```

Effective payload ~2010 bytes (2048 minus 36 UUID, 1 space, 1 newline). When exceeded, `snprintf` truncates and the trailing `\n` is lost, so the next log entry collides on the same physical line:

```
varia3231989a-c8fb-42c3-9078-b9d6b1482fa7 EXECUTE [depth=0] ...
```

Garbage prefix length varies (`var`, `varia`, `variab`, `variable`). For long values (e.g., PIDF XML), the collision UUID can appear hundreds of bytes in.

Note: truncation happens exclusively in `mod_logfile`'s UUID prepend stage, not in the core logging pipeline which uses `switch_vasprintf()` (dynamic allocation, no size limit).

### Log output taxonomy

Two structurally distinct output types. The `[LEVEL] source:line` marker is definitive — present means `switch_log_printf()`, absent means structured subsystem output.

**Primary log lines (Format A/B):** Every `switch_log_printf()` call goes through `switch_log_meta_vprintf()` (switch_log.c:599). When `log_uuid=true` (default), `mod_logfile` splits `node->data` by `\n` and prepends the session UUID (mod_logfile.c:298-314). A single call can produce multiple lines if its format string contains embedded `\n`:

| Source | Format | Multi-line |
|--------|--------|------------|
| mod_dptools.c:1999 | `"CHANNEL_DATA:\n%s\n"` | Yes — serialized event |
| sofia_glue.c:1676 | `"Local SDP %s:\n%s\n"` | Yes — SDP body |
| sofia.c:7634 | `"Remote SDP:\n%s\n"` | Yes — SDP body |
| switch_channel.c:2615 | `"(%s) State Change %s -> %s\n"` | No |
| switch_core_media.c:8892 | `"Activating RTCP PORT %d\n"` | No |

**Structured output (Format C/D):** UUID present but no timestamp/level/source.

Dialplan engine (mod_dialplan_xml.c):

| Pattern | Format string |
|---------|---------------|
| Regex match | `"Dialplan: %s Regex (PASS\|FAIL) [%s] %s(%s) =~ /%s/ break=%s\n"` |
| Action | `"Dialplan: %s Action %s(%s) %s\n"` |
| ANTI-Action | `"Dialplan: %s ANTI-Action %s(%s) %s\n"` |
| Absolute | `"Dialplan: %s Absolute Condition [%s]\n"` |
| Recursive | `"Processing recursive conditions level:%d [%s] require-nested=%s\n"` |

Chatplan (mod_sms.c) uses identical patterns with `"Chatplan:"` prefix.

Execution traces (switch_core_session.c:2907): `"EXECUTE [depth=%d] %s %s(%s)\n"`

CHANNEL_DATA (switch_event.c:1603): `"FIELDNAME: [VALUE]\n"` — multi-line values keep `[` on first line, content on subsequent lines, `]` closes on its own line.

State machine: `"%s Standard EXECUTE\n"`, `"%s Standard SOFT_EXECUTE\n"` (switch_core_state_machine.c)

Endpoint-specific: `"%s SOFIA EXECUTE\n"` (mod_sofia.c:232), `"%s RTC EXECUTE\n"` (mod_rtc.c:120)

## Parser Internals

### Message classification

`classify_message()` is a pure function using positional byte checks:

- `EXECUTE [depth=N] channel app(args)` → execution trace
- `Dialplan: channel ...` / `Chatplan: channel ...` → dialplan processing
- `CHANNEL_DATA` → start of channel variable dump block
- `Channel-Name: [value]` → channel field within a dump
- `variable_name: [value]` → channel variable within a dump
- `Local SDP:` / `Remote SDP:` → start of SDP body block
- `State Change ...` → channel state transition
- Everything else → `General`

Exposed as a public function so Layer 1 consumers can call it directly on `RawLine.message` without using the stream parser.

### Block detection state machine

`LogStream` tracks block boundaries with explicit `StreamState`:

```
Idle → CHANNEL_DATA primary → InChannelData
Idle → SDP marker primary   → InSdp

InChannelData:
  Channel-X or variable_ continuation → accumulate into block
  Bare continuation while value "open" ([ without ]) → append to value
  Primary line or different UUID → finalize Block::ChannelData, yield, transition

InSdp:
  SDP line continuation → accumulate into body
  Primary line or non-SDP → finalize Block::Sdp, yield, transition
```

Multi-line variable values (e.g., embedded SDP) are reassembled: parser tracks open brackets and concatenates continuation lines with `\n` separators. Raw lines remain in `attached` for consumers needing the original format.

Every `LogEntry` carries both `block: Option<Block>` (typed, parsed) and `attached: Vec<String>` (raw continuation lines).

### Continuation grouping

The iterator buffers one entry at a time. A new "primary" line (Full, System, Truncated) finalizes any in-progress block, yields the buffered entry, and starts a new one. Continuation lines append to both the raw `attached` vec and the appropriate block accumulator.

UUID continuation with a *different* UUID also triggers yielding — the UUID change means a different session's output.

EXECUTE UUID continuations are treated as primary lines — they yield the previous entry and start a new one, separating execution traces from their parent CHANNEL_DATA blocks.

The iterator always yields entries one behind the current parse position. Final entry yields when the underlying iterator is exhausted.

### UUID tracking across truncated lines

Layer 1 scans the first 50 bytes for a UUID pattern — catches common short-prefix collisions. For long collisions (UUID hundreds of bytes in), Layer 1 classifies as BareContinuation. Layer 2 detects these by checking message length against the ~2010-byte payload limit and scanning the overflow for an embedded UUID. When found, the line is split: prefix stays as continuation data, UUID+suffix becomes a separate entry, `lines_split` incremented.

Both detected and split truncated lines are treated as primary lines — they start a new entry and update `last_uuid`.

### Unclassified data tracking

Three tiers:

- `CountOnly` — default, zero allocation. Just increments `lines_unclassified`.
- `TrackLines` — records line number and reason per unclassified line.
- `CaptureData` — like TrackLines plus actual line content.

`ParseStats` accounting invariant:

```
lines_processed + lines_split == lines_in_entries + lines_empty_orphan
```

`ParseStats::unaccounted_lines()` returns the difference — non-zero indicates a parser bug.

Counters: `lines_processed` (every physical line), `lines_in_entries` (lines in entries: 1 primary + N attached), `lines_empty_orphan` (empty lines with no pending entry), `lines_split` (truncated collisions split into multiple entries), `lines_unclassified` (orthogonal anomaly counter).

### Per-session state propagation

`SessionTracker` maintains `SessionState` per UUID:

- `channel_name`, `channel_state` — from CHANNEL_DATA blocks
- `dialplan_context`, `dialplan_from`, `dialplan_to` — from dialplan processing messages
- `variables: HashMap<String, String>` — all variables from CHANNEL_DATA dumps, `set()`, `export()`, variable lines

No application-specific logic — consumers do business-specific lookups.

Sessions are never automatically cleaned up — consumer calls `remove_session(uuid)`. Library doesn't make retention policy decisions.

### LogLevel ordering

Ordered least to most severe: Debug < Info < Notice < Warning < Err < Crit < Alert < Console. Allows `level >= LogLevel::Info` for filtering (inverted from syslog numeric values, natural for Rust's `>=`).

## Test Data

Production log fixtures live in `tests/fixtures/` (xz-compressed rotated files + uncompressed `freeswitch.log`).

**Always prefer `fslog` over raw grep/rg** when investigating log data:
```
./target/release/fslog --dir tests/fixtures/ search --from YYYY-MM-DD -u <uuid> --session --blocks
```
`--session` shows accumulated state (context, channel state, channel name) per entry.
`--blocks` expands CHANNEL_DATA fields/variables and SDP bodies inline.
Add `--from` to avoid scanning the full fixture set (a month of logs), you are NOT allowed to override with `--yes`, no meaningful search requires reading >20 logs files.

Use RFC 5737 IPs (192.0.2.x, 198.51.100.x) and RFC 3849 IPv6 (2001:db8::/32) in tests.
Use fictional UUIDs — generate consistent ones for test fixtures.
Never copy production log lines verbatim into source.

## Rust Guidelines

### Workflow
- `cargo check --message-format=short` → `cargo clippy --fix --allow-dirty --message-format=short` → `cargo fmt --all` → `cargo test --release -- --quiet`
- Always run tests with `--release` — debug builds are too slow on xz-compressed production fixture tests
- Build the binary with `cargo build --release --features tui` — the `tui` feature enables the monitor subcommand (includes ratatui, serde, serde_yml)
- Before release: verify no warnings with each feature combination — `cargo check --features cli`, `cargo check --features tui` (tui implies cli)
- Release tags: `git tag -as vX.Y.Z -m "vX.Y.Z"` (annotated + signed)
- `fslog monitor --dump` prints the call table to stdout (no TUI), useful for testing and scripting

### Style
- Minimal dependencies (`freeswitch-types` only) — do not add crates without discussion
- No regex — all parsing is positional byte checks
- `pub use` re-exports in `lib.rs` for clean public API
- Every line format and edge case gets its own `#[test]`
- Tests use realistic but fictional log lines that exercise the exact byte positions the parser checks
