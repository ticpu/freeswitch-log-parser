# Claude Code Development Notes

## Project Overview

Library crate for parsing FreeSWITCH log files. Three-layer design:
- **Layer 1**: Stateless line parser (`parse_line`) — classifies individual lines, extracts fields
- **Layer 2**: Structural state machine (`LogStream`) — groups continuations, classifies messages (`MessageKind`), detects block boundaries (CHANNEL_DATA, SDP), tracks unclassified lines
- **Layer 3**: Per-session state machine (`SessionTracker`) — tracks per-UUID state (dialplan context, channel state, variables), propagates context across entries

Single dependency: `freeswitch-types` (same author) for typed enums (`CallDirection`, `ChannelState`, `CallState`). No regex — all positional byte parsing.

## Architecture

See `docs/design-rationale.md` for design reasoning: why a dedicated parser, why no regex, and why the three-layer split.

### Scope: what earns built-in decoding

Built-in decoding is only for shapes FreeSWITCH itself emits — before accepting
a feature request to decode a new pattern, verify it against core/module format
strings, not against what appears in our production logs. If a log shape exists
because of *our* dialplan or config (user-chosen variable names, inlined `${api}`
calls in a `set`), it is application-specific and stays in a consumer hook
(`with_pre_hook`/`with_post_hook`), no matter how canonical the request's framing
sounds. Rejected example: "SessionTracker should decode `set(api_result=+OK
<uuid>)` per the canonical-decoder principle" — `api_result` is a variable name
chosen by a CAUCA dialplan (`set(api_result=${regex(${uuid_bridge(...)}...)})`),
not a FreeSWITCH log shape; another deployment names it differently or never sets
it. The tell was in this repo the whole time: `docs/design-rationale.md`
"Extensible relationship detection" lists that exact pattern as the motivating
example for the hook API. When a feature request contradicts a decision already
recorded in design-rationale.md, the rationale wins until explicitly revisited —
check it *before* evaluating the request's mechanics.

### Key Files

- `src/level.rs` — `LogLevel` enum with `FromStr`/`Display`/`Ord`
- `src/line.rs` — `parse_line()` stateless parser, `RawLine`, `LineKind`
- `src/message/` — `classify_message()` pure function, `MessageKind`, `SdpDirection`; `parts.rs` holds the positional slicers `fields/` reuses
- `src/fields/` — `Field`/`FieldKind` byte spans over raw line text, `message_fields()`, `apply_fields()`
- `src/stream/` — `LogStream` state machine, `LogEntry`, `Block`, `ParseStats`, `UnclassifiedTracking`
- `src/session/` — `SessionTracker` (`tracker.rs`), `SessionState` (`state.rs`), the secondary indexes (`index.rs`), line shapes (`parse.rs`)
- `src/codec.rs` — `CodecOffer`/`CodecMedia`, the bracketed token in codec-negotiation traces
- `src/session/conference.rs` — `ConferenceMembership`, conference join/leave detection
- `src/session/media.rs` — `SessionMedia`, negotiated/offered codecs per media type
- `src/session/loopback.rs` — mod_loopback A/B leg pairing
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

**Format D — Bare continuation (no UUID, no timestamp).** Two producers, both structural:

1. **The 100-element split cap.** `switch_split(dup, '\n', lines)` with `char *lines[100]` (`mod_logfile.c:301`) stops the moment it has filled the array, so element 99 keeps the *entire unsplit remainder* of `node->data` with its newlines intact. That element is written by one `snprintf`, so it lands as a UUID-prefixed line followed by bare ones, and the dump never resumes prefixed output. Confirmed on a live 1.10.13 build: a CHANNEL_DATA dump with 100+ variables ends after exactly 99 prefixed lines — the last one closing its `[value]` normally — then continues bare.
2. **A verbatim multi-line node.** With no session context (`zstr(node->userdata)`) or `log_uuid=false`, `mod_logfile` writes `node->data` whole, so every line of it lacks a prefix, the first included.

Inherits both UUID and timestamp from context.

**Format E — Truncated buffer collision.** `mod_logfile` formats through a fixed 2048-byte buffer *only* when it prepends a session UUID (`mod_logfile.c:298-308`):

```c
if (profile->log_uuid && !zstr(node->userdata)) {
    char buf[2048];
    argc = switch_split(dup, '\n', lines);
    for (i = 0; i < argc; i++) {
        switch_snprintf(buf, sizeof(buf), "%s %s\n", node->userdata, lines[i]);
        mod_logfile_raw_write(profile, buf);
    }
} else {
    mod_logfile_raw_write(profile, node->data);
}
```

The `else` branch has no buffer, so a record with no UUID prefix is intact at any length — production logs carry verbatim lines past 11 KB. Never read a length alone as evidence of truncation.

One `snprintf` puts at most 2047 bytes on disk. The terminating `\n` is the first thing that no longer fits, so **the longest intact physical line is 2046 bytes and a cut write is exactly 2047 with no newline** — the next write then collides on the same physical line, starting at offset 2047. Measured across 49 M writes in the fixture corpus: no intact write ever reaches 2047.

```
varia3231989a-c8fb-42c3-9078-b9d6b1482fa7 EXECUTE [depth=0] ...
```

The cut lands mid-token, so the fragment before the collision UUID varies in length. Because a write can span several physical lines (Format D case 1), the cut frequently lands on a *short* bare line rather than a long one — its physical length says nothing.

Note: truncation happens exclusively in `mod_logfile`'s UUID prepend stage, not in the core logging pipeline which uses `switch_vasprintf()` (dynamic allocation, no size limit).

### The prepend stage re-encodes every line it writes

Each element passes through `cleanup_separated_string()` (`switch_utils.c:2687`) before it is written, so a prefixed line is a rendering of the value, not the value. Verified on a live build by setting channel variables and dumping them:

- **Apostrophes pair and vanish within a line.** A value with two is logged with none; with one, the odd one survives. Across 1.9 M prefixed production lines, every line containing an apostrophe contains exactly one.
- **Backslash escapes are consumed and applied** before `'`, `"`, a newline, another backslash, or any character `unescape_char()` maps. A backslash before anything else survives.
- **Leading and trailing spaces are trimmed.**
- **Lines glue.** In the tokenizer (`switch_utils.c:2774-2778`), a backslash skips the next character and an apostrophe opens a quoted region — in both cases a newline stops being a delimiter, so two records are written as one element.

None of this is recoverable downstream. A consumer reconstructing an exact string — a caller name, a SIP header — must treat a prefixed line as lossy; only the verbatim path carries the bytes as they were.

### Log output taxonomy

Two structurally distinct output types. The `[LEVEL] source:line` marker is definitive — present means `switch_log_printf()`, absent means structured subsystem output.

**Primary log lines (Format A/B):** Every `switch_log_printf()` call goes through `switch_log_meta_vprintf()` (switch_log.c:599). When `log_uuid=true` (default), `mod_logfile` splits `node->data` by `\n` and prepends the session UUID (mod_logfile.c:298-314). A single call can produce multiple lines if its format string contains embedded `\n`:

| Source | Format | Multi-line |
|--------|--------|------------|
| mod_dptools.c:1999 | `"CHANNEL_DATA:\n%s\n"` | Yes — serialized event |
| sofia_glue.c:1676 | `"%s sending invite version: %s\nLocal SDP:\n%s\n"` | Yes — marker on line 2, then body |
| mod_sofia.c:914 | `"Local SDP %s:\n%s\n"` | Yes — SDP body |
| mod_oreka.c:121 | `"Oreka SIP Packet (...):\n%s"` | Yes — whole SIP message, no SDP marker |
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

CHANNEL_DATA (switch_event.c:1603): `"FIELDNAME: [VALUE]\n"` — multi-line values keep `[` on first line, content on subsequent lines. `switch_event.c:1587` glues `]` to the end of the last content line, so it lands on a line of its own only when the value itself ends in a newline (SDP does; an arbitrary value need not).

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

Every `LogEntry` carries both `block: Option<Block>` (typed, parsed) and `attached: AttachedLines` (raw continuation lines).

### Continuation grouping

The iterator buffers one entry at a time. A new "primary" line (Full, System, Truncated) finalizes any in-progress block, yields the buffered entry, and starts a new one. Continuation lines append to both the raw `attached` vec and the appropriate block accumulator.

UUID continuation with a *different* UUID also triggers yielding — the UUID change means a different session's output.

EXECUTE UUID continuations are treated as primary lines — they yield the previous entry and start a new one, separating execution traces from their parent CHANNEL_DATA blocks.

The iterator always yields entries one behind the current parse position. Final entry yields when the underlying iterator is exhausted.

### UUID tracking across truncated lines

Layer 1 scans the first 50 bytes for a UUID pattern — catches common short-prefix collisions. For long collisions (UUID hundreds of bytes in), Layer 1 classifies as BareContinuation. Layer 2 scans oversize lines for an embedded UUID near the expected boundary and splits there: prefix stays as continuation data, UUID+suffix becomes a separate entry, `lines_split` incremented.

That scan is a heuristic windowed on the wrong quantity — a payload budget compared against physical lengths that already carry the 37-byte prefix — and it only looks at lines long enough to trip it. The real boundary is 2047 bytes from the start of the *write*, which is exact and also reaches the common case the length test cannot see: a write spanning a prefixed line plus bare ones, cut on one of the short bare lines.

Both detected and split truncated lines are treated as primary lines — they start a new entry and update `last_uuid`.

### Unclassified data tracking

Three tiers:

- `CountOnly` — default, zero allocation. Just increments `lines_unclassified`.
- `TrackLines` — records line number and reason per unclassified line.
- `CaptureData` — like TrackLines plus actual line content.

`ParseStats` accounting invariant:

```
lines_processed + lines_split == lines_in_entries + lines_empty_orphan + lines_dropped
```

`ParseStats::unaccounted_lines()` returns the difference — non-zero indicates a parser bug.

Counters: `lines_processed` (every physical line), `lines_in_entries` (lines in entries: 1 primary + N attached), `lines_empty_orphan` (empty lines with no pending entry), `lines_split` (extra chunks from splitting a physical line that held more than one record — a cut write's successor, or write contention), `lines_dropped` (continuation lines an entry's attached buffer had no room for), `lines_unclassified` (orthogonal anomaly counter).

### Per-session state propagation

`SessionTracker` maintains `SessionState` per UUID:

- `channel_name` — from CHANNEL_DATA blocks
- `channel_state` (`CS_*`) and `call_state` — separate vocabularies, separate typed fields; neither displaces the other
- `hangup_cause`, `call_direction` — typed from `freeswitch-types`. A value none of these vocabularies knows raises `ParseWarning::UnreadableValue` on the entry and leaves the last resolved value standing
- `dialplan_context` — from dialplan processing messages; `dialplan_from`/`dialplan_to` carry the caller/dialed pair of a `Processing` line only, never a `parsing [ctx->ext]` context
- `variables: HashMap<String, String>` — all variables from CHANNEL_DATA dumps, `set()`, `export()`, variable lines. Keys have the `variable_` prefix stripped; `SessionState::variable(V: VariableName)` hides that and takes any `freeswitch-types` variable-name enum
- `conference` — name and instance from `conference()` / a transfer to an inline `conference:` extension; member id and conference UUID only when a dump supplies them
- `media` — matched codec and deduped remote offer set per media type, plus the engine's read implementation. FreeSWITCH logs no write codec at DEBUG, so none is modelled

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
- **`hooks/pre-commit` is the verification.** Run `cargo clippy --fix --allow-dirty --message-format=short && cargo fmt`, then commit and let the hook gate it. It runs `cargo fmt --check`, `cargo clippy --all-targets --features tui -D warnings`, `cargo test --release --features tui` and gitleaks — do not re-run any of those by hand
- `tui → cli → sdp`, so the hook's one test run already covers every feature the crate has. There is no `--all-features` run to add, and no `cargo build` to add
- `cargo test --release` on its own only when iterating on a failing test — never in debug, xz-compressed production fixture tests are far too slow there
- `cargo build --release --features tui` when you actually need the `fslog` binary to run against fixtures; `tui` enables the monitor subcommand (ratatui, serde, serde_yml), `sdp` gates `Block::sdp_codecs()`
- **Cargo.lock is never committed** — this is a library crate, Cargo.lock stays in .gitignore
- `fslog monitor --dump` prints the call table to stdout (no TUI), useful for testing and scripting

### Style
- Minimal dependencies (`freeswitch-types` only) — do not add crates without discussion
- No regex — all parsing is positional byte checks
- FreeSWITCH channel variable names come from `freeswitch-types`' variable enums (`ChannelVariable`, `SofiaVariable`, `CoreMediaVariable`, `LoopbackVariable`, `ConferenceVariable`), never string literals — those enums carry drift checks against FreeSWITCH source
- `pub use` re-exports in `lib.rs` for clean public API
- Every line format and edge case gets its own `#[test]`
- Tests use realistic but fictional log lines that exercise the exact byte positions the parser checks

### Semver and `#[non_exhaustive]`
- Public enums that are likely to grow get `#[non_exhaustive]` so adding variants is not a breaking change
- Currently marked: `MessageKind`, `Block`, `LineKind`, `UnclassifiedReason`, `SipInviteDirection`, `Utf8Decode`, `DtmfSource`, `CodecMedia`, `CodecOffer`, `CodecParseError`, `FieldKind`, `RenderError`, `ParseWarning`, `SessionReading`, `BridgeInfo`, `CodecImpl`, `SessionState`, `SessionSnapshot`, `RegexCondition`
- `CodecOffer` being `#[non_exhaustive]` means the binary cannot build one literally — construct via `CodecOffer::parse`, including in tests. `SessionState`/`SessionSnapshot` are the same: build one from a tracker, or from `Default` plus field assignment. Hooks still get plain `&mut` field access
- `LogEntry` is not marked, but `LogEntry::synthetic` exists so a consumer needing one does not spell out every field
- NOT marked: `SdpDirection` (small fixed set, downstream match is valuable), `LogLevel` (fixed syslog levels with Ord), `UnclassifiedTracking` (fixed tiers), `FieldLocation` (message or attached, nothing else exists), `Field` (consumers construct their own to feed `apply_fields`)
- New public enums should be `#[non_exhaustive]` by default unless the set is definitively closed
