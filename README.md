# freeswitch-log-parser

[![CI](https://github.com/ticpu/freeswitch-log-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/ticpu/freeswitch-log-parser/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/ticpu/5d6e27e07995772a5bf424d4cf51e608/raw/test-count.json)](https://github.com/ticpu/freeswitch-log-parser/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/freeswitch-log-parser)](https://crates.io/crates/freeswitch-log-parser)
[![docs.rs](https://img.shields.io/docsrs/freeswitch-log-parser)](https://docs.rs/freeswitch-log-parser)
[![license](https://img.shields.io/crates/l/freeswitch-log-parser)](https://github.com/ticpu/freeswitch-log-parser/blob/master/LICENSE)

Rust library for parsing FreeSWITCH log files. Three-layer streaming
architecture, no regex, single runtime dependency (`freeswitch-types`
for typed enums).

## Layers

```
Layer 1: parse_line()       &str -> RawLine        (stateless, zero-alloc)
Layer 2: LogStream          Iterator -> LogEntry    (structural state machine)
Layer 3: SessionTracker     LogStream -> EnrichedEntry (per-UUID state)
```

**Layer 1** classifies individual log lines into five formats (Full,
System, UuidContinuation, BareContinuation, Truncated) and extracts
positional fields (UUID, timestamp, log level, source, message).

**Layer 2** groups continuation lines, detects block boundaries
(CHANNEL_DATA dumps, SDP bodies), reassembles multi-line variable
values, and classifies messages into semantic `MessageKind` variants:
`Execute`, `Dialplan`, `ChannelData`, `ChannelField`, `Variable`,
`SdpMarker`, `StateChange`, `CodecNegotiation`, `Media`,
`ChannelLifecycle`, `SipInvite`, `EventSocket`, `General`, plus the
synthetic `FileChange`/`DateChange` markers. `SipInvite` is the
canonical `sip_call_id ↔ channel_uuid` correlation primitive — sofia
emits it for every inbound and outbound call regardless of dialplan.
Every entry carries both a typed `Block` and raw `attached` lines.

Codec negotiation blocks are typed per media type: audio and video traces
carry different fields and never share a block, and near-match verdicts are
recorded rather than treated as parse failures. With the `sdp` feature,
`Block::sdp_codecs()` parses an SDP body on demand through
`freeswitch-types` — the only place text and DTMF payloads appear, since the
negotiation trace never mentions them. It is off by default so a Layer 2
consumer keeps the crate's minimal dependency tree; `fslog` enables it.

**Layer 3** maintains per-UUID session state (dialplan context, channel
state, learned variables, call direction, caller/destination numbers,
negotiated codecs per media type)
and propagates it across entries. Also links bridged a-leg ↔ b-leg
sessions via `other_leg_uuid` — from the explicit `Peer UUID:` suffix
when present, by matching a live b-leg `channel_name` when FreeSWITCH
omits it, or by mod_loopback's A/B leg naming. Conference membership is
tracked per conference instance, so a name reused by a later conference
does not merge the two; `SessionTracker::conference_members` lists an
instance's UUIDs. `SessionState::variable` reads a learned variable by
typed name, taking any of `freeswitch-types`' variable-name enums. Yields
`EnrichedEntry` with a `SessionSnapshot` alongside the raw `LogEntry`.

Each layer wraps the previous and can be used independently.

Alongside them the crate exposes the primitives a consumer would
otherwise re-derive: `find_uuids`/`is_uuid` locate channel UUIDs inside a
message or a needle without a regex, `for_each_peer_uuid` walks the
channel variables that name another leg (`for_each_peer_uuid_with` takes a
predicate for names a deployment adds), `parse_bridge_args` reads a
`bridge()` argument list, and `log_rotation_stamp`/`normalize_entry_timestamp`
put a rotated filename and an entry timestamp into one comparable form.

## Performance

Built to handle the worst `mod_logfile` produces — 2 KiB buffer
truncations, multi-line CHANNEL_DATA dumps with embedded SDP/XML,
write-contention collisions. An 11 MB fixture (185 physical lines
averaging ~60 KB each) parses in ~60 ms. `LogEntry::attached` uses
a compact contiguous buffer (`AttachedLines`) instead of
`Vec<String>` to amortize allocations on CHANNEL_DATA-heavy entries
— iteration via `&entry.attached` works unchanged.

## Usage

```rust
use std::io::{self, BufRead};
use freeswitch_log_parser::{LogStream, SessionTracker};

let lines = io::stdin().lock().lines().map(|l| l.unwrap());
let stream = LogStream::new(lines);

for enriched in SessionTracker::new(stream) {
    let entry = &enriched.entry;
    println!("{} {} {}", entry.uuid, entry.message_kind, entry.message);
    if let Some(session) = &enriched.session {
        if let Some(ctx) = &session.dialplan_context {
            println!("  context: {ctx}");
        }
    }
}
```

## Unclassified data tracking

Lines that can't be fully classified are tracked, never silently dropped:

```rust
use freeswitch_log_parser::{LogStream, UnclassifiedTracking};

let mut stream = LogStream::new(lines)
    .unclassified_tracking(UnclassifiedTracking::TrackLines);

for entry in stream.by_ref() { /* ... */ }

let stats = stream.stats();
eprintln!("{} lines, {} unclassified",
    stats.lines_processed, stats.lines_unclassified);
```

## Custom relationship detection

The built-in leg linking handles standard FreeSWITCH patterns. For
application-specific patterns (Lua API results, custom SIP headers),
register a hook:

```rust
let tracker = SessionTracker::new(stream)
    .with_post_hook(|entry, state| {
        // Check entry.message_kind, state.variables, etc.
        // Set state.other_leg_uuid if pattern matches
    });
```

A pre-hook (`with_pre_hook`) runs before built-in detection, so state it
seeds is visible to the built-in patterns of the same entry.

See `examples/custom_hooks.rs` for a complete example.

## Multi-file input with segment tracking

`TrackedChain` concatenates named input segments (typically rotated log
files) into a single iterator and records where each segment starts.
`SegmentTracker` then maps any line number back to its source file —
useful for emitting `FileChange` markers or reporting errors with the
original filename:

```rust
use freeswitch_log_parser::{LogStream, TrackedChain};

let segments = vec![
    ("freeswitch.log.1".into(), open_xz("freeswitch.log.1.xz")),
    ("freeswitch.log".into(), open_plain("freeswitch.log")),
];
let (chain, tracker) = TrackedChain::new(segments);
let stream = LogStream::new(chain);
// ... consume stream; query tracker.segment_for_line(n) as needed.
```

## `fslog` binary

The crate ships an `fslog` CLI that turns the parser into a log-search
tool: structured, UUID-aware, and able to follow a call across its
bridged and transferred legs. It reads rotated `.xz` files directly and
chains them in date order, so a single query spans the whole retention
window.

![fslog rendering one call with --blocks](https://raw.githubusercontent.com/ticpu/freeswitch-log-parser/master/docs/fslog-demo.webp)

*`fslog read docs/demo.log --blocks` — one synthetic call, start to hangup.*

### Install

Each release carries an `amd64` and an `arm64` `.deb` (binary plus
bash/zsh/fish completions), the same binaries standalone, and
`SHA256SUMS`:

```
curl -LO https://github.com/ticpu/freeswitch-log-parser/releases/latest/download/fslog_<version>_amd64.deb
sudo dpkg -i fslog_<version>_amd64.deb
```

They are built in a Debian bullseye container, so they run on any glibc
2.30 or newer — Debian 11+, Ubuntu 20.04+, RHEL 9+ — and need only
`liblzma5` beyond libc. `make deb` reproduces them locally with podman
(`DEB_ARCH=arm64` for the other architecture).

From source, build with `cargo build --release --features cli` for
everything below, or `--features tui` to also get the `monitor`
dashboard. The library itself pulls no CLI dependencies unless a feature
is enabled.

### Commands

| Command | Purpose |
|---------|---------|
| `fslog list` | List discovered log files with dates and sizes |
| `fslog search` | Filter entries across many files (date range, UUID, level, pattern) |
| `fslog read [FILE]` | Parse a single file (or stdin with `-`) |
| `fslog tail [FILE]` | Follow a file live, parsed and colorized |
| `fslog monitor` | Live TUI call table (requires `--features tui`) |
| `fslog completions <SHELL>` | Emit a shell completion script |

Global flags: `--dir <PATH>` (or `FSLOG_DIR`, default
`/var/log/freeswitch`), `--color auto|always|never`, `--pager` (alias
`--less`), `--version`.

Output goes straight to stdout unless `--pager` is given, and the pager is
started only once there is something to show, so an empty search never leaves
`less` holding the terminal. `FSLOG_PAGER` overrides the command (default
`less -RFX`); `tail` and `completions` never page.

### `search`

```
fslog search [OPTIONS] [PATTERN]
```

`PATTERN` is a case-insensitive fixed-string shorthand for `--fgrep`.

Filtering:

- `-u, --uuid <UUID>` — session UUID substring, matched against the channel-UUID column; repeat for OR matching
- `-l, --level <LEVEL>` — minimum severity (`debug`…`console`)
- `-c, --category <KIND>` — message kind (`execute`, `dialplan`, `media`, …); repeat for OR matching
- `--fgrep <PATTERN>` — case-insensitive fixed-string match on the message
- `--grep <REGEX>` — regex match on the message
- `--codec <NAME>` — codec named in a negotiation or SDP block, case-insensitive; repeat for OR matching
- `--match-blocks` — also match `--fgrep`/`--grep`/`PATTERN` inside attached block lines (SDP, CHANNEL_DATA, codec negotiation), not just the message
- `--related` — expand matching sessions to their bridged/transferred peer legs (originate, `bridge()`, `uuid_bridge`, `Other-Leg-Unique-ID`, peer-UUID channel variables, mod_loopback A/B legs) and to everyone in the same conference

Pattern search reads the message field; `-u` reads the channel-UUID column.
Neither reaches the other's, so `--grep <uuid>` shows only the lines that *name*
the session and `-u <uuid>` only the lines it *produced*. Entries kept out by
that boundary alone are counted and reported on stderr at end of run, with the
flag — and where the pattern names a UUID, the command — that widens to them:

```
$ fslog read --grep 393d8167-062d-4652-b86e-c4e0acf488ff
17:03:56.190807  notice 393d8167-…88ff [channel-lifecycle] New Channel sofia/…
note: 49 more entries carry this pattern in the channel-UUID column, which --grep does not search
hint: rerun with -u 393d8167-062d-4652-b86e-c4e0acf488ff
```

Context (grep-style), with `--` dividers between non-contiguous groups:

- `-A, --after-context <N>`, `-B, --before-context <N>`, `-C, --context <N>`

Output and selection:

- `--blocks` — expand structured content inline (see below)
- `--session` — annotate each entry with tracked state (context, channel state, channel name, conference and member id)
- `--stats` / `--unclassified` — summary and unclassified-line report
- `-n, --line-numbers` — show physical line numbers
- `--from <DATE>` / `--until <DATE>` — bound discovery (progressive: `2026-03`, `2026-03-08`, `2026-03-08T15:48`)
- `--on <DATE>` — a single day; `--today` — today, in the machine's local timezone
- `--file <FILE>` — scan explicit files instead of date discovery (repeatable)
- `-y, --yes` — skip the confirmation prompt for large scans

### Reading the output

Each entry is one line — time, level, UUID, message kind, message —
followed by whatever structure it carries. Time and level share the level's
color, so a run of one severity reads as a band down the left edge.

UUIDs get a stable per-call truecolor, in the UUID column and wherever one
appears inside a message or a continuation line, so a bridge target is the
same color as the leg it names.

Continuation lines the parser did not fold into a typed block — dialplan
condition traces, EXECUTE output — print inline under `--blocks`, with
`(PASS)` and `(FAIL)` verdicts colored. Without `--blocks` they collapse to
a count, unless there is only one.

A dialplan block prints its channel once, on the header, and every line
under it starts with what differs:

```
19:06:09.550802    info 9865d278-…78f2 [dialplan] Dialplan: sofia/internal/1262@pbx:5062
         parsing [default->unloop] continue=false
         Regex (PASS) [unloop] ${unroll_loops}(true) =~ /^true$/ break=on-false
         Regex (FAIL) [unloop] ${sip_looped_call}() =~ /^true$/ break=on-false
         Action set(call_debug=false)
```

`--blocks` also expands:

- **CHANNEL_DATA** — every field and variable, values in full
- **SDP** — the body, tagged local or remote
- **Codec negotiation** — offered-versus-local comparisons and what matched
- **Dial strings** — `bridge()` and `att_xfer()` arguments broken into their
  global variables, failover groups and endpoints, with `ARRAY::` values
  split into entries and `presence_id` surfaced as the extension

### Speed

`search` decompresses and parses only what it must. When the search term is
a full UUID or a SIP Call-ID — identifiers that cannot span a line break —
candidate files are scanned for the raw bytes in parallel first, and those
that cannot match are never parsed. Free-text and regex searches read
everything, because a match there can legitimately span an entry and the
continuation lines the parser reassembles into it.

Scanning a large set prompts first; `-y` skips the prompt, and
`FSLOG_CONFIRM_SIZE` (bytes) moves the threshold. When nothing matches,
`search` reports the span of log files on hand, so "not in these logs" is
distinguishable from "already rotated away".

### Examples

```sh
# Follow one call across all its legs, with session state
fslog search --from 2026-03-08 -u 9bee8676 --related --session

# grep a string with two lines of context on each side
fslog search --from 2026-03-08 'receiving invite' -C 2

# Find calls by an SDP attribute that only appears in the media block
fslog search --from 2026-03-08 --grep 'm=audio' --match-blocks --blocks

# Every leg that negotiated or was offered opus, with the codec detail
fslog search --from 2026-03-08 --codec opus --blocks

# Errors and worse from one session, expanding structured blocks
fslog search --from 2026-03-08 -u 9bee8676 -l err --blocks

# Today's dialplan and execute traces, expanded
fslog search --today -c dialplan -c execute --blocks
```

## Related crates

FreeSWITCH and SIP crates by the same author, usable independently:

- [`freeswitch-types`](https://crates.io/crates/freeswitch-types) — typed
  FreeSWITCH enums (call direction, channel/call state, hangup causes). This
  crate's only runtime dependency.
- [`freeswitch-sofia-trace-parser`](https://crates.io/crates/freeswitch-sofia-trace-parser)
  — parses sofia's `tport` SIP traces. Complements this crate: `fslog` gives you
  the channel-level view, the trace parser gives you the SIP messages behind it.
- [`freeswitch-esl-tokio`](https://crates.io/crates/freeswitch-esl-tokio) — async
  ESL client, for reading events off a live switch rather than off its logs.
- [`sip-uri`](https://crates.io/crates/sip-uri) — RFC 3261 SIP/SIPS, RFC 3966
  `tel:`, RFC 8141 URN parser. Zero dependencies.
- [`sip-header`](https://crates.io/crates/sip-header) — SIP header field parsers
  (name-addr, Call-Info, History-Info, Geolocation, conference-info).

## License

LGPL-2.1-or-later
