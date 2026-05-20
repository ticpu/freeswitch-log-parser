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

**Layer 3** maintains per-UUID session state (dialplan context, channel
state, learned variables, call direction, caller/destination numbers)
and propagates it across entries. Also links bridged a-leg ↔ b-leg
sessions via `other_leg_uuid` — from the explicit `Peer UUID:` suffix
when present, or by matching a live b-leg `channel_name` when
FreeSWITCH omits it. Yields `EnrichedEntry` with a `SessionSnapshot`
alongside the raw `LogEntry`.

Each layer wraps the previous and can be used independently.

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
    .with_relationship_hook(|entry, state| {
        // Check entry.message_kind, state.variables, etc.
        // Set state.other_leg_uuid if pattern matches
    });
```

See `examples/custom_relationship.rs` for a complete example.

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

The crate also ships an `fslog` CLI for searching and tailing logs.
Build with `cargo build --release --features cli` (search/filter) or
`--features tui` (adds the `monitor` subcommand with a ratatui call
table). The library itself has no CLI dependencies unless a feature is
enabled.

## License

LGPL-2.1-or-later
