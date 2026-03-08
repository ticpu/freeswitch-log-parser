# freeswitch-log-parser

Rust library for parsing FreeSWITCH log files. Three-layer streaming
architecture with zero dependencies and no regex.

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
values, and classifies messages into semantic types (Execute, Dialplan,
Variable, ChannelField, SdpMarker, StateChange, General). Every entry
carries both a typed `Block` and raw `attached` lines.

**Layer 3** maintains per-UUID session state (dialplan context, channel
state, learned variables) and propagates it across entries. Yields
`EnrichedEntry` with a `SessionSnapshot` alongside the raw `LogEntry`.

Each layer wraps the previous and can be used independently.

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

## License

LGPL-2.1-or-later
