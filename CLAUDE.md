# Claude Code Development Notes

## Project Overview

Library crate for parsing FreeSWITCH log files. Three-layer design:
- **Layer 1**: Stateless line parser (`parse_line`) — classifies individual lines, extracts fields
- **Layer 2**: Structural state machine (`LogStream`) — groups continuations, classifies messages (`MessageKind`), detects block boundaries (CHANNEL_DATA, SDP), tracks unclassified lines
- **Layer 3**: Per-session state machine (`SessionTracker`) — tracks per-UUID state (dialplan context, channel state, variables), propagates context across entries

Zero dependencies. No regex — all positional byte parsing.

## Architecture

See `docs/design-rationale.md` for full design prose including the five line formats (A-E), why no regex, block detection, unclassified data tracking, and session state propagation.

### Key Files
- `src/level.rs` — `LogLevel` enum with `FromStr`/`Display`/`Ord`
- `src/line.rs` — `parse_line()` stateless parser, `RawLine`, `LineKind`
- `src/message.rs` — `classify_message()` pure function, `MessageKind`, `SdpDirection`
- `src/stream.rs` — `LogStream` state machine, `LogEntry`, `Block`, `ParseStats`, `UnclassifiedTracking`
- `src/session.rs` — `SessionTracker`, `SessionState`, `EnrichedEntry`, `SessionSnapshot`
- `src/lib.rs` — public API re-exports

## Test Data

Use RFC 5737 IPs (192.0.2.x, 198.51.100.x) and RFC 3849 IPv6 (2001:db8::/32) in tests.
Use fictional UUIDs — generate consistent ones for test fixtures.
Never copy production log lines verbatim into source.

## Rust Guidelines

### Workflow
- `cargo check --message-format=short` → `cargo clippy --fix --allow-dirty --message-format=short` → `cargo fmt --all` → `cargo test -- --quiet`
- Production fixture tests (`tests/production_log.rs`) must be run with `--release` for performance — debug builds are too slow on large xz-compressed logs

### Style
- Zero dependencies — do not add crates without discussion
- No regex — all parsing is positional byte checks
- `pub use` re-exports in `lib.rs` for clean public API
- Every line format and edge case gets its own `#[test]`
- Tests use realistic but fictional log lines that exercise the exact byte positions the parser checks
