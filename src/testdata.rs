//! Shared fixtures for tests across `stream` and `session`.

pub const UUID1: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
pub const UUID2: &str = "b2c3d4e5-f6a7-8901-bcde-f12345678901";
pub const TS1: &str = "2025-01-15 10:30:45.123456";
pub const TS2: &str = "2025-01-15 10:30:46.234567";

pub fn full_line(uuid: &str, ts: &str, msg: &str) -> String {
    format!("{uuid} {ts} 95.97% [DEBUG] sofia.c:100 {msg}")
}
