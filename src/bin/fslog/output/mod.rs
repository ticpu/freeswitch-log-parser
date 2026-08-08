//! Terminal output — colouring, entry rendering, and filtering.

mod color;
mod filter;
mod printer;
#[cfg(test)]
pub mod tests;

pub use filter::{FilterConfig, FilterParams, Hidden, Verdict};
pub use printer::EntryPrinter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Always,
    Never,
}
