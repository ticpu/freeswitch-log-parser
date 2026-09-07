//! The command-line surface: clap types, and the colour and filter objects
//! built from them.

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};

use freeswitch_log_parser::{
    stamp_lower_bound, stamp_upper_bound, LogLevel, MessageKind, UnclassifiedTracking,
};

use crate::files::DEFAULT_MAX_LINE_BYTES;

use crate::output::{ColorMode, EntryPrinter, FilterConfig, FilterParams};

#[derive(Clone, Copy, ValueEnum)]
pub enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Parser)]
#[command(name = "fslog", version, about = "FreeSWITCH log file query tool")]
pub struct Cli {
    /// Log directory
    #[arg(long, default_value = "/var/log/freeswitch", env = "FSLOG_DIR")]
    pub dir: PathBuf,

    /// Color output: auto, always, never
    #[arg(long, default_value = "auto", value_enum)]
    pub color: ColorWhen,

    /// Pipe output through a pager (`$FSLOG_PAGER`, default `less -RFX`)
    #[arg(long, visible_alias = "less")]
    pub pager: bool,

    /// Bytes of one physical line to read before dropping its remainder
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_LINE_BYTES)]
    pub max_line_bytes: usize,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List log files with dates and sizes
    List,

    /// Search/filter entries across multiple files
    Search(SearchArgs),

    /// Parse and display a single log file
    Read(ReadArgs),

    /// Follow the log file and display new entries in color
    Tail(TailArgs),

    /// Live TUI dashboard of active calls
    #[cfg(feature = "tui")]
    Monitor(crate::monitor::MonitorArgs),

    /// Generate shell completion script
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::aot::Shell,
    },
}

#[derive(clap::Args, Default)]
pub struct FilterArgs {
    /// UUID substring filter (case-insensitive, repeatable, OR logic)
    ///
    /// Matches the channel-UUID column only — the session that produced the
    /// line, not every line naming it. A peer leg's bridge line, an
    /// Other-Leg-Unique-ID field or a system line mentioning the UUID belongs
    /// to another session and is not shown; `--related` follows those legs.
    #[arg(short, long, value_name = "UUID")]
    pub uuid: Vec<String>,

    /// Minimum log level
    #[arg(short, long, value_name = "LEVEL", value_parser = parse_level)]
    pub level: Option<LogLevel>,

    /// Message category filter (repeatable, OR logic)
    #[arg(short, long, value_name = "KIND", value_parser = parse_category)]
    pub category: Vec<String>,

    /// Fixed string substring search (case-insensitive)
    ///
    /// Searches the same field --grep does; see its --help for the scope.
    #[arg(long, value_name = "PATTERN")]
    pub fgrep: Option<String>,

    /// Regex pattern search
    ///
    /// Matches the message text only. The parser splits a log line into
    /// `uuid | timestamp | [LEVEL] | source.c:line | message`, and this
    /// searches the last field — not the channel-UUID column, and not the
    /// attached block lines (dialplan regexes, CHANNEL_DATA dumps, SDP) unless
    /// --match-blocks is given. That is deliberate: a term found in a dialplan
    /// regex is the configuration mentioning it, not the call. Entries a
    /// narrower scope kept out are counted and reported on stderr at end of run.
    #[arg(long, value_name = "PATTERN", value_parser = parse_regex)]
    pub grep: Option<regex::Regex>,

    /// Codec name in a negotiation or SDP block (repeatable, OR logic)
    #[arg(long, value_name = "NAME")]
    pub codec: Vec<String>,

    /// Also match --fgrep/--grep/PATTERN inside attached block lines (SDP, CHANNEL_DATA)
    ///
    /// Widens the pattern scope; see --grep's --help for what it is by default.
    #[arg(long)]
    pub match_blocks: bool,

    /// Expand structured blocks inline (CHANNEL_DATA fields/variables, SDP bodies, codec negotiation)
    #[arg(long)]
    pub blocks: bool,

    /// Annotate entries with tracked session state (dialplan context, channel state, channel name)
    #[arg(long)]
    pub session: bool,

    /// Summary only, no per-entry output
    #[arg(long)]
    pub stats: bool,

    /// Report unclassified lines
    #[arg(long)]
    pub unclassified: bool,

    /// Show line numbers in output
    #[arg(short = 'n', long)]
    pub line_numbers: bool,
}

impl FilterArgs {
    pub fn tracking(&self) -> UnclassifiedTracking {
        if self.unclassified {
            UnclassifiedTracking::CaptureData
        } else {
            UnclassifiedTracking::CountOnly
        }
    }

    pub fn printer(&self, color: ColorMode) -> EntryPrinter {
        EntryPrinter {
            color,
            show_blocks: self.blocks,
            show_session: self.session,
            show_line_numbers: self.line_numbers,
        }
    }
}

#[derive(clap::Args)]
pub struct SearchArgs {
    /// Start date (progressive tab-complete from filenames)
    #[arg(long)]
    pub from: Option<String>,

    /// End date (progressive tab-complete from filenames)
    #[arg(long)]
    pub until: Option<String>,

    /// A single date, shorthand for --from DATE --until DATE
    #[arg(long, value_name = "DATE", conflicts_with_all = ["from", "until"])]
    pub on: Option<String>,

    /// Today only, in the machine's local timezone
    #[arg(long, conflicts_with_all = ["from", "until", "on"])]
    pub today: bool,

    /// Skip confirmation prompt for large file sets
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Lines of context to show after each match
    #[arg(short = 'A', long, value_name = "N", default_value = "0")]
    pub after_context: usize,

    /// Lines of context to show before each match
    #[arg(short = 'B', long, value_name = "N", default_value = "0")]
    pub before_context: usize,

    /// Lines of context before and after each match (sets both -A and -B)
    #[arg(short = 'C', long, value_name = "N")]
    pub context: Option<usize>,

    /// Expand to bridged/transferred peer legs of matching sessions
    #[arg(long)]
    pub related: bool,

    #[command(flatten)]
    pub filter: FilterArgs,

    /// Fixed-string pattern (case-insensitive); shorthand for --fgrep
    ///
    /// Searches the same field --grep does; see its --help for the scope.
    #[arg(value_name = "PATTERN")]
    pub pattern: Option<String>,

    /// Explicit files to scan (overrides --from/--until auto-discovery)
    #[arg(long = "file", value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

impl SearchArgs {
    pub fn before(&self) -> usize {
        self.context.unwrap_or(self.before_context)
    }
    pub fn after(&self) -> usize {
        self.context.unwrap_or(self.after_context)
    }

    /// Resolve the date bounds, collapsing the `--on`/`--today` shorthands into
    /// the same pair of partial dates `--from`/`--until` supply.
    pub fn window(&self) -> (Option<String>, Option<String>) {
        if self.today {
            let today = jiff::Zoned::now().date().to_string();
            return (Some(today.clone()), Some(today));
        }
        if let Some(on) = &self.on {
            return (Some(on.clone()), Some(on.clone()));
        }
        (self.from.clone(), self.until.clone())
    }
}

#[derive(clap::Args)]
pub struct ReadArgs {
    #[command(flatten)]
    pub filter: FilterArgs,

    /// Log file to read (default: freeswitch.log in --dir, or stdin if `-`)
    #[arg(value_name = "FILE")]
    pub file: Option<String>,
}

#[derive(clap::Args)]
pub struct TailArgs {
    #[command(flatten)]
    pub filter: FilterArgs,

    /// Number of recent lines to show initially
    #[arg(long, default_value = "50")]
    pub lines: usize,

    /// Log file to tail (default: freeswitch.log in --dir)
    #[arg(value_name = "FILE")]
    pub file: Option<String>,
}

/// Paging does not change this: the process keeps the terminal on its own
/// stdout, only the pager's stdin is a pipe.
pub fn resolve_color(when: ColorWhen) -> ColorMode {
    match when {
        ColorWhen::Always => ColorMode::Always,
        ColorWhen::Never => ColorMode::Never,
        ColorWhen::Auto => {
            if io::stdout().is_terminal() {
                ColorMode::Always
            } else {
                ColorMode::Never
            }
        }
    }
}

fn level_labels() -> Vec<&'static str> {
    LogLevel::ALL
        .iter()
        .filter(|l| **l != LogLevel::Disable)
        .map(LogLevel::as_str)
        .collect()
}

fn parse_level(s: &str) -> Result<LogLevel, String> {
    match s.to_ascii_lowercase().parse::<LogLevel>() {
        Ok(LogLevel::Disable) => Err(format!(
            "disable is the switch's \"log nothing\" sentinel, not a severity; \
             valid levels are {}",
            level_labels().join(", ")
        )),
        Err(_) => Err(format!(
            "{s} is not a log level; valid levels are {}",
            level_labels().join(", ")
        )),
        Ok(level) => Ok(level),
    }
}

fn parse_category(s: &str) -> Result<String, String> {
    if MessageKind::ALL_LABELS.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "valid categories are {}",
            MessageKind::ALL_LABELS.join(", ")
        ))
    }
}

fn parse_regex(s: &str) -> Result<regex::Regex, regex::Error> {
    regex::Regex::new(s)
}

pub fn build_filter(
    filter: &FilterArgs,
    from: Option<&str>,
    until: Option<&str>,
) -> anyhow::Result<FilterConfig> {
    FilterConfig::new(FilterParams {
        uuid: filter.uuid.clone(),
        uuid_strict: true,
        match_blocks: filter.match_blocks,
        min_level: filter.level,
        category: filter.category.clone(),
        fgrep: filter.fgrep.clone(),
        grep: filter.grep.clone(),
        codec: filter.codec.clone(),
        from_ts: from.map(stamp_lower_bound),
        until_ts: until.map(stamp_upper_bound),
    })
    .context("building the entry filter")
}
