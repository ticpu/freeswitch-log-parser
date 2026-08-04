mod complete;
#[cfg(feature = "tui")]
mod config;
mod context;
mod dialstring;
mod files;
#[cfg(feature = "tui")]
mod monitor;
mod output;
mod prescan;
mod related;

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use log::warn;

use freeswitch_log_parser::{
    AttachedLines, LineKind, LogEntry, LogLevel, LogStream, MessageKind, ParseStats,
    SessionTracker, TrackedChain, UnclassifiedTracking,
};

use context::Emitter;

use files::{
    discover_log_files, filter_files_by_date, format_size, lazy_log_reader, lossy_line_iter,
    normalize_date_from, normalize_date_until, open_log_reader, open_tail_reader, resolve_log_path,
};
use output::{ColorMode, EntryPrinter, FilterConfig, FilterParams};

#[derive(Clone, Copy, ValueEnum)]
enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Parser)]
#[command(name = "fslog", about = "FreeSWITCH log file query tool")]
struct Cli {
    /// Log directory
    #[arg(long, default_value = "/var/log/freeswitch", env = "FSLOG_DIR")]
    dir: PathBuf,

    /// Color output: auto, always, never
    #[arg(long, default_value = "auto", value_enum)]
    color: ColorWhen,

    /// Disable auto-pager
    #[arg(long)]
    no_pager: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    Monitor(monitor::MonitorArgs),

    /// Generate shell completion script
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::aot::Shell,
    },
}

#[derive(clap::Args)]
struct FilterArgs {
    /// UUID substring filter (case-insensitive, repeatable, OR logic)
    #[arg(short, long, value_name = "UUID")]
    uuid: Vec<String>,

    /// Minimum log level
    #[arg(short, long, value_name = "LEVEL")]
    level: Option<String>,

    /// Message category filter (repeatable, OR logic)
    #[arg(short, long, value_name = "KIND")]
    category: Vec<String>,

    /// Fixed string substring search (case-insensitive)
    #[arg(long, value_name = "PATTERN")]
    fgrep: Option<String>,

    /// Regex pattern search
    #[arg(long, value_name = "PATTERN")]
    grep: Option<String>,

    /// Also match --fgrep/--grep/PATTERN inside attached block lines (SDP, CHANNEL_DATA)
    #[arg(long)]
    match_blocks: bool,

    /// Expand structured blocks inline (CHANNEL_DATA fields/variables, SDP bodies, codec negotiation)
    #[arg(long)]
    blocks: bool,

    /// Annotate entries with tracked session state (dialplan context, channel state, channel name)
    #[arg(long)]
    session: bool,

    /// Summary only, no per-entry output
    #[arg(long)]
    stats: bool,

    /// Report unclassified lines
    #[arg(long)]
    unclassified: bool,

    /// Show line numbers in output
    #[arg(short = 'n', long)]
    line_numbers: bool,
}

impl FilterArgs {
    fn tracking(&self) -> UnclassifiedTracking {
        if self.unclassified {
            UnclassifiedTracking::CaptureData
        } else {
            UnclassifiedTracking::CountOnly
        }
    }

    fn printer(&self, color: ColorMode) -> EntryPrinter {
        EntryPrinter {
            color,
            show_blocks: self.blocks,
            show_session: self.session,
            show_filename: false,
            show_line_numbers: self.line_numbers,
        }
    }
}

/// Stats/unclassified epilogue on stderr, shared by search and read.
fn print_epilogue(
    printer: &EntryPrinter,
    fargs: &FilterArgs,
    stats: &ParseStats,
    count: u64,
    session_count: usize,
) -> io::Result<()> {
    if fargs.stats || fargs.unclassified {
        printer.print_stats(&mut io::stderr(), stats, count, session_count)?;
    }
    if fargs.unclassified {
        printer.print_unclassified(&mut io::stderr(), stats)?;
    }
    Ok(())
}

#[derive(clap::Args)]
struct SearchArgs {
    /// Start date (progressive tab-complete from filenames)
    #[arg(long)]
    from: Option<String>,

    /// End date (progressive tab-complete from filenames)
    #[arg(long)]
    until: Option<String>,

    /// A single date, shorthand for --from DATE --until DATE
    #[arg(long, value_name = "DATE", conflicts_with_all = ["from", "until"])]
    on: Option<String>,

    /// Today only, in the machine's local timezone
    #[arg(long, conflicts_with_all = ["from", "until", "on"])]
    today: bool,

    /// Skip confirmation prompt for large file sets
    #[arg(short = 'y', long)]
    yes: bool,

    /// Lines of context to show after each match
    #[arg(short = 'A', long, value_name = "N", default_value = "0")]
    after_context: usize,

    /// Lines of context to show before each match
    #[arg(short = 'B', long, value_name = "N", default_value = "0")]
    before_context: usize,

    /// Lines of context before and after each match (sets both -A and -B)
    #[arg(short = 'C', long, value_name = "N")]
    context: Option<usize>,

    /// Expand to bridged/transferred peer legs of matching sessions
    #[arg(long)]
    related: bool,

    #[command(flatten)]
    filter: FilterArgs,

    /// Fixed-string pattern (case-insensitive); shorthand for --fgrep
    #[arg(value_name = "PATTERN")]
    pattern: Option<String>,

    /// Explicit files to scan (overrides --from/--until auto-discovery)
    #[arg(long = "file", value_name = "FILE")]
    files: Vec<PathBuf>,
}

impl SearchArgs {
    fn before(&self) -> usize {
        self.context.unwrap_or(self.before_context)
    }
    fn after(&self) -> usize {
        self.context.unwrap_or(self.after_context)
    }

    /// Resolve the date bounds, collapsing the `--on`/`--today` shorthands into
    /// the same pair of partial dates `--from`/`--until` supply.
    fn window(&self) -> io::Result<(Option<String>, Option<String>)> {
        if self.today {
            let today = jiff::Zoned::now().date().to_string();
            return Ok((Some(today.clone()), Some(today)));
        }
        if let Some(on) = &self.on {
            return Ok((Some(on.clone()), Some(on.clone())));
        }
        Ok((self.from.clone(), self.until.clone()))
    }
}

#[derive(clap::Args)]
struct ReadArgs {
    #[command(flatten)]
    filter: FilterArgs,

    /// Log file to read (default: freeswitch.log in --dir, or stdin if `-`)
    #[arg(value_name = "FILE")]
    file: Option<String>,
}

#[derive(clap::Args)]
struct TailArgs {
    #[command(flatten)]
    filter: FilterArgs,

    /// Number of recent lines to show initially
    #[arg(long, default_value = "50")]
    lines: usize,

    /// Log file to tail (default: freeswitch.log in --dir)
    #[arg(value_name = "FILE")]
    file: Option<String>,
}

fn resolve_color(when: ColorWhen, use_pager: bool) -> ColorMode {
    match when {
        ColorWhen::Always => ColorMode::Always,
        ColorWhen::Never => ColorMode::Never,
        ColorWhen::Auto => {
            if use_pager || io::stdout().is_terminal() {
                ColorMode::Always
            } else {
                ColorMode::Never
            }
        }
    }
}

fn build_filter(filter: &FilterArgs, from: Option<&str>, until: Option<&str>) -> FilterConfig {
    let min_level: Option<LogLevel> = filter.level.as_ref().map(|l| {
        l.parse().unwrap_or_else(|_| {
            eprintln!("invalid log level: {l}");
            eprintln!("valid levels: {}", LogLevel::ALL_LABELS.join(", "));
            process::exit(2);
        })
    });

    for cat in &filter.category {
        if !MessageKind::ALL_LABELS.contains(&cat.as_str()) {
            eprintln!("invalid category: {cat}");
            eprintln!("valid categories: {}", MessageKind::ALL_LABELS.join(", "));
            process::exit(2);
        }
    }

    let grep = filter.grep.as_ref().map(|pattern| {
        regex::Regex::new(pattern).unwrap_or_else(|e| {
            eprintln!("invalid regex: {e}");
            process::exit(2);
        })
    });

    FilterConfig::new(FilterParams {
        uuid: filter.uuid.clone(),
        uuid_strict: true,
        match_blocks: filter.match_blocks,
        min_level,
        category: filter.category.clone(),
        fgrep: filter.fgrep.clone(),
        grep,
        from_ts: from.map(normalize_date_from),
        until_ts: until.map(normalize_date_until),
    })
    .unwrap_or_else(|e| {
        eprintln!("fslog: {e}");
        process::exit(2);
    })
}

fn setup_pager(cli: &Cli) -> Option<process::Child> {
    if cli.no_pager || !io::stdout().is_terminal() {
        return None;
    }
    if matches!(cli.command, Command::Completions { .. } | Command::Tail(_)) {
        return None;
    }
    let pager_cmd = std::env::var("FSLOG_PAGER").unwrap_or_else(|_| "less".to_string());
    let mut parts = pager_cmd.split_whitespace();
    let program = parts.next()?;
    let args: Vec<&str> = parts.collect();
    let default_args;
    let final_args = if args.is_empty() && program == "less" {
        default_args = ["-RFX"];
        &default_args[..]
    } else {
        &args[..]
    };
    match process::Command::new(program)
        .args(final_args)
        .stdin(process::Stdio::piped())
        .spawn()
    {
        Ok(child) => Some(child),
        Err(e) => {
            warn!("failed to spawn pager {program}: {e}; output goes to stdout");
            None
        }
    }
}

fn run_with_output(cli: Cli, use_pager: bool, out: &mut dyn Write) -> io::Result<()> {
    let color = resolve_color(cli.color, use_pager);
    match cli.command {
        Command::List => cmd_list(&cli.dir, out),
        Command::Search(ref args) => cmd_search(&cli.dir, args, color, out),
        Command::Read(ref args) => cmd_read(&cli.dir, args, color, out),
        Command::Tail(ref args) => cmd_tail(&cli.dir, args, color, out),
        #[cfg(feature = "tui")]
        Command::Monitor(_) => unreachable!("handled in main()"),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            complete::generate_completions(shell, &mut cmd);
            Ok(())
        }
    }
}

fn cmd_list(dir: &Path, out: &mut dyn Write) -> io::Result<()> {
    let files = discover_log_files(dir)?;
    for f in &files {
        let date = f
            .date
            .as_deref()
            .map(|d| {
                // "2026-03-08-16-52-07" → "2026-03-08 16:52"
                if d.len() >= 16 {
                    format!("{} {}:{}", &d[..10], &d[11..13], &d[14..16])
                } else {
                    d.to_string()
                }
            })
            .unwrap_or_else(|| "(current)".to_string());
        let size = format_size(f.size);
        let name = f.path.file_name().unwrap().to_string_lossy();
        writeln!(out, "{date:<17} {size:>6}  {name}")?;
    }
    Ok(())
}

pub(crate) fn separator_entry(kind: MessageKind, msg: String) -> LogEntry {
    LogEntry {
        uuid: String::new(),
        timestamp: String::new(),
        level: None,
        idle_pct: None,
        source: None,
        message: msg,
        kind: LineKind::Full,
        message_kind: kind,
        block: None,
        attached: AttachedLines::new(),
        line_number: 0,
        warnings: Vec::new(),
    }
}

const MAX_UNCONFIRMED_FILES: usize = 20;
const MAX_UNCONFIRMED_BYTES: u64 = 1024 * 1024 * 1024;

fn max_unconfirmed_bytes() -> u64 {
    let raw = match std::env::var("FSLOG_CONFIRM_SIZE") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return MAX_UNCONFIRMED_BYTES,
        // Set but unreadable is a misconfiguration, not an absent setting.
        Err(e) => {
            eprintln!("fslog: FSLOG_CONFIRM_SIZE is set but unusable: {e}");
            process::exit(2);
        }
    };
    raw.parse().unwrap_or_else(|e| {
        eprintln!("fslog: FSLOG_CONFIRM_SIZE={raw} is not a byte count: {e}");
        process::exit(2);
    })
}

/// A human-readable span of the log files on hand, so an empty result says
/// whether the search was even looking at the right days.
fn coverage_note(files: &[files::LogFile]) -> Option<String> {
    let stamps: Vec<&str> = files.iter().filter_map(|f| f.date.as_deref()).collect();
    let active = files.iter().any(|f| f.date.is_none());
    match (stamps.first(), active) {
        (None, true) => Some("log coverage here: active log only".to_string()),
        (None, false) => None,
        (Some(first), _) => {
            let day = |s: &str| s[..s.len().min(10)].to_string();
            let last = if active {
                "now".to_string()
            } else {
                day(stamps.last()?)
            };
            Some(format!("log coverage here: {} – {last}", day(first)))
        }
    }
}

/// Resolve the files a search will scan: explicit `--file` paths, or
/// date-filtered discovery in `dir`. Returns `None` when nothing matches or the
/// user declines the large-scan confirmation.
fn resolve_search_files(
    dir: &Path,
    args: &SearchArgs,
    from: Option<&str>,
    until: Option<&str>,
) -> io::Result<Option<Vec<(String, PathBuf)>>> {
    if !args.files.is_empty() {
        let v = args
            .files
            .iter()
            .map(|p| {
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                (name, p.clone())
            })
            .collect();
        return Ok(Some(v));
    }

    let all_files = discover_log_files(dir)?;
    let selected = filter_files_by_date(&all_files, from, until);
    if selected.is_empty() {
        eprintln!("no log files match the date range");
        return Ok(None);
    }
    let total_size: u64 = selected.iter().map(|f| f.size).sum();
    // File count alone is a poor proxy for the wait: twenty rotated logs from a
    // quiet box are seconds, one from a busy one can be gigabytes decompressed.
    if !args.yes && (selected.len() > MAX_UNCONFIRMED_FILES || total_size > max_unconfirmed_bytes())
    {
        let scale = format!("{} files ({})", selected.len(), format_size(total_size));
        if !io::stdin().is_terminal() {
            return Err(io::Error::other(format!(
                "refusing to scan {scale} without confirmation; pass -y to override"
            )));
        }
        eprint!("about to scan {scale}, proceed? [y/N] ");
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Ok(None);
        }
    }
    let v = selected
        .iter()
        .map(|f| {
            let name = f
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, f.path.clone())
        })
        .collect();
    Ok(Some(v))
}

fn build_segments(files: &[(String, PathBuf)]) -> Vec<(String, Box<dyn Iterator<Item = String>>)> {
    files
        .iter()
        .map(|(name, path)| (name.clone(), lazy_log_reader(path.clone())))
        .collect()
}

fn cmd_search(
    dir: &Path,
    args: &SearchArgs,
    color: ColorMode,
    out: &mut dyn Write,
) -> io::Result<()> {
    if args.pattern.is_some() && args.filter.fgrep.is_some() {
        return Err(io::Error::other(
            "provide either a positional PATTERN or --fgrep, not both",
        ));
    }

    let (from, until) = args.window()?;
    let mut filter = build_filter(&args.filter, from.as_deref(), until.as_deref());
    if let Some(p) = &args.pattern {
        filter.set_fgrep(p)?;
    }

    let files = match resolve_search_files(dir, args, from.as_deref(), until.as_deref())? {
        Some(f) => f,
        None => return Ok(()),
    };

    // Coverage is only meaningful for the files discovery chose; with explicit
    // --file paths the operator already knows what was searched.
    let report_empty = || -> io::Result<()> {
        let note = if args.files.is_empty() {
            coverage_note(&discover_log_files(dir)?)
        } else {
            None
        };
        match note {
            Some(n) => eprintln!("no matching entries; {n}"),
            None => eprintln!("no matching entries"),
        }
        Ok(())
    };

    // A needle that cannot span a line break lets whole files be ruled out before
    // the parse touches them. Any other search reads everything.
    let seeded = if files.len() > 1 {
        match args
            .pattern
            .as_deref()
            .or(args.filter.fgrep.as_deref())
            .or(match args.filter.uuid.as_slice() {
                [only] => Some(only.as_str()),
                _ => None,
            })
            .filter(|n| prescan::is_single_line_safe(n))
        {
            Some(needle) => prescan::narrow(&files, needle),
            None => files.clone(),
        }
    } else {
        files.clone()
    };
    if seeded.is_empty() {
        return report_empty();
    }

    let printer = args.filter.printer(color);

    // The narrowed set is sound for discovery, which matches the seed the prescan
    // looked for. It is not sound for output: `--related` re-keys the filter onto
    // the discovered peer legs, and a peer's own file need never mention the seed.
    let mut rendered = seeded;
    if args.related {
        let discovered = related::discover(build_segments(&rendered), &filter.for_discovery());
        if discovered.is_empty() {
            return report_empty();
        }
        let seeds: Vec<String> = discovered.into_iter().collect();
        filter.set_uuids(&seeds)?;
        filter.uuid_strict = true;
        rendered = files;
    }

    let (stats, session_count, count, matched) = run_output(
        out,
        build_segments(&rendered),
        &filter,
        &printer,
        &args.filter,
        args.before(),
        args.after(),
    )?;

    if matched == 0 {
        report_empty()?;
    }
    print_epilogue(&printer, &args.filter, &stats, count, session_count)
}

/// Drive the parse over `segments`, emitting matches through `Emitter`. The
/// single output loop for both search and read.
fn run_output(
    out: &mut dyn Write,
    segments: Vec<(String, Box<dyn Iterator<Item = String>>)>,
    filter: &FilterConfig,
    printer: &EntryPrinter,
    fargs: &FilterArgs,
    before: usize,
    after: usize,
) -> io::Result<(ParseStats, usize, u64, u64)> {
    let (chain, seg_tracker) = TrackedChain::new(segments);
    let stream = LogStream::new(chain).unclassified_tracking(fargs.tracking());
    let mut emitter = Emitter::new(printer, filter, &seg_tracker, fargs.stats, before, after);

    let (stats, session_count) = if fargs.session {
        let mut tracker = SessionTracker::new(stream);
        for enriched in tracker.by_ref() {
            emitter.on_entry(out, &enriched.entry, enriched.session.as_ref())?;
        }
        (tracker.stats().clone(), tracker.sessions().len())
    } else {
        let mut stream = stream;
        for entry in stream.by_ref() {
            emitter.on_entry(out, &entry, None)?;
        }
        (stream.stats().clone(), 0)
    };

    Ok((stats, session_count, emitter.count, emitter.matched))
}

fn cmd_read(dir: &Path, args: &ReadArgs, color: ColorMode, out: &mut dyn Write) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);

    let (name, lines): (String, Box<dyn Iterator<Item = String>>) = match args.file.as_deref() {
        Some("-") => (
            "-".to_string(),
            lossy_line_iter(Box::new(io::stdin().lock())),
        ),
        Some(path) => {
            let p = PathBuf::from(path);
            let p = if p.is_absolute() || p.exists() {
                p
            } else {
                dir.join(&p)
            };
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            (name, open_log_reader(&p)?)
        }
        None => {
            let p = resolve_log_path(dir, None);
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            (name, open_log_reader(&p)?)
        }
    };

    let printer = args.filter.printer(color);
    let (stats, session_count, count, _) = run_output(
        out,
        vec![(name, lines)],
        &filter,
        &printer,
        &args.filter,
        0,
        0,
    )?;

    print_epilogue(&printer, &args.filter, &stats, count, session_count)
}

fn cmd_tail(dir: &Path, args: &TailArgs, color: ColorMode, out: &mut dyn Write) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);

    let path = resolve_log_path(dir, args.file.as_deref());
    let lines = open_tail_reader(&path, args.lines)?;

    let printer = args.filter.printer(color);
    let stream = LogStream::new(lines).unclassified_tracking(args.filter.tracking());
    let mut tracker = SessionTracker::new(stream);

    for enriched in tracker.by_ref() {
        if !filter.matches(&enriched.entry) {
            continue;
        }
        if !args.filter.stats {
            printer.print_entry(out, &enriched.entry, enriched.session.as_ref(), None)?;
            out.flush()?;
        }
    }

    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    #[cfg(feature = "tui")]
    if let Command::Monitor(args) = cli.command {
        if let Err(e) = monitor::run(&cli.dir, args) {
            eprintln!("fslog: {e}");
            process::exit(1);
        }
        return;
    }

    let mut pager = setup_pager(&cli);
    let use_pager = pager.is_some();

    let result = if let Some(ref mut child) = pager {
        let mut stdin = child.stdin.take().expect("pager stdin");
        let result = run_with_output(cli, use_pager, &mut stdin);
        drop(stdin);
        if let Err(e) = child.wait() {
            warn!("waiting for the pager failed: {e}");
        }
        result
    } else {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        run_with_output(cli, use_pager, &mut lock)
    };

    if let Err(e) = result {
        if e.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("fslog: {e}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_file(date: Option<&str>) -> files::LogFile {
        files::LogFile {
            path: PathBuf::from("freeswitch.log"),
            date: date.map(str::to_string),
            size: 0,
        }
    }

    #[test]
    fn coverage_spans_first_stamp_to_last() {
        let files = vec![
            log_file(Some("2026-05-01-00-00-00")),
            log_file(Some("2026-05-20-00-00-00")),
        ];
        assert_eq!(
            coverage_note(&files).unwrap(),
            "log coverage here: 2026-05-01 – 2026-05-20"
        );
    }

    #[test]
    fn active_log_makes_the_upper_bound_now() {
        let files = vec![log_file(Some("2026-05-01-00-00-00")), log_file(None)];
        assert_eq!(
            coverage_note(&files).unwrap(),
            "log coverage here: 2026-05-01 – now"
        );
    }

    #[test]
    fn active_log_alone_has_no_span() {
        assert_eq!(
            coverage_note(&[log_file(None)]).unwrap(),
            "log coverage here: active log only"
        );
    }

    #[test]
    fn no_files_no_note() {
        assert!(coverage_note(&[]).is_none());
    }
}
