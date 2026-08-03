mod complete;
#[cfg(feature = "tui")]
mod config;
mod context;
mod dialstring;
mod files;
#[cfg(feature = "tui")]
mod monitor;
mod output;
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
use output::{ColorMode, EntryPrinter, FilterConfig};

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

    /// Message category filter
    #[arg(short, long, value_name = "KIND")]
    category: Option<String>,

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

    if let Some(ref cat) = filter.category {
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

    FilterConfig {
        uuid_filter: filter.uuid.iter().map(|u| u.to_lowercase()).collect(),
        uuid_strict: true,
        match_blocks: filter.match_blocks,
        min_level,
        category: filter.category.clone(),
        fgrep: filter.fgrep.as_ref().map(|p| p.to_lowercase()),
        grep,
        from_ts: from.map(normalize_date_from),
        until_ts: until.map(normalize_date_until),
    }
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

/// Resolve the files a search will scan: explicit `--file` paths, or
/// date-filtered discovery in `dir`. Returns `None` when nothing matches or the
/// user declines the large-scan confirmation.
fn resolve_search_files(
    dir: &Path,
    args: &SearchArgs,
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
    let selected = filter_files_by_date(&all_files, args.from.as_deref(), args.until.as_deref());
    if selected.is_empty() {
        eprintln!("no log files match the date range");
        return Ok(None);
    }
    if !args.yes && selected.len() > 20 {
        let total_size: u64 = selected.iter().map(|f| f.size).sum();
        if !io::stdin().is_terminal() {
            return Err(io::Error::other(format!(
                "refusing to scan {} files ({}) without confirmation; pass -y to override",
                selected.len(),
                format_size(total_size)
            )));
        }
        eprint!(
            "about to scan {} files ({}), proceed? [y/N] ",
            selected.len(),
            format_size(total_size)
        );
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

    let mut filter = build_filter(&args.filter, args.from.as_deref(), args.until.as_deref());
    if let Some(p) = &args.pattern {
        filter.fgrep = Some(p.to_lowercase());
    }

    let files = match resolve_search_files(dir, args)? {
        Some(f) => f,
        None => return Ok(()),
    };

    let printer = args.filter.printer(color);

    if args.related {
        let discovered = related::discover(build_segments(&files), &filter.for_discovery());
        if discovered.is_empty() {
            return Ok(());
        }
        filter.uuid_filter = discovered.into_iter().map(|u| u.to_lowercase()).collect();
        filter.uuid_strict = true;
    }

    let (stats, session_count, count) = run_output(
        out,
        build_segments(&files),
        &filter,
        &printer,
        &args.filter,
        args.before(),
        args.after(),
    )?;

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
) -> io::Result<(ParseStats, usize, u64)> {
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

    Ok((stats, session_count, emitter.count))
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
    let (stats, session_count, count) = run_output(
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
        let _ = child.wait();
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
