mod complete;
#[cfg(feature = "tui")]
mod config;
mod files;
#[cfg(feature = "tui")]
mod monitor;
mod output;

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

use freeswitch_log_parser::{
    LineKind, LogEntry, LogLevel, LogStream, MessageKind, SessionTracker, TrackedChain,
    UnclassifiedTracking,
};

use files::{
    discover_log_files, filter_files_by_date, format_size, lazy_log_reader, normalize_date_from,
    normalize_date_until, open_log_reader, open_tail_reader,
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
    /// UUID substring filter (case-insensitive)
    #[arg(short, long, value_name = "UUID")]
    uuid: Option<String>,

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

#[derive(clap::Args)]
struct SearchArgs {
    /// Start date (progressive tab-complete from filenames)
    #[arg(long)]
    from: Option<String>,

    /// End date (progressive tab-complete from filenames)
    #[arg(long)]
    until: Option<String>,

    #[command(flatten)]
    filter: FilterArgs,

    /// Explicit files (overrides --from/--until auto-discovery)
    #[arg(value_name = "FILES")]
    files: Vec<PathBuf>,
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
        uuid_filter: filter.uuid.as_deref().map(|u| u.to_lowercase()),
        min_level,
        category: filter.category.clone(),
        fgrep: filter.fgrep.clone(),
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
    process::Command::new(program)
        .args(final_args)
        .stdin(process::Stdio::piped())
        .spawn()
        .ok()
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

fn separator_entry(kind: MessageKind, msg: String) -> LogEntry {
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
        attached: Vec::new(),
        line_number: 0,
    }
}

fn cmd_search(
    dir: &Path,
    args: &SearchArgs,
    color: ColorMode,
    out: &mut dyn Write,
) -> io::Result<()> {
    let filter = build_filter(&args.filter, args.from.as_deref(), args.until.as_deref());
    let tracking = if args.filter.unclassified {
        UnclassifiedTracking::CaptureData
    } else {
        UnclassifiedTracking::CountOnly
    };

    let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = if !args.files.is_empty() {
        args.files
            .iter()
            .map(|p| {
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                (name, lazy_log_reader(p.clone()))
            })
            .collect()
    } else {
        let all_files = discover_log_files(dir)?;
        let selected =
            filter_files_by_date(&all_files, args.from.as_deref(), args.until.as_deref());
        if selected.is_empty() {
            eprintln!("no log files match the date range");
            return Ok(());
        }
        selected
            .iter()
            .map(|f| {
                let name = f
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (name, lazy_log_reader(f.path.clone()))
            })
            .collect()
    };

    let (chain, seg_tracker) = TrackedChain::new(segments);

    let printer = EntryPrinter {
        color,
        show_blocks: args.filter.blocks,
        show_session: args.filter.session,
        show_filename: false,
        show_line_numbers: args.filter.line_numbers,
    };

    let stream = LogStream::new(chain).unclassified_tracking(tracking);
    let mut count: u64 = 0;
    let mut last_seg: Option<usize> = None;
    let mut last_date = String::new();

    let mut print_matching = |out: &mut dyn Write,
                              entry: &LogEntry,
                              session: Option<&freeswitch_log_parser::SessionSnapshot>|
     -> io::Result<()> {
        count += 1;
        if !filter.matches(entry) {
            return Ok(());
        }
        if args.filter.stats {
            return Ok(());
        }
        if let Some((idx, name)) = seg_tracker.segment_for_line(entry.line_number) {
            if last_seg != Some(idx) {
                last_seg = Some(idx);
                let sep = separator_entry(MessageKind::FileChange, name.to_string());
                printer.print_entry(out, &sep, None, None)?;
            }
        }
        if entry.timestamp.len() >= 10 {
            let date = &entry.timestamp[..10];
            if date != last_date {
                last_date = date.to_string();
                let sep = separator_entry(MessageKind::DateChange, last_date.clone());
                printer.print_entry(out, &sep, None, None)?;
            }
        }
        printer.print_entry(out, entry, session, None)
    };

    let (stats, session_count) = if args.filter.session {
        let mut tracker = SessionTracker::new(stream);
        for enriched in tracker.by_ref() {
            print_matching(out, &enriched.entry, enriched.session.as_ref())?;
        }
        (tracker.stats().clone(), tracker.sessions().len())
    } else {
        let mut stream = stream;
        for entry in stream.by_ref() {
            print_matching(out, &entry, None)?;
        }
        (stream.stats().clone(), 0)
    };

    if args.filter.stats || args.filter.unclassified {
        printer.print_stats(&mut io::stderr(), &stats, count, session_count)?;
    }
    if args.filter.unclassified {
        printer.print_unclassified(&mut io::stderr(), &stats)?;
    }

    Ok(())
}

fn cmd_read(dir: &Path, args: &ReadArgs, color: ColorMode, out: &mut dyn Write) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);
    let tracking = if args.filter.unclassified {
        UnclassifiedTracking::CaptureData
    } else {
        UnclassifiedTracking::CountOnly
    };

    let lines: Box<dyn Iterator<Item = String>> = match args.file.as_deref() {
        Some("-") => {
            let stdin = io::stdin();
            Box::new(
                stdin
                    .lock()
                    .lines()
                    .map(|l| l.expect("read error"))
                    .collect::<Vec<_>>()
                    .into_iter(),
            )
        }
        Some(path) => {
            let p = PathBuf::from(path);
            open_log_reader(&p)?
        }
        None => {
            let p = dir.join("freeswitch.log");
            open_log_reader(&p)?
        }
    };

    let printer = EntryPrinter {
        color,
        show_blocks: args.filter.blocks,
        show_session: args.filter.session,
        show_filename: false,
        show_line_numbers: args.filter.line_numbers,
    };

    let stream = LogStream::new(lines).unclassified_tracking(tracking);
    let mut count: u64 = 0;
    let mut last_date = String::new();

    let mut print_matching = |out: &mut dyn Write,
                              entry: &LogEntry,
                              session: Option<&freeswitch_log_parser::SessionSnapshot>|
     -> io::Result<()> {
        count += 1;
        if !filter.matches(entry) {
            return Ok(());
        }
        if args.filter.stats {
            return Ok(());
        }
        if entry.timestamp.len() >= 10 {
            let date = &entry.timestamp[..10];
            if date != last_date {
                last_date = date.to_string();
                let sep = separator_entry(MessageKind::DateChange, last_date.clone());
                printer.print_entry(out, &sep, None, None)?;
            }
        }
        printer.print_entry(out, entry, session, None)
    };

    let (stats, session_count) = if args.filter.session {
        let mut tracker = SessionTracker::new(stream);
        for enriched in tracker.by_ref() {
            print_matching(out, &enriched.entry, enriched.session.as_ref())?;
        }
        (tracker.stats().clone(), tracker.sessions().len())
    } else {
        let mut stream = stream;
        for entry in stream.by_ref() {
            print_matching(out, &entry, None)?;
        }
        (stream.stats().clone(), 0)
    };

    if args.filter.stats || args.filter.unclassified {
        printer.print_stats(&mut io::stderr(), &stats, count, session_count)?;
    }
    if args.filter.unclassified {
        printer.print_unclassified(&mut io::stderr(), &stats)?;
    }

    Ok(())
}

fn cmd_tail(dir: &Path, args: &TailArgs, color: ColorMode, out: &mut dyn Write) -> io::Result<()> {
    let filter = build_filter(&args.filter, None, None);
    let tracking = if args.filter.unclassified {
        UnclassifiedTracking::CaptureData
    } else {
        UnclassifiedTracking::CountOnly
    };

    let path = match args.file.as_deref() {
        Some(p) => PathBuf::from(p),
        None => dir.join("freeswitch.log"),
    };

    let lines = open_tail_reader(&path, args.lines)?;

    let printer = EntryPrinter {
        color,
        show_blocks: args.filter.blocks,
        show_session: args.filter.session,
        show_filename: false,
        show_line_numbers: args.filter.line_numbers,
    };

    let stream = LogStream::new(lines).unclassified_tracking(tracking);
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
