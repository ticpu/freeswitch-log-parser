//! Live call monitor — a TUI table of in-flight calls, and the `--dump`
//! scripting surface behind it.

mod input;
mod model;
mod reader;
#[cfg(test)]
mod tests;
mod time;
mod ui;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::ExecutableCommand;
use ratatui::widgets::TableState;
use ratatui::Terminal;

use freeswitch_log_parser::{LogStream, SessionTracker, TrackedChain};

use crate::config;
use crate::files::{open_log_reader, resolve_log_path};

use input::{execute_action, handle_key};
use model::{AppState, ContextFilter, UiMode};
use reader::{apply_update, build_segments, build_update, gc_ended, spawn_reader};
use ui::{render_ui, row_cells};

#[derive(clap::Args)]
pub struct MonitorArgs {
    /// Config file path
    #[arg(long, env = "FSLOG_CONFIG")]
    config: Option<PathBuf>,

    /// Filter by dialplan context (comma-separated, prefix with - to exclude)
    #[arg(long, value_name = "CTX", allow_hyphen_values = true)]
    context: Option<String>,

    /// Print call table to stdout and exit (no TUI)
    #[arg(long)]
    dump: bool,

    /// Log file to tail (default: freeswitch.log in --dir)
    #[arg(value_name = "FILE")]
    file: Option<String>,
}

fn process_log(dir: &Path, path: &Path, context_filter: ContextFilter) -> io::Result<AppState> {
    let segments = build_segments(dir, path, open_log_reader)?;

    let (chain, _) = TrackedChain::new(segments);
    let stream = LogStream::new(chain);
    let mut tracker = SessionTracker::new(stream);

    let mut state = AppState::new(
        dir.to_path_buf(),
        context_filter,
        Vec::new(),
        Duration::from_secs(3600),
    );

    while let Some(enriched) = tracker.next() {
        if let Some(msg) = build_update(&enriched, tracker.sessions()) {
            apply_update(&mut state, msg);
        }
    }

    Ok(state)
}

pub fn run_dump(dir: &Path, args: &MonitorArgs) -> io::Result<()> {
    let path = resolve_log_path(dir, args.file.as_deref());

    let context_filter = args
        .context
        .as_deref()
        .map(ContextFilter::parse)
        .unwrap_or(ContextFilter::None);

    let state = process_log(dir, &path, context_filter)?;

    // `println!` panics when the reader closes early; `fslog monitor --dump |
    // head` is exactly that.
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for r in &state.calls {
        match writeln!(out, "{}", row_cells(r, &state.latest_timestamp).join("\t")) {
            Err(e) if crate::pager::is_broken_pipe(&e) => return Ok(()),
            other => other?,
        }
    }

    Ok(())
}

pub fn run(dir: &Path, args: MonitorArgs) -> io::Result<()> {
    if args.dump {
        return run_dump(dir, &args);
    }

    let cfg = config::load_config(args.config.as_deref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let path = resolve_log_path(dir, args.file.as_deref());

    let (tx, rx) = mpsc::channel();
    let (remove_tx, remove_rx) = mpsc::channel();
    let _reader = spawn_reader(dir.to_path_buf(), path, tx, remove_rx)?;

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let context_filter = args
        .context
        .as_deref()
        .map(ContextFilter::parse)
        .unwrap_or(ContextFilter::None);

    let mut state = AppState::new(
        dir.to_path_buf(),
        context_filter,
        cfg.tools,
        Duration::from_secs(cfg.monitor.hangup_linger_seconds),
    );
    state.remove_tx = Some(remove_tx);

    let mut table_state = TableState::default();

    let result = (|| -> io::Result<()> {
        loop {
            while let Ok(msg) = rx.try_recv() {
                apply_update(&mut state, msg);
            }

            gc_ended(&mut state);

            if !state.calls.is_empty() {
                table_state.select(Some(state.selected_index()));
            } else {
                table_state.select(None);
            }

            state.page_size = terminal.size()?.height.saturating_sub(5) as usize;

            terminal.draw(|f| render_ui(f, &state, &mut table_state))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    if key.code == KeyCode::Enter {
                        if let UiMode::Menu {
                            target_uuid,
                            selected,
                        } = &state.ui_mode
                        {
                            let uuid = target_uuid.clone();
                            let selected = *selected;
                            state.ui_mode = UiMode::Table;
                            // exec() replaces the process on success; an error
                            // return means spawn failed and exits the loop.
                            execute_action(&state, &uuid, selected)?;
                            continue;
                        }
                    }

                    handle_key(&mut state, key.code);
                }
            }

            if state.should_quit {
                break;
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    result
}
