use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState,
};
use ratatui::Terminal;

use freeswitch_log_parser::{
    CallDirection, CallState, ChannelState, LogStream, MessageKind, SessionTracker, TrackedChain,
};

use crate::config::{self, Tool};
use crate::files::{discover_log_files, open_log_reader, open_tail_reader};

#[derive(clap::Args)]
pub struct MonitorArgs {
    /// Config file path
    #[arg(long, env = "FSLOG_CONFIG")]
    config: Option<PathBuf>,

    /// Number of recent lines to show initially
    #[arg(long, default_value = "50")]
    lines: usize,

    /// Filter by dialplan context (comma-separated, prefix with - to exclude)
    #[arg(long, value_name = "CTX", allow_hyphen_values = true)]
    context: Option<String>,

    /// Log file to tail (default: freeswitch.log in --dir)
    #[arg(value_name = "FILE")]
    file: Option<String>,
}

struct CallRow {
    uuid: String,
    direction: Option<String>,
    caller: Option<String>,
    callee: Option<String>,
    channel_state: Option<String>,
    context: Option<String>,
    first_seen: Instant,
    ended: Option<Instant>,
}

enum ContextFilter {
    None,
    Include(Vec<String>),
    Exclude(Vec<String>),
}

impl ContextFilter {
    fn parse(spec: &str) -> Self {
        let tokens: Vec<&str> = spec
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if tokens.is_empty() {
            return Self::None;
        }
        if tokens[0].starts_with('-') {
            Self::Exclude(
                tokens
                    .iter()
                    .map(|t| t.strip_prefix('-').unwrap_or(t).to_string())
                    .collect(),
            )
        } else {
            Self::Include(tokens.iter().map(|t| t.to_string()).collect())
        }
    }

    fn matches(&self, context: Option<&str>) -> bool {
        match self {
            Self::None => true,
            Self::Include(list) => context.is_some_and(|c| list.iter().any(|f| c == f)),
            Self::Exclude(list) => context.is_none_or(|c| !list.iter().any(|f| c == f)),
        }
    }
}

struct AppState {
    calls: Vec<CallRow>,
    selected_uuid: Option<String>,
    show_menu: bool,
    menu_selected: usize,
    tools: Vec<Tool>,
    linger: Duration,
    should_quit: bool,
    dir: PathBuf,
    page_size: usize,
    context_filter: ContextFilter,
}

impl AppState {
    fn selected_index(&self) -> usize {
        match &self.selected_uuid {
            Some(uuid) => self.calls.iter().position(|r| r.uuid == *uuid).unwrap_or(0),
            None => 0,
        }
    }

    fn select_index(&mut self, idx: usize) {
        self.selected_uuid = self.calls.get(idx).map(|r| r.uuid.clone());
    }

    fn sort_calls(&mut self) {
        self.calls.sort_by(|a, b| {
            let a_ended = a.ended.is_some();
            let b_ended = b.ended.is_some();
            match (a_ended, b_ended) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => b.first_seen.cmp(&a.first_seen),
            }
        });
    }
}

enum ReaderMsg {
    Update {
        uuid: String,
        channel_state: Option<String>,
        context: Option<String>,
        direction: Option<String>,
        caller: Option<String>,
        callee: Option<String>,
        is_hangup: bool,
    },
}

fn format_state(raw: &str) -> String {
    if let Ok(cs) = ChannelState::from_str(raw) {
        match cs {
            ChannelState::CsExchangeMedia => "MEDIA".to_string(),
            ChannelState::CsConsumeMedia => "CONSUME".to_string(),
            ChannelState::CsSoftExecute => "SOFTEX".to_string(),
            ChannelState::CsReporting => "REPORT".to_string(),
            _ => {
                let s = cs.to_string();
                s.strip_prefix("CS_").unwrap_or(&s).to_string()
            }
        }
    } else if let Ok(cs) = CallState::from_str(raw) {
        cs.to_string()
    } else {
        raw.to_string()
    }
}

fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

fn spawn_reader(
    dir: PathBuf,
    path: PathBuf,
    initial_lines: usize,
    tx: mpsc::Sender<ReaderMsg>,
) -> io::Result<std::thread::JoinHandle<()>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", path.display()),
        ));
    }
    let handle = std::thread::spawn(move || {
        let mut segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = Vec::new();

        if let Ok(files) = discover_log_files(&dir) {
            if let Some(prev) = files.iter().rev().find(|f| f.date.is_some()) {
                if let Ok(reader) = open_log_reader(&prev.path) {
                    let name = prev
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    segments.push((name, reader));
                }
            }
        }

        let tail = match open_tail_reader(&path, initial_lines) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("fslog: {}: {e}", path.display());
                return;
            }
        };
        let current_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        segments.push((current_name, tail));

        let (chain, _seg_tracker) = TrackedChain::new(segments);
        let stream = LogStream::new(chain);
        let mut tracker = SessionTracker::new(stream);

        while let Some(enriched) = tracker.next() {
            let uuid = enriched.entry.uuid.clone();
            if uuid.is_empty() {
                continue;
            }

            let is_hangup = matches!(
                &enriched.entry.message_kind,
                MessageKind::ChannelLifecycle { detail }
                    if detail.contains("Hangup") || detail.contains("Destroy")
            ) || matches!(
                &enriched.entry.message_kind,
                MessageKind::StateChange { detail }
                    if detail.contains("CS_DESTROY")
            );

            let snap = enriched.session.as_ref();
            let state = tracker.sessions().get(&uuid);

            let msg = ReaderMsg::Update {
                channel_state: state
                    .and_then(|s| s.channel_state.clone())
                    .or_else(|| snap.and_then(|s| s.channel_state.clone())),
                context: state
                    .and_then(|s| s.initial_context.clone())
                    .or_else(|| snap.and_then(|s| s.initial_context.clone())),
                direction: state
                    .and_then(|s| s.call_direction.map(|d| d.to_string()))
                    .or_else(|| state.and_then(|s| s.variables.get("direction").cloned())),
                caller: state
                    .and_then(|s| s.caller_id_number.clone())
                    .or_else(|| state.and_then(|s| s.variables.get("sip_from_user").cloned()))
                    .or_else(|| state.and_then(|s| s.dialplan_from.clone())),
                callee: state
                    .and_then(|s| s.destination_number.clone())
                    .or_else(|| state.and_then(|s| s.variables.get("sip_to_user").cloned()))
                    .or_else(|| state.and_then(|s| s.dialplan_to.clone())),
                uuid,
                is_hangup,
            };

            if tx.send(msg).is_err() {
                break;
            }
        }
    });
    Ok(handle)
}

fn apply_update(state: &mut AppState, msg: ReaderMsg) {
    let ReaderMsg::Update {
        uuid,
        channel_state,
        context,
        direction,
        caller,
        callee,
        is_hangup,
    } = msg;

    if !state.context_filter.matches(context.as_deref()) {
        return;
    }

    if let Some(row) = state.calls.iter_mut().find(|r| r.uuid == uuid) {
        if channel_state.is_some() {
            row.channel_state = channel_state;
        }
        if context.is_some() {
            row.context = context;
        }
        if direction.is_some() {
            row.direction = direction;
        }
        if caller.is_some() {
            row.caller = caller;
        }
        if callee.is_some() {
            row.callee = callee;
        }
        if is_hangup && row.ended.is_none() {
            row.ended = Some(Instant::now());
        }
    } else if !is_hangup {
        state.calls.push(CallRow {
            uuid,
            direction,
            caller,
            callee,
            channel_state,
            context,
            first_seen: Instant::now(),
            ended: None,
        });
    } else {
        return;
    }

    state.sort_calls();
}

fn gc_ended(state: &mut AppState) {
    let linger = state.linger;
    state
        .calls
        .retain(|r| r.ended.is_none_or(|t| t.elapsed() < linger));
    if let Some(ref uuid) = state.selected_uuid {
        if !state.calls.iter().any(|r| r.uuid == *uuid) {
            state.selected_uuid = state.calls.first().map(|r| r.uuid.clone());
        }
    }
}

fn render_ui(f: &mut ratatui::Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();

    let active_count = state.calls.iter().filter(|r| r.ended.is_none()).count();
    let header_text = format!(
        " fslog monitor - {} active call{}",
        active_count,
        if active_count == 1 { "" } else { "s" }
    );

    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).split(area);

    let status = Line::from(vec![
        Span::raw(header_text),
        Span::raw("  "),
        Span::styled("[q]", Style::default().fg(Color::DarkGray)),
        Span::styled("uit ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Enter]", Style::default().fg(Color::DarkGray)),
        Span::styled(" actions", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(status), chunks[0]);

    let header = Row::new([
        Cell::from("UUID"),
        Cell::from("Dir"),
        Cell::from("Caller"),
        Cell::from("Callee"),
        Cell::from("State"),
        Cell::from("Age"),
        Cell::from("Context"),
    ])
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    );

    let rows: Vec<Row> = state
        .calls
        .iter()
        .map(|r| {
            let ended = r.ended.is_some();
            let style = if ended {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let uuid_short = if r.uuid.len() > 8 {
                &r.uuid[..8]
            } else {
                &r.uuid
            };
            let age = format_age(r.first_seen.elapsed());
            let st = r
                .channel_state
                .as_deref()
                .map(format_state)
                .unwrap_or_else(|| "-".to_string());
            let dir = r
                .direction
                .as_deref()
                .and_then(|d| CallDirection::from_str(d).ok())
                .map(|d| match d {
                    CallDirection::Inbound => "IN",
                    CallDirection::Outbound => "OUT",
                    _ => "?",
                })
                .unwrap_or("-");
            Row::new([
                Cell::from(uuid_short.to_string()),
                Cell::from(dir),
                Cell::from(r.caller.as_deref().unwrap_or("-")),
                Cell::from(r.callee.as_deref().unwrap_or("-")),
                Cell::from(st),
                Cell::from(age),
                Cell::from(r.context.as_deref().unwrap_or("-")),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Min(12),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Min(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, chunks[1], table_state);

    if state.show_menu {
        render_menu(f, state, area);
    }
}

fn render_menu(f: &mut ratatui::Frame, state: &AppState, area: Rect) {
    let uuid = match state.calls.get(state.selected_index()) {
        Some(r) => &r.uuid,
        None => return,
    };

    let mut items: Vec<ListItem> = vec![
        ListItem::new(format!("search  (fslog search --uuid {:.8}...)", uuid)),
        ListItem::new(format!("tail    (fslog tail --uuid {:.8}...)", uuid)),
    ];
    for tool in &state.tools {
        items.push(ListItem::new(format!("{}  ({})", tool.name, tool.command)));
    }

    let menu_height = (items.len() as u16 + 2).min(area.height.saturating_sub(4));
    let menu_width = 60.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(menu_width)) / 2;
    let y = area.y + (area.height.saturating_sub(menu_height)) / 2;
    let menu_area = Rect::new(x, y, menu_width, menu_height);

    f.render_widget(Clear, menu_area);

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Actions ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(state.menu_selected));
    f.render_stateful_widget(list, menu_area, &mut list_state);
}

fn execute_action(state: &AppState, action_index: usize) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let uuid = match state.calls.get(state.selected_index()) {
        Some(r) => &r.uuid,
        None => return Ok(()),
    };

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    let err = match action_index {
        0 => {
            let exe = std::env::current_exe()?;
            let dir_str = state.dir.to_string_lossy().into_owned();
            std::process::Command::new(&exe)
                .args(["--dir", &dir_str, "search", "--uuid", uuid])
                .exec()
        }
        1 => {
            let exe = std::env::current_exe()?;
            let dir_str = state.dir.to_string_lossy().into_owned();
            std::process::Command::new(&exe)
                .args(["--dir", &dir_str, "tail", "--uuid", uuid])
                .exec()
        }
        n => {
            let tool_idx = n - 2;
            if let Some(tool) = state.tools.get(tool_idx) {
                let cmd = tool.expand_command(uuid);
                std::process::Command::new("sh").args(["-c", &cmd]).exec()
            } else {
                return Ok(());
            }
        }
    };

    Err(io::Error::other(err))
}

fn handle_key(state: &mut AppState, code: KeyCode) {
    if state.show_menu {
        handle_menu_key(state, code);
    } else {
        handle_table_key(state, code);
    }
}

fn handle_table_key(state: &mut AppState, code: KeyCode) {
    let idx = state.selected_index();
    let len = state.calls.len();
    match code {
        KeyCode::Char('q') | KeyCode::Esc => state.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            if idx > 0 {
                state.select_index(idx - 1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if len > 0 && idx < len - 1 {
                state.select_index(idx + 1);
            }
        }
        KeyCode::PageUp => {
            let new = idx.saturating_sub(state.page_size);
            state.select_index(new);
        }
        KeyCode::PageDown => {
            if len > 0 {
                let new = (idx + state.page_size).min(len - 1);
                state.select_index(new);
            }
        }
        KeyCode::Home => {
            state.select_index(0);
        }
        KeyCode::End => {
            if len > 0 {
                state.select_index(len - 1);
            }
        }
        KeyCode::Enter => {
            if !state.calls.is_empty() {
                state.show_menu = true;
                state.menu_selected = 0;
            }
        }
        _ => {}
    }
}

fn handle_menu_key(state: &mut AppState, code: KeyCode) {
    let item_count = 2 + state.tools.len();
    match code {
        KeyCode::Esc | KeyCode::Char('q') => state.show_menu = false,
        KeyCode::Up | KeyCode::Char('k') => {
            if state.menu_selected > 0 {
                state.menu_selected -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if state.menu_selected + 1 < item_count {
                state.menu_selected += 1;
            }
        }
        KeyCode::Enter => {
            // handled in the event loop since we need terminal access
        }
        _ => {}
    }
}

pub fn run(dir: &Path, args: MonitorArgs) -> io::Result<()> {
    let cfg = config::load_config(args.config.as_deref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let path = match args.file.as_deref() {
        Some(p) => PathBuf::from(p),
        None => dir.join("freeswitch.log"),
    };

    let (tx, rx) = mpsc::channel();
    let _reader = spawn_reader(dir.to_path_buf(), path, args.lines, tx)?;

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let context_filter = args
        .context
        .as_deref()
        .map(ContextFilter::parse)
        .unwrap_or(ContextFilter::None);

    let mut state = AppState {
        calls: Vec::new(),
        selected_uuid: None,
        show_menu: false,
        menu_selected: 0,
        tools: cfg.tools,
        linger: Duration::from_secs(cfg.monitor.hangup_linger_seconds),
        should_quit: false,
        dir: dir.to_path_buf(),
        page_size: 20,
        context_filter,
    };

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

                    if state.show_menu && key.code == KeyCode::Enter {
                        state.show_menu = false;
                        execute_action(&state, state.menu_selected)?;
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
