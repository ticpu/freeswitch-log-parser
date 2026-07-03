use std::collections::HashSet;
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
    CallDirection, CallState, ChannelState, ChannelVariable, EnrichedEntry, LogStream, MessageKind,
    SessionState, SessionTracker, SofiaVariable, TrackedChain,
};

use crate::config::{self, Tool};
use crate::files::{discover_log_files, open_full_tail_reader, open_log_reader, resolve_log_path};

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

/// Channel state parsed once at the reader boundary: usually a `CS_*`
/// ChannelState, sometimes a CallState; anything else passes through raw.
enum LegState {
    Channel(ChannelState),
    Call(CallState),
    Raw(String),
}

impl LegState {
    fn parse(raw: &str) -> Self {
        if let Ok(cs) = ChannelState::from_str(raw) {
            LegState::Channel(cs)
        } else if let Ok(cs) = CallState::from_str(raw) {
            LegState::Call(cs)
        } else {
            LegState::Raw(raw.to_string())
        }
    }

    /// Short column label for the call table.
    fn short(&self) -> String {
        match self {
            LegState::Channel(ChannelState::CsExchangeMedia) => "MEDIA".to_string(),
            LegState::Channel(ChannelState::CsConsumeMedia) => "CONSUME".to_string(),
            LegState::Channel(ChannelState::CsSoftExecute) => "SOFTEX".to_string(),
            LegState::Channel(ChannelState::CsReporting) => "REPORT".to_string(),
            LegState::Channel(cs) => {
                let s = cs.to_string();
                s.strip_prefix("CS_").unwrap_or(&s).to_string()
            }
            LegState::Call(cs) => cs.to_string(),
            LegState::Raw(s) => s.clone(),
        }
    }
}

/// Call fields carried by reader updates and merged into the table row.
#[derive(Default)]
struct CallFields {
    other_leg_uuid: Option<String>,
    direction: Option<CallDirection>,
    caller: Option<String>,
    callee: Option<String>,
    channel_state: Option<LegState>,
    context: Option<String>,
}

impl CallFields {
    /// Field-wise merge: `Some` in `update` overwrites, `None` keeps existing.
    fn merge(&mut self, update: CallFields) {
        let CallFields {
            other_leg_uuid,
            direction,
            caller,
            callee,
            channel_state,
            context,
        } = update;
        if other_leg_uuid.is_some() {
            self.other_leg_uuid = other_leg_uuid;
        }
        if direction.is_some() {
            self.direction = direction;
        }
        if caller.is_some() {
            self.caller = caller;
        }
        if callee.is_some() {
            self.callee = callee;
        }
        if channel_state.is_some() {
            self.channel_state = channel_state;
        }
        if context.is_some() {
            self.context = context;
        }
    }
}

/// When a call ended: wall clock for linger GC, log timestamp for display.
struct CallEnd {
    at: Instant,
    log_ts: String,
}

struct CallRow {
    uuid: String,
    fields: CallFields,
    log_start: String,
    log_last: String,
    end: Option<CallEnd>,
    first_seen: Instant,
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

/// Which overlay owns the keyboard. The action menu always has a target, and
/// the leg picker and menu cannot both be open — illegal combinations are
/// unrepresentable.
enum UiMode {
    Table,
    LegPicker {
        selected: usize,
    },
    Menu {
        target_uuid: String,
        selected: usize,
    },
}

struct AppState {
    calls: Vec<CallRow>,
    selected_uuid: Option<String>,
    ui_mode: UiMode,
    tools: Vec<Tool>,
    linger: Duration,
    should_quit: bool,
    dir: PathBuf,
    page_size: usize,
    context_filter: ContextFilter,
    filtered_uuids: HashSet<String>,
    latest_timestamp: String,
    /// Requests the reader thread drop a UUID's SessionTracker state; `None`
    /// in one-shot (dump) mode where the tracker dies with the read.
    remove_tx: Option<mpsc::Sender<String>>,
}

impl AppState {
    fn new(
        dir: PathBuf,
        context_filter: ContextFilter,
        tools: Vec<Tool>,
        linger: Duration,
    ) -> Self {
        AppState {
            calls: Vec::new(),
            selected_uuid: None,
            ui_mode: UiMode::Table,
            tools,
            linger,
            should_quit: false,
            dir,
            page_size: 20,
            context_filter,
            filtered_uuids: HashSet::new(),
            latest_timestamp: String::new(),
            remove_tx: None,
        }
    }

    fn selected_index(&self) -> usize {
        match &self.selected_uuid {
            Some(uuid) => self.calls.iter().position(|r| r.uuid == *uuid).unwrap_or(0),
            None => 0,
        }
    }

    fn select_index(&mut self, idx: usize) {
        self.selected_uuid = self.calls.get(idx).map(|r| r.uuid.clone());
    }

    fn request_session_removal(&mut self, uuid: String) {
        if let Some(tx) = &self.remove_tx {
            // A closed channel means the reader thread (and its tracker) is
            // gone, so there is no session state left to free.
            if tx.send(uuid).is_err() {
                self.remove_tx = None;
            }
        }
    }

    fn sort_calls(&mut self) {
        self.calls.sort_by(|a, b| {
            let a_ended = a.end.is_some();
            let b_ended = b.end.is_some();
            match (a_ended, b_ended) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => b.first_seen.cmp(&a.first_seen),
            }
        });
    }
}

/// Lifecycle transition detected in a log entry, if any.
enum CallEvent {
    NewChannel,
    Hangup,
}

struct ReaderMsg {
    uuid: String,
    timestamp: String,
    fields: CallFields,
    event: Option<CallEvent>,
}

fn format_direction(direction: Option<CallDirection>) -> &'static str {
    direction
        .map(|d| match d {
            CallDirection::Inbound => "IN",
            CallDirection::Outbound => "OUT",
            _ => "?",
        })
        .unwrap_or("-")
}

/// First 8 chars of a UUID for display. Byte slicing is safe here only because
/// UUIDs are ASCII — keep this on UUID-typed call sites.
fn short8(uuid: &str) -> &str {
    if uuid.len() > 8 {
        &uuid[..8]
    } else {
        uuid
    }
}

/// The 9 display columns shared by the TUI table and `--dump` output, so the
/// scripting surface cannot drift from what the TUI shows.
fn row_cells(r: &CallRow, latest: &str) -> [String; 9] {
    [
        short8(&r.uuid).to_string(),
        r.fields
            .other_leg_uuid
            .as_deref()
            .map(short8)
            .unwrap_or("-")
            .to_string(),
        format_direction(r.fields.direction).to_string(),
        r.fields.caller.as_deref().unwrap_or("-").to_string(),
        r.fields.callee.as_deref().unwrap_or("-").to_string(),
        r.fields
            .channel_state
            .as_ref()
            .map(LegState::short)
            .unwrap_or_else(|| "-".to_string()),
        format_duration(call_duration(r)),
        format_age(call_age(r, latest)),
        r.fields.context.as_deref().unwrap_or("-").to_string(),
    ]
}

fn end_ts(row: &CallRow) -> &str {
    row.end
        .as_ref()
        .map(|e| e.log_ts.as_str())
        .unwrap_or(&row.log_last)
}

fn call_duration(row: &CallRow) -> Duration {
    log_age(&row.log_start, end_ts(row))
}

fn call_age(row: &CallRow, latest: &str) -> Duration {
    log_age(end_ts(row), latest)
}

fn build_update(
    enriched: &EnrichedEntry,
    sessions: &std::collections::HashMap<String, SessionState>,
) -> Option<ReaderMsg> {
    let uuid = enriched.entry.uuid.clone();
    if uuid.is_empty() || enriched.entry.timestamp.is_empty() {
        return None;
    }

    let cs_destroy = ChannelState::CsDestroy.to_string();
    let is_hangup = matches!(
        &enriched.entry.message_kind,
        MessageKind::ChannelLifecycle { detail }
            if detail.contains("Hangup") || detail.contains("Destroy")
    ) || matches!(
        &enriched.entry.message_kind,
        MessageKind::StateChange { detail }
            if detail.contains(cs_destroy.as_str())
    );

    let is_new_channel = matches!(
        &enriched.entry.message_kind,
        MessageKind::ChannelLifecycle { detail }
            if detail.starts_with("New Channel ")
    );

    let snap = enriched.session.as_ref();
    let state = sessions.get(&uuid);

    let event = if is_hangup {
        Some(CallEvent::Hangup)
    } else if is_new_channel {
        Some(CallEvent::NewChannel)
    } else {
        None
    };

    let fields = CallFields {
        other_leg_uuid: state
            .and_then(|s| s.other_leg_uuid.clone())
            .or_else(|| snap.and_then(|s| s.other_leg_uuid.clone())),
        channel_state: state
            .and_then(|s| s.channel_state.as_deref())
            .or_else(|| snap.and_then(|s| s.channel_state.as_deref()))
            .map(LegState::parse),
        context: state
            .and_then(|s| s.initial_context.clone())
            .or_else(|| snap.and_then(|s| s.initial_context.clone())),
        direction: state.and_then(|s| s.call_direction).or_else(|| {
            state.and_then(|s| {
                s.variables
                    .get(ChannelVariable::Direction.as_str())
                    .and_then(|v| CallDirection::from_str(v).ok())
            })
        }),
        caller: state
            .and_then(|s| s.caller_id_number.clone())
            .or_else(|| {
                state.and_then(|s| {
                    s.variables
                        .get(SofiaVariable::SipFromUser.as_str())
                        .cloned()
                })
            })
            .or_else(|| state.and_then(|s| s.dialplan_from.clone())),
        callee: state
            .and_then(|s| s.destination_number.clone())
            .or_else(|| {
                state.and_then(|s| s.variables.get(SofiaVariable::SipToUser.as_str()).cloned())
            })
            .or_else(|| state.and_then(|s| s.dialplan_to.clone())),
    };

    Some(ReaderMsg {
        timestamp: enriched.entry.timestamp.clone(),
        uuid,
        fields,
        event,
    })
}

fn parse_timestamp_secs(ts: &str) -> Option<u64> {
    if ts.len() < 19 {
        return None;
    }
    let year: u64 = ts[0..4].parse().ok()?;
    let month: u64 = ts[5..7].parse().ok()?;
    let day: u64 = ts[8..10].parse().ok()?;
    let hour: u64 = ts[11..13].parse().ok()?;
    let min: u64 = ts[14..16].parse().ok()?;
    let sec: u64 = ts[17..19].parse().ok()?;
    let (y, m) = if month > 2 {
        (year, month - 3)
    } else {
        (year - 1, month + 9)
    };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + day - 1;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn log_age(start: &str, end: &str) -> Duration {
    match (parse_timestamp_secs(start), parse_timestamp_secs(end)) {
        (Some(s), Some(e)) if e >= s => Duration::from_secs(e - s),
        _ => Duration::ZERO,
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86400;
    let hours = secs / 3600;
    let minutes = secs / 60;
    if days > 0 {
        format!("{}d", days)
    } else if hours > 0 {
        format!("{}h", hours)
    } else {
        format!("{}m", minutes)
    }
}

/// Apply pending session-removal requests from the UI thread to the tracker.
/// The tracker lives with the reader, so removal must happen here.
fn drain_session_removals<I: Iterator<Item = String>>(
    tracker: &mut SessionTracker<I>,
    remove_rx: &mpsc::Receiver<String>,
) {
    while let Ok(uuid) = remove_rx.try_recv() {
        tracker.remove_session(&uuid);
    }
}

type LineIter = Box<dyn Iterator<Item = String>>;

/// Build the parse segments: the newest rotated file (if any, skipped with a
/// warning on failure) followed by the current log opened via `open_current`
/// (full-then-tail for the TUI, plain read for --dump).
fn build_segments(
    dir: &Path,
    path: &Path,
    open_current: fn(&Path) -> io::Result<LineIter>,
) -> io::Result<Vec<(String, LineIter)>> {
    let mut segments: Vec<(String, LineIter)> = Vec::new();

    match discover_log_files(dir) {
        Ok(files) => {
            if let Some(prev) = files.iter().rev().find(|f| f.date.is_some()) {
                match open_log_reader(&prev.path) {
                    Ok(reader) => {
                        let name = prev
                            .path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();
                        segments.push((name, reader));
                    }
                    Err(e) => eprintln!(
                        "fslog: skipping rotated history {}: open failed: {e}",
                        prev.path.display()
                    ),
                }
            }
        }
        Err(e) => eprintln!(
            "fslog: skipping rotated history: discovery in {} failed: {e}",
            dir.display()
        ),
    }

    let current = open_current(path)?;
    let current_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    segments.push((current_name, current));
    Ok(segments)
}

fn spawn_reader(
    dir: PathBuf,
    path: PathBuf,
    tx: mpsc::Sender<ReaderMsg>,
    remove_rx: mpsc::Receiver<String>,
) -> io::Result<std::thread::JoinHandle<()>> {
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", path.display()),
        ));
    }
    let handle = std::thread::spawn(move || {
        let segments = match build_segments(&dir, &path, open_full_tail_reader) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("fslog: {}: {e}", path.display());
                return;
            }
        };

        let (chain, _seg_tracker) = TrackedChain::new(segments);
        let stream = LogStream::new(chain);
        let mut tracker = SessionTracker::new(stream);

        while let Some(enriched) = tracker.next() {
            drain_session_removals(&mut tracker, &remove_rx);
            if let Some(msg) = build_update(&enriched, tracker.sessions()) {
                if tx.send(msg).is_err() {
                    break;
                }
            }
        }
    });
    Ok(handle)
}

fn apply_update(state: &mut AppState, msg: ReaderMsg) {
    let ReaderMsg {
        uuid,
        timestamp,
        fields,
        event,
    } = msg;

    if !timestamp.is_empty() && timestamp > state.latest_timestamp {
        state.latest_timestamp.clone_from(&timestamp);
    }

    let is_hangup = matches!(event, Some(CallEvent::Hangup));

    if state.filtered_uuids.contains(&uuid) {
        if is_hangup {
            state.filtered_uuids.remove(&uuid);
            state.request_session_removal(uuid);
        }
        return;
    }

    let uuid_key = uuid.clone();
    if let Some(row) = state.calls.iter_mut().find(|r| r.uuid == uuid_key) {
        if !timestamp.is_empty() {
            row.log_last = timestamp.clone();
        }
        row.fields.merge(fields);
        if is_hangup && row.end.is_none() {
            row.end = Some(CallEnd {
                at: Instant::now(),
                log_ts: timestamp,
            });
        }
    } else if matches!(event, Some(CallEvent::NewChannel)) {
        state.calls.push(CallRow {
            uuid,
            fields,
            log_last: timestamp.clone(),
            log_start: timestamp,
            end: None,
            first_seen: Instant::now(),
        });
    } else {
        if is_hangup {
            // No row exists and none will linger, so the tracker's session
            // state for this UUID would otherwise never be freed.
            state.request_session_removal(uuid_key);
        }
        return;
    }

    if let Some(pos) = state.calls.iter().position(|r| r.uuid == uuid_key) {
        if !state
            .context_filter
            .matches(state.calls[pos].fields.context.as_deref())
        {
            state.calls.remove(pos);
            state.filtered_uuids.insert(uuid_key);
            return;
        }
    }

    state.sort_calls();
}

fn gc_ended(state: &mut AppState) {
    let linger = state.linger;
    let mut expired = Vec::new();
    state.calls.retain(|r| {
        let keep = r.end.as_ref().is_none_or(|e| e.at.elapsed() < linger);
        if !keep {
            expired.push(r.uuid.clone());
        }
        keep
    });
    for uuid in expired {
        state.request_session_removal(uuid);
    }
    if let Some(ref uuid) = state.selected_uuid {
        if !state.calls.iter().any(|r| r.uuid == *uuid) {
            state.selected_uuid = state.calls.first().map(|r| r.uuid.clone());
        }
    }
}

fn render_ui(f: &mut ratatui::Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();

    let active_count = state.calls.iter().filter(|r| r.end.is_none()).count();
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
        Cell::from("A-Leg"),
        Cell::from("B-Leg"),
        Cell::from("Dir"),
        Cell::from("Caller"),
        Cell::from("Callee"),
        Cell::from("State"),
        Cell::from("Duration"),
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
            let style = if r.end.is_some() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(row_cells(r, &state.latest_timestamp).map(Cell::from)).style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Min(12),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(4),
        Constraint::Min(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, chunks[1], table_state);

    match &state.ui_mode {
        UiMode::Table => {}
        UiMode::LegPicker { selected } => render_leg_picker(f, state, area, *selected),
        UiMode::Menu {
            target_uuid,
            selected,
        } => render_menu(f, state, area, target_uuid, *selected),
    }
}

/// Clear a centered popup area and render a bordered selection list in it.
/// Height follows the item count; both dimensions are clamped to the frame.
fn render_popup_list(
    f: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    items: Vec<ListItem>,
    selected: usize,
    width: u16,
) {
    let height = (items.len() as u16 + 2).min(area.height.saturating_sub(4));
    let width = width.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);
    f.render_widget(Clear, popup);
    let list = List::new(items)
        .block(
            Block::default()
                .title(title.to_string())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(selected));
    f.render_stateful_widget(list, popup, &mut list_state);
}

fn render_leg_picker(f: &mut ratatui::Frame, state: &AppState, area: Rect, selected: usize) {
    let row = match state.calls.get(state.selected_index()) {
        Some(r) => r,
        None => return,
    };
    let a_short = short8(&row.uuid);
    let b_short = row
        .fields
        .other_leg_uuid
        .as_deref()
        .map(short8)
        .unwrap_or("?");
    let items = vec![
        ListItem::new(format!("A-leg: {a_short}...")),
        ListItem::new(format!("B-leg: {b_short}...")),
    ];
    render_popup_list(f, area, " Select Leg ", items, selected, 30);
}

fn render_menu(f: &mut ratatui::Frame, state: &AppState, area: Rect, uuid: &str, selected: usize) {
    let uuid_short = short8(uuid);
    let mut items: Vec<ListItem> = vec![
        ListItem::new(format!("search  (fslog search --uuid {uuid_short}...)")),
        ListItem::new(format!("tail    (fslog tail --uuid {uuid_short}...)")),
    ];
    for tool in &state.tools {
        items.push(ListItem::new(format!("{}  ({})", tool.name, tool.command)));
    }
    render_popup_list(f, area, " Actions ", items, selected, 60);
}

fn execute_action(state: &AppState, uuid: &str, action_index: usize) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let from_date = state
        .calls
        .get(state.selected_index())
        .map(|r| &r.log_start)
        .and_then(|ts| ts.get(..10))
        .unwrap_or("");

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    let err = match action_index {
        0 => {
            let exe = std::env::current_exe()?;
            let dir_str = state.dir.to_string_lossy().into_owned();
            let mut args = vec!["--dir", &dir_str, "search", "--uuid", uuid];
            if !from_date.is_empty() {
                args.extend(["--from", from_date]);
            }
            std::process::Command::new(&exe).args(args).exec()
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
    match state.ui_mode {
        UiMode::Table => handle_table_key(state, code),
        UiMode::LegPicker { .. } => handle_leg_picker_key(state, code),
        UiMode::Menu { .. } => handle_menu_key(state, code),
    }
}

fn handle_table_key(state: &mut AppState, code: KeyCode) {
    let idx = state.selected_index();
    let len = state.calls.len();
    match code {
        KeyCode::Char('q') | KeyCode::Esc => state.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') if idx > 0 => {
            state.select_index(idx - 1);
        }
        KeyCode::Down | KeyCode::Char('j') if len > 0 && idx < len - 1 => {
            state.select_index(idx + 1);
        }
        KeyCode::PageUp => {
            let new = idx.saturating_sub(state.page_size);
            state.select_index(new);
        }
        KeyCode::PageDown if len > 0 => {
            let new = (idx + state.page_size).min(len - 1);
            state.select_index(new);
        }
        KeyCode::Home => {
            state.select_index(0);
        }
        KeyCode::End if len > 0 => {
            state.select_index(len - 1);
        }
        KeyCode::Enter => {
            if let Some(row) = state.calls.get(state.selected_index()) {
                state.ui_mode = if row.fields.other_leg_uuid.is_some() {
                    UiMode::LegPicker { selected: 0 }
                } else {
                    UiMode::Menu {
                        target_uuid: row.uuid.clone(),
                        selected: 0,
                    }
                };
            }
        }
        _ => {}
    }
}

fn handle_leg_picker_key(state: &mut AppState, code: KeyCode) {
    let UiMode::LegPicker { selected } = state.ui_mode else {
        return;
    };
    match code {
        KeyCode::Esc | KeyCode::Char('q') => state.ui_mode = UiMode::Table,
        KeyCode::Up | KeyCode::Char('k') if selected > 0 => {
            state.ui_mode = UiMode::LegPicker {
                selected: selected - 1,
            };
        }
        KeyCode::Down | KeyCode::Char('j') if selected == 0 => {
            state.ui_mode = UiMode::LegPicker { selected: 1 };
        }
        KeyCode::Enter => {
            if let Some(row) = state.calls.get(state.selected_index()) {
                let uuid = if selected == 0 {
                    row.uuid.clone()
                } else {
                    row.fields
                        .other_leg_uuid
                        .clone()
                        .unwrap_or_else(|| row.uuid.clone())
                };
                state.ui_mode = UiMode::Menu {
                    target_uuid: uuid,
                    selected: 0,
                };
            }
        }
        _ => {}
    }
}

fn handle_menu_key(state: &mut AppState, code: KeyCode) {
    let item_count = 2 + state.tools.len();
    match code {
        KeyCode::Esc | KeyCode::Char('q') => state.ui_mode = UiMode::Table,
        KeyCode::Up | KeyCode::Char('k') => {
            if let UiMode::Menu { selected, .. } = &mut state.ui_mode {
                if *selected > 0 {
                    *selected -= 1;
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let UiMode::Menu { selected, .. } = &mut state.ui_mode {
                if *selected + 1 < item_count {
                    *selected += 1;
                }
            }
        }
        // Enter is handled in the event loop, which owns the terminal.
        _ => {}
    }
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

    for r in &state.calls {
        println!("{}", row_cells(r, &state.latest_timestamp).join("\t"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timestamp_basic() {
        let secs = parse_timestamp_secs("2025-01-15 10:30:45.123456").unwrap();
        assert_eq!(secs % 86400, 10 * 3600 + 30 * 60 + 45);
    }

    #[test]
    fn parse_timestamp_midnight() {
        let secs = parse_timestamp_secs("2025-06-01 00:00:00.000000").unwrap();
        assert_eq!(secs % 86400, 0);
    }

    #[test]
    fn parse_timestamp_too_short() {
        assert!(parse_timestamp_secs("2025-01-15").is_none());
        assert!(parse_timestamp_secs("").is_none());
    }

    #[test]
    fn log_age_same_timestamp() {
        let d = log_age("2025-01-15 10:30:45.123456", "2025-01-15 10:30:45.999999");
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn log_age_one_minute() {
        let d = log_age("2025-01-15 10:30:00.000000", "2025-01-15 10:31:00.000000");
        assert_eq!(d, Duration::from_secs(60));
    }

    #[test]
    fn log_age_across_midnight() {
        let d = log_age("2025-01-15 23:59:00.000000", "2025-01-16 00:01:00.000000");
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn log_age_across_month() {
        let d = log_age("2025-01-31 23:00:00.000000", "2025-02-01 01:00:00.000000");
        assert_eq!(d, Duration::from_secs(7200));
    }

    #[test]
    fn log_age_reversed_returns_zero() {
        let d = log_age("2025-01-15 10:31:00.000000", "2025-01-15 10:30:00.000000");
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(5)), "0:05");
        assert_eq!(format_duration(Duration::from_secs(59)), "0:59");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1:00");
        assert_eq!(format_duration(Duration::from_secs(754)), "12:34");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1:00:00");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1:01:01");
    }

    #[test]
    fn format_age_minutes() {
        assert_eq!(format_age(Duration::from_secs(0)), "0m");
        assert_eq!(format_age(Duration::from_secs(59)), "0m");
        assert_eq!(format_age(Duration::from_secs(1800)), "30m");
        assert_eq!(format_age(Duration::from_secs(3599)), "59m");
    }

    #[test]
    fn format_age_hours() {
        assert_eq!(format_age(Duration::from_secs(3600)), "1h");
        assert_eq!(format_age(Duration::from_secs(7200)), "2h");
        assert_eq!(format_age(Duration::from_secs(86399)), "23h");
    }

    #[test]
    fn format_age_days() {
        assert_eq!(format_age(Duration::from_secs(86400)), "1d");
        assert_eq!(format_age(Duration::from_secs(259200)), "3d");
    }

    fn state_short(raw: &str) -> String {
        LegState::parse(raw).short()
    }

    #[test]
    fn format_state_cs_prefix() {
        assert_eq!(state_short("CS_EXECUTE"), "EXECUTE");
        assert_eq!(state_short("CS_ROUTING"), "ROUTING");
        assert_eq!(state_short("CS_HANGUP"), "HANGUP");
        assert_eq!(state_short("CS_DESTROY"), "DESTROY");
    }

    #[test]
    fn format_state_abbreviations() {
        assert_eq!(state_short("CS_EXCHANGE_MEDIA"), "MEDIA");
        assert_eq!(state_short("CS_CONSUME_MEDIA"), "CONSUME");
        assert_eq!(state_short("CS_SOFT_EXECUTE"), "SOFTEX");
        assert_eq!(state_short("CS_REPORTING"), "REPORT");
    }

    #[test]
    fn format_state_unknown_passthrough() {
        assert_eq!(state_short("SOMETHING_ELSE"), "SOMETHING_ELSE");
    }

    #[test]
    fn context_filter_exclude() {
        let f = ContextFilter::parse("-recordings,-default");
        assert!(!f.matches(Some("recordings")));
        assert!(!f.matches(Some("default")));
        assert!(f.matches(Some("public")));
        assert!(f.matches(None));
    }

    #[test]
    fn context_filter_include() {
        let f = ContextFilter::parse("public,private");
        assert!(f.matches(Some("public")));
        assert!(f.matches(Some("private")));
        assert!(!f.matches(Some("recordings")));
        assert!(!f.matches(None));
    }

    #[test]
    fn context_filter_none() {
        let f = ContextFilter::parse("");
        assert!(f.matches(Some("anything")));
        assert!(f.matches(None));
    }

    fn make_state() -> AppState {
        AppState::new(
            PathBuf::from("."),
            ContextFilter::None,
            Vec::new(),
            Duration::from_secs(3600),
        )
    }

    #[test]
    fn gc_ended_requests_session_removal_after_linger() {
        let (tx, rx) = mpsc::channel();
        let mut state = make_state();
        state.remove_tx = Some(tx);
        state.linger = Duration::ZERO;
        apply_update(
            &mut state,
            make_update("aaaa", "2025-01-15 10:30:45.000000", false),
        );
        apply_update(
            &mut state,
            make_update("aaaa", "2025-01-15 10:30:50.000000", true),
        );
        gc_ended(&mut state);
        assert!(state.calls.is_empty());
        assert_eq!(rx.try_recv().ok().as_deref(), Some("aaaa"));
    }

    #[test]
    fn hangup_without_row_requests_session_removal() {
        let (tx, rx) = mpsc::channel();
        let mut state = make_state();
        state.remove_tx = Some(tx);
        // Hangup for a call whose New Channel was never seen: no row exists,
        // none will linger, so the session must be freed immediately.
        apply_update(
            &mut state,
            make_update("dddd", "2025-01-15 10:30:45.000000", true),
        );
        assert!(state.calls.is_empty());
        assert_eq!(rx.try_recv().ok().as_deref(), Some("dddd"));
    }

    #[test]
    fn drain_session_removals_drops_tracker_state() {
        let uuid = "11111111-2222-3333-4444-555555555555";
        let lines = vec![format!(
            "{uuid} 2025-01-15 10:30:45.123456 95.00% [DEBUG] test.c:1 hello"
        )];
        let stream = LogStream::new(lines.into_iter());
        let mut tracker = SessionTracker::new(stream);
        while tracker.next().is_some() {}
        assert!(tracker.sessions().contains_key(uuid));

        let (tx, rx) = mpsc::channel();
        tx.send(uuid.to_string()).unwrap();
        drain_session_removals(&mut tracker, &rx);
        assert!(!tracker.sessions().contains_key(uuid));
    }

    fn make_update(uuid: &str, ts: &str, is_hangup: bool) -> ReaderMsg {
        ReaderMsg {
            uuid: uuid.to_string(),
            timestamp: ts.to_string(),
            fields: CallFields {
                channel_state: Some(LegState::parse("CS_EXECUTE")),
                context: Some("public".to_string()),
                direction: Some(CallDirection::Inbound),
                caller: Some("1234".to_string()),
                callee: Some("5678".to_string()),
                ..CallFields::default()
            },
            event: Some(if is_hangup {
                CallEvent::Hangup
            } else {
                CallEvent::NewChannel
            }),
        }
    }

    // A call first seen in a terminal state (its New Channel was never
    // observed) must not produce a row.
    #[test]
    fn no_row_for_call_first_seen_in_terminal_state() {
        let mut state = make_state();
        // First message is a state change to CS_HANGUP (not a Hangup event per
        // current rules)
        let msg = ReaderMsg {
            uuid: "aaaa".to_string(),
            timestamp: "2025-01-15 10:30:45.000000".to_string(),
            fields: CallFields {
                channel_state: Some(LegState::parse("CS_HANGUP")),
                ..CallFields::default()
            },
            event: None,
        };
        apply_update(&mut state, msg);
        // Then CS_DESTROY arrives
        let msg = ReaderMsg {
            uuid: "aaaa".to_string(),
            timestamp: "2025-01-15 10:30:45.000000".to_string(),
            fields: CallFields {
                channel_state: Some(LegState::parse("CS_DESTROY")),
                ..CallFields::default()
            },
            event: Some(CallEvent::Hangup),
        };
        apply_update(&mut state, msg);
        assert!(
            state.calls.is_empty(),
            "call first seen in CS_HANGUP should not produce a row (duration would be 0:00)"
        );
    }

    // Continuation lines at the start of a new file segment must not inherit
    // the previous segment's last timestamp.
    #[test]
    fn timestamp_not_contaminated_across_file_segments() {
        use freeswitch_log_parser::LogStream;

        let uuid = "f2cb66d4-aaaa-bbbb-cccc-dddddddddddd";
        // Segment 1 (rotated file): ends with a timestamped line for a different UUID
        let seg1_lines: Vec<String> = vec![
            format!(
                "eeeeeeee-1111-2222-3333-444444444444 2025-01-15 23:58:03.000000 95.00% [DEBUG] test.c:1 Last line in rotated file"
            ),
        ];
        // Segment 2 (current file): starts with UUID-continuation lines (no timestamp)
        // followed by a full timestamped line
        let seg2_lines: Vec<String> = vec![
            format!("{uuid} CHANNEL_DATA:"),
            format!("{uuid} Channel-State: [CS_EXECUTE]"),
            format!(
                "{uuid} 2025-01-16 08:37:12.000000 95.00% [DEBUG] test.c:1 First real line in new file"
            ),
        ];

        let segments: Vec<(String, Box<dyn Iterator<Item = String>>)> = vec![
            ("rotated.log".to_string(), Box::new(seg1_lines.into_iter())),
            (
                "freeswitch.log".to_string(),
                Box::new(seg2_lines.into_iter()),
            ),
        ];

        let (chain, _) = freeswitch_log_parser::TrackedChain::new(segments);
        let stream = LogStream::new(chain);
        let entries: Vec<_> = stream.collect();

        // The CHANNEL_DATA entry's timestamp must not come from the rotated
        // file's last line.
        let cd_entry = entries
            .iter()
            .find(|e| e.uuid == uuid)
            .expect("should find entry for test UUID");

        assert_ne!(
            cd_entry.timestamp, "2025-01-15 23:58:03.000000",
            "continuation lines in new file segment must not inherit timestamp from previous file"
        );
    }

    // A call seen only in the rotated file must not grow its duration against
    // timestamps from the current file.
    #[test]
    fn call_from_previous_file_not_seen_again_gets_bounded_age() {
        let mut state = make_state();
        // Call appears during rotated file processing
        apply_update(
            &mut state,
            make_update("bbbb", "2025-01-15 23:58:02.000000", false),
        );
        // latest_log_ts advances as we process the current file (different calls)
        apply_update(
            &mut state,
            make_update("cccc", "2025-01-16 09:06:41.000000", false),
        );

        let row = state
            .calls
            .iter()
            .find(|r| r.uuid == "bbbb")
            .expect("should have row for bbbb");
        let dur = call_duration(row);

        // The call was only seen at 23:58:02. 9+ hours of duration is wrong —
        // it should not exceed the call's actual log span.
        assert!(
            dur < Duration::from_secs(3600),
            "call from rotated file not seen in current file should not grow duration against \
             latest_log_ts (got {dur:?}, expected < 1h)"
        );
    }

    // --dump must build rows from the same segment data as the TUI: every row
    // gets a parseable log_start.
    #[test]
    fn fixture_dump_all_calls_have_valid_timestamps() {
        use std::path::Path;

        let dir = Path::new("tests/fixtures");
        let path = dir.join("freeswitch.log");
        if !path.exists() {
            return; // skip if fixtures not available
        }

        let state = process_log(dir, &path, ContextFilter::None)
            .expect("process_log should succeed on fixtures");

        let bad: Vec<_> = state
            .calls
            .iter()
            .filter(|r| parse_timestamp_secs(&r.log_start).is_none())
            .map(|r| &r.uuid)
            .collect();

        assert!(
            bad.is_empty(),
            "all calls should have parseable log_start timestamps: {bad:?}"
        );
    }

    // Fixture check: cross-segment timestamp inheritance must not inflate a
    // call's duration.
    #[test]
    fn fixture_no_cross_file_timestamp_inflation() {
        use std::path::Path;

        let dir = Path::new("tests/fixtures");
        let path = dir.join("freeswitch.log");
        if !path.exists() {
            return;
        }

        let state = process_log(dir, &path, ContextFilter::None)
            .expect("process_log should succeed on fixtures");

        let row = state.calls.iter().find(|r| r.uuid.starts_with("f2cb66d4"));

        if let Some(row) = row {
            let dur = call_duration(row);
            assert!(
                dur < Duration::from_secs(300),
                "f2cb66d4 duration should be ~19s (actual call duration), \
                 not {dur:?} (inflated by timestamp from previous file segment)"
            );
        }
    }

    // Fixture check: rotated-file-only calls keep a bounded duration.
    #[test]
    fn fixture_rotated_only_calls_bounded_duration() {
        use std::path::Path;

        let dir = Path::new("tests/fixtures");
        let path = dir.join("freeswitch.log");
        if !path.exists() {
            return;
        }

        let state = process_log(dir, &path, ContextFilter::None)
            .expect("process_log should succeed on fixtures");

        for prefix in &["031193dc", "0a962643"] {
            if let Some(row) = state.calls.iter().find(|r| r.uuid.starts_with(prefix)) {
                let dur = call_duration(row);
                assert!(
                    dur < Duration::from_secs(300),
                    "{prefix} duration should be ~1s (only seen in rotated file), \
                     not {dur:?} (inflated by latest_log_ts from current file)"
                );
            }
        }
    }
}
