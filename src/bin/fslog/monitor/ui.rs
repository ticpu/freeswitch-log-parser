//! Widgets — the call table and the popups over it.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState,
};

use freeswitch_log_parser::CallDirection;

use super::model::{state_label, AppState, CallRow, UiMode};
use super::time::{call_age, call_duration, format_age, format_duration};

pub(super) fn format_direction(direction: Option<CallDirection>) -> &'static str {
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
pub(super) fn short8(uuid: &str) -> &str {
    if uuid.len() > 8 {
        &uuid[..8]
    } else {
        uuid
    }
}

/// The 9 display columns shared by the TUI table and `--dump` output, so the
/// scripting surface cannot drift from what the TUI shows.
pub(super) fn row_cells(r: &CallRow, latest: &str) -> [String; 9] {
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
        state_label(r.fields.channel_state, r.fields.call_state).unwrap_or_else(|| "-".to_string()),
        format_duration(call_duration(r)),
        format_age(call_age(r, latest)),
        r.fields.context.as_deref().unwrap_or("-").to_string(),
    ]
}
pub(super) fn render_ui(f: &mut ratatui::Frame, state: &AppState, table_state: &mut TableState) {
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
pub(super) fn render_popup_list(
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

pub(super) fn render_leg_picker(
    f: &mut ratatui::Frame,
    state: &AppState,
    area: Rect,
    selected: usize,
) {
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

pub(super) fn render_menu(
    f: &mut ratatui::Frame,
    state: &AppState,
    area: Rect,
    uuid: &str,
    selected: usize,
) {
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
