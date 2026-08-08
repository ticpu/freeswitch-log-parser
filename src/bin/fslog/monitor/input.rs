//! Key handling and the external tools a row can launch.

use std::io;

use ratatui::crossterm::event::KeyCode;
use ratatui::crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use ratatui::crossterm::ExecutableCommand;

use super::model::{AppState, UiMode};

pub(super) fn execute_action(state: &AppState, uuid: &str, action_index: usize) -> io::Result<()> {
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

pub(super) fn handle_key(state: &mut AppState, code: KeyCode) {
    match state.ui_mode {
        UiMode::Table => handle_table_key(state, code),
        UiMode::LegPicker { .. } => handle_leg_picker_key(state, code),
        UiMode::Menu { .. } => handle_menu_key(state, code),
    }
}

pub(super) fn handle_table_key(state: &mut AppState, code: KeyCode) {
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

pub(super) fn handle_leg_picker_key(state: &mut AppState, code: KeyCode) {
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

pub(super) fn handle_menu_key(state: &mut AppState, code: KeyCode) {
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
