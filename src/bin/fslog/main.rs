mod cli;
mod commands;
mod complete;
#[cfg(feature = "tui")]
mod config;
mod context;
mod dialstring;
mod files;
#[cfg(feature = "tui")]
mod monitor;
mod output;
mod pager;
mod prescan;
mod related;
mod run;

use std::io::{self, Write};
use std::process;

use clap::{CommandFactory, Parser};

use cli::{resolve_color, Cli, Command};
use pager::PagedWriter;

/// Run `body` against the output sink, through a pager when asked for one.
fn paged(pager: bool, body: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> io::Result<()> {
    let mut out = PagedWriter::new(pager);
    let result = body(&mut out);
    result.and(out.finish())
}

/// The one place a command meets its output sink. `monitor` owns the terminal
/// itself, `tail` follows forever and `completions` writes a shell script —
/// none of the three is something to hold in a pager.
fn dispatch(cli: Cli) -> io::Result<()> {
    let Cli {
        dir,
        color,
        pager,
        max_line_bytes,
        command,
    } = cli;
    let color = resolve_color(color);

    match command {
        #[cfg(feature = "tui")]
        Command::Monitor(args) => monitor::run(&dir, args, max_line_bytes),
        Command::Completions { shell } => {
            complete::generate_completions(shell, &mut Cli::command());
            Ok(())
        }
        Command::Tail(args) => {
            commands::tail::run(&dir, &args, color, &mut io::stdout(), max_line_bytes)
        }
        Command::List => paged(pager, |out| commands::list::run(&dir, out)),
        Command::Search(args) => paged(pager, |out| {
            commands::search::run(&dir, &args, color, out, max_line_bytes)
        }),
        Command::Read(args) => paged(pager, |out| {
            commands::read::run(&dir, &args, color, out, max_line_bytes)
        }),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Err(e) = dispatch(Cli::parse()) {
        eprintln!("fslog: {e}");
        process::exit(1);
    }
}
