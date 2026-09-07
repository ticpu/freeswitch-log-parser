mod cli;
mod commands;
mod complete;
#[cfg(feature = "tui")]
mod config;
mod context;
mod dialstring;
mod env;
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
use run::RunCtx;

/// Run `body` against the output sink, through a pager when asked for one.
fn paged(
    pager: bool,
    body: impl FnOnce(&mut dyn Write) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut out = PagedWriter::new(pager)?;
    let result = body(&mut out);
    let finished = out.finish();
    result.and(finished.map_err(anyhow::Error::from))
}

/// The one place a command meets its output sink. `monitor` owns the terminal
/// itself, `tail` follows forever and `completions` writes a shell script —
/// none of the three is something to hold in a pager.
fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let Cli {
        dir,
        color,
        pager,
        max_line_bytes,
        command,
    } = cli;
    let ctx = RunCtx {
        dir,
        color: resolve_color(color),
        max_line_bytes,
    };

    match command {
        #[cfg(feature = "tui")]
        Command::Monitor(args) => monitor::run(&ctx, args),
        Command::Completions { shell } => {
            complete::generate_completions(shell, &mut Cli::command());
            Ok(())
        }
        Command::Tail(args) => commands::tail::run(&ctx, &args, &mut io::stdout()),
        Command::List => paged(pager, |out| commands::list::run(&ctx, out)),
        Command::Search(args) => paged(pager, |out| commands::search::run(&ctx, &args, out)),
        Command::Read(args) => paged(pager, |out| commands::read::run(&ctx, &args, out)),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Err(e) = dispatch(Cli::parse()) {
        // `{e:#}` prints the whole context chain; `{e}` prints only the
        // outermost, which is the one the caller already knew.
        eprintln!("fslog: {e:#}");
        process::exit(1);
    }
}
