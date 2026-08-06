use std::io::{self, IsTerminal, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

use log::warn;

/// Output sink that pipes through a pager when asked to.
///
/// The child is spawned on the first write, not on construction: an empty
/// result set, a confirmation prompt or a progress line must never end up
/// behind a pager holding the terminal.
pub struct PagedWriter {
    target: Target,
}

enum Target {
    Stdout(io::Stdout),
    Deferred,
    Pager { child: Child, stdin: ChildStdin },
}

impl PagedWriter {
    pub fn new(use_pager: bool) -> Self {
        let target = if use_pager && io::stdout().is_terminal() {
            Target::Deferred
        } else {
            Target::Stdout(io::stdout())
        };
        PagedWriter { target }
    }

    pub fn finish(self) -> io::Result<()> {
        if let Target::Pager { mut child, stdin } = self.target {
            drop(stdin);
            match child.wait() {
                Ok(status) if !status.success() => warn!("pager exited with {status}"),
                Ok(_) => {}
                Err(e) => warn!("waiting for the pager failed: {e}"),
            }
        }
        Ok(())
    }

    fn sink(&mut self) -> &mut dyn Write {
        if matches!(self.target, Target::Deferred) {
            self.target = spawn();
        }
        match self.target {
            Target::Stdout(ref mut out) => out,
            Target::Pager { ref mut stdin, .. } => stdin,
            // `spawn()` never returns Deferred, so this is the compiler's
            // exhaustiveness check rather than a reachable state.
            Target::Deferred => unreachable!("spawn resolves the deferred target"),
        }
    }
}

/// `-R` passes colour through, `-F` quits when the output fits one screen, `-X`
/// leaves it on the terminal after quitting.
fn spawn() -> Target {
    let pager = std::env::var("FSLOG_PAGER").unwrap_or_else(|_| "less".to_string());
    let mut parts = pager.split_whitespace();
    let Some(program) = parts.next() else {
        return Target::Stdout(io::stdout());
    };
    let args: Vec<&str> = parts.collect();
    let default_args = ["-RFX"];
    let args = if args.is_empty() && program == "less" {
        &default_args[..]
    } else {
        &args[..]
    };

    match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => match child.stdin.take() {
            Some(stdin) => Target::Pager { child, stdin },
            None => {
                warn!("pager {program} has no stdin pipe; output goes to stdout");
                Target::Stdout(io::stdout())
            }
        },
        Err(e) => {
            warn!("failed to spawn pager {program}: {e}; output goes to stdout");
            Target::Stdout(io::stdout())
        }
    }
}

impl Write for PagedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink().write(buf)
    }

    /// Nothing written yet means nothing to flush — and spawning the pager here
    /// would defeat the deferral, since `tail`-style loops flush per entry.
    fn flush(&mut self) -> io::Result<()> {
        match self.target {
            Target::Deferred => Ok(()),
            Target::Stdout(ref mut out) => out.flush(),
            Target::Pager { ref mut stdin, .. } => stdin.flush(),
        }
    }
}

/// A reader that closed its end — the pager quit, or a downstream `| head` had
/// enough — is normal termination. Every other write error is real and must
/// surface: stopping on any I/O error would hide the difference between "the
/// reader went away" and "we wrote truncated garbage".
pub fn is_broken_pipe(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::BrokenPipe
}
