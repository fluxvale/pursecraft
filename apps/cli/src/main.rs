//! The thin binary (ADRs 0023, 0025, 0030): the only reader of the process
//! environment and the wall clock; everything else is injected into the
//! library. `login` alone touches the interactive side: when stdin is a
//! terminal it gets the form channel (choice screen, domain prompt, hidden
//! secret via rpassword — prompts to stderr, stdout stays the answer), and
//! when it is not, the enrollment secret is read from stdin and the hosted
//! relay is the default server. No other command ever blocks on a
//! terminal.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use pursecraft_cli::{Context, Terminal, home, run};
use pursecraft_core::date::Date;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let is_login = args.first().is_some_and(|first| first == "login");
    // ADR 0030: the form exists only on a terminal; a piped stdin is the
    // secret's channel and the hosted relay is the default server.
    let stdin_is_tty = is_login && std::io::stdin().is_terminal();
    let out = run(&args, || {
        let home = home::data_home()?;
        Ok(Context {
            home,
            today: today_local(),
            // LAZY (ADR 0030 §5, as amended): the source is called only
            // after the fail-early probe passes — a dead relay answers
            // before the process ever blocks on the writer's pipe.
            piped_secret: (!stdin_is_tty).then(|| Box::new(read_stdin) as _),
            e2ee: e2ee_enabled(),
            terminal: stdin_is_tty.then(|| Box::new(StdinTerminal::new()) as Box<dyn Terminal>),
        })
    });
    // A closed pipe (e.g. `pursecraft list | head`) is a truncation, not a
    // crash — write errors are ignored and the exit code stands.
    if !out.stdout.is_empty() {
        let _ = std::io::stdout().write_all(out.stdout.as_bytes());
        let _ = std::io::stdout().flush();
    }
    if !out.stderr.is_empty() {
        let _ = std::io::stderr().write_all(out.stderr.as_bytes());
        let _ = std::io::stderr().flush();
    }
    ExitCode::from(u8::try_from(out.code).unwrap_or(1))
}

/// The real terminal (ADR 0030 §3/§6, fix round 2): the form lives on
/// ONE descriptor — the controlling terminal (`/dev/tty`), opened once
/// for reading and writing. Everything the form shows goes there, every
/// answer (echoed lines and the hidden secret) is read from there, and
/// the echo-off span around the probe (`tcsetattr`) plus the drain
/// before the hidden read (`tcflush`) ride the same tty — stdin's
/// terminal-ness only decides whether the form runs at all, so a stdin
/// that happens to be a different tty can neither capture the secret nor
/// split the conversation. Without a controlling terminal the lines fall
/// back to stderr/stdin and the hidden read fails loudly on its own.
/// stdout keeps only the final answer. (The echo span is unix termios;
/// elsewhere the span is a no-op and rpassword's own hidden read is the
/// whole guarantee.)
struct StdinTerminal {
    tty: Option<std::fs::File>,
    /// The termios state to restore after the hidden span (fix round 2).
    #[cfg(unix)]
    saved_termios: Option<nix::sys::termios::Termios>,
}

impl StdinTerminal {
    fn new() -> Self {
        Self {
            tty: std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .ok(),
            #[cfg(unix)]
            saved_termios: None,
        }
    }

    /// One write to the controlling terminal, falling back to stderr.
    fn put(&self, text: &str) -> std::io::Result<()> {
        match &self.tty {
            Some(tty) => {
                use std::io::Write;
                let mut tty = tty;
                tty.write_all(text.as_bytes())?;
                tty.flush()
            }
            None => {
                use std::io::Write;
                let mut stderr = std::io::stderr().lock();
                stderr.write_all(text.as_bytes())?;
                stderr.flush()
            }
        }
    }
}

impl Terminal for StdinTerminal {
    fn say(&mut self, line: &str) -> std::io::Result<()> {
        self.put(&format!("{line}\n"))
    }

    fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
        use std::io::BufRead;
        self.put(prompt)?;
        let Some(tty) = self.tty.as_ref() else {
            // No controlling terminal: read stdin, as before — the hidden
            // read will fail loudly if this ever mattered.
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            return Ok(line);
        };
        let mut reader = std::io::BufReader::new(tty.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Ok(line)
    }

    fn hide_input(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use nix::sys::termios::{self as t, LocalFlags, SetArg};
            let Some(tty) = self.tty.as_ref() else {
                return Ok(()); // nothing to control; reads fail loudly later
            };
            let saved = t::tcgetattr(tty)?;
            let mut quiet = saved.clone();
            quiet.local_flags &= !LocalFlags::ECHO;
            t::tcsetattr(tty, SetArg::TCSANOW, &quiet)?;
            self.saved_termios = Some(saved);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    fn show_input(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use nix::sys::termios::SetArg;
            if let (Some(saved), Some(tty)) = (self.saved_termios.take(), self.tty.as_ref()) {
                nix::sys::termios::tcsetattr(tty, SetArg::TCSANOW, &saved)?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    fn read_secret(&mut self, prompt: &str) -> std::io::Result<String> {
        // Drain everything that arrived while echo was off (§6): those
        // bytes were never echoed and are discarded — never the secret.
        #[cfg(unix)]
        if let Some(tty) = self.tty.as_ref() {
            nix::sys::termios::tcflush(tty, nix::sys::termios::FlushArg::TCIFLUSH)?;
        }
        let secret = rpassword::prompt_password(prompt);
        // The hidden read restores what IT saved (echo-off); restore the
        // pre-span state so the terminal is exactly as the user left it.
        let _ = self.show_input();
        secret
    }
}

/// The enrollment secret (ADR 0025): all of stdin, first line used. Read
/// only for a piped `login` — scripts pipe it; a terminal gets the hidden
/// prompt instead (ADR 0030).
fn read_stdin() -> String {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

/// The self-host E2EE switch (ADR 0028): `PURSECRAFT_E2EE=off` selects the
/// plaintext mode ADR 0009 allows; anything else — unset included — is E2EE.
/// Read here, with the rest of the environment, so the library stays fully
/// injectable.
fn e2ee_enabled() -> bool {
    std::env::var_os("PURSECRAFT_E2EE").is_none_or(|v| v != "off")
}

/// Today's local civil date (ADR 0023): jiff resolves the system timezone —
/// a UTC-only today would misdate every capture west of midnight UTC.
fn today_local() -> Date {
    let today = jiff::Zoned::now().date();
    Date::new(
        u16::try_from(today.year()).expect("year fits u16"),
        u8::try_from(today.month()).expect("month is 1..=12"),
        u8::try_from(today.day()).expect("day is 1..=31"),
    )
    .expect("today is a valid civil date")
}
