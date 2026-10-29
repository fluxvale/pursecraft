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
            stdin: if is_login && !stdin_is_tty {
                read_stdin()
            } else {
                String::new()
            },
            e2ee: e2ee_enabled(),
            terminal: stdin_is_tty.then(|| Box::new(StdinTerminal) as Box<dyn Terminal>),
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

/// The real terminal (ADR 0030): form lines and prompts go to stderr —
/// stdout keeps only the final answer — lines echo (nothing secret in
/// them), and the enrollment secret is read hidden via rpassword, which
/// prompts and reads the controlling TTY with echo off (`/dev/tty`, so a
/// redirected stderr never eats the prompt).
struct StdinTerminal;

impl Terminal for StdinTerminal {
    fn say(&mut self, line: &str) -> std::io::Result<()> {
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(line.as_bytes())?;
        stderr.write_all(b"\n")?;
        stderr.flush()
    }

    fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(prompt.as_bytes())?;
        stderr.flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line)
    }

    fn read_secret(&mut self, prompt: &str) -> std::io::Result<String> {
        rpassword::prompt_password(prompt)
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
