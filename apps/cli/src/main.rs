//! The thin binary (ADR 0023): the only reader of the process environment
//! and the wall clock; everything else is injected into the library.

use std::io::Write;
use std::process::ExitCode;

use pursecraft_cli::{Context, home, run};
use pursecraft_core::date::Date;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = run(&args, || {
        let home = home::data_home()?;
        Ok(Context {
            home,
            today: today_local(),
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
