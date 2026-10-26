//! The relay binary (ADRs 0013, 0024): local dev binds `127.0.0.1:8080`,
//! one process per data directory.
//!
//! Environment: `PURSECRAFT_DATA_DIR` (default `data`) and
//! `PURSECRAFT_BIND` (default `127.0.0.1:8080`). First boot writes the
//! enrollment secret to `<data>/enrollment.secret` — read it once, keep
//! it off the network (ADR 0024).
//!
//! Shutdown (ADR 0026): SIGTERM or SIGINT stops the listener and drains
//! in-flight requests for at most [`SHUTDOWN_WINDOW`] — sized inside the
//! fleet's 30s termination grace so the process is never SIGKILLed
//! mid-fsync. Nothing needs flushing: appends commit per-op under the
//! request and the auth db commits before acknowledging (ADR 0024), so a
//! drained request leaves nothing half-written; a window overrun exits
//! and leaves boot to repair the torn tail (ADR 0018), exactly as a
//! crash would.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pursecraft_api::{AppState, router};

/// How long SIGTERM drains in-flight requests before exiting anyway.
/// Appends are fsync-per-op under the request (ADR 0024), so seconds
/// cover any honest batch; the bound exists so the fleet's 30s
/// termination grace never ends the process mid-drain (ADR 0026).
const SHUTDOWN_WINDOW: Duration = Duration::from_secs(25);

/// Resolves on the drain trigger: SIGTERM (what the fleet sends) or
/// SIGINT (interactive Ctrl-C).
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

/// The non-Unix fallback: Ctrl-C alone (there is no SIGTERM to catch).
#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    let data_dir = std::env::var("PURSECRAFT_DATA_DIR").unwrap_or_else(|_| "data".into());
    let bind = std::env::var("PURSECRAFT_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let state = match AppState::open(Path::new(&data_dir)) {
        Ok(state) => Arc::new(state),
        Err(e) => {
            eprintln!("pursecraft-api: cannot open {data_dir}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "pursecraft-api: serving {bind} from {data_dir} (enrollment secret: {data_dir}/enrollment.secret)"
    );
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("pursecraft-api: cannot bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    // The drain trigger rides a oneshot so the same signal both starts
    // the graceful shutdown inside axum and bounds it here (ADR 0026).
    let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<()>();
    let serve = axum::serve(listener, router(state)).with_graceful_shutdown(async move {
        let _ = drain_rx.await;
    });
    // WithGracefulShutdown is IntoFuture (not Future) — resolve it once,
    // pinned, so the select and the bounded wait share one drain.
    let mut serve = std::pin::pin!(serve.into_future());
    tokio::select! {
        _ = shutdown_signal() => {
            eprintln!("pursecraft-api: shutdown signal received; draining in-flight requests");
            let _ = drain_tx.send(());
        }
        result = serve.as_mut() => {
            // serve resolves only after its shutdown signal fires — an
            // early return is a listener failure.
            eprintln!("pursecraft-api: server error: {result:?}");
            std::process::exit(1);
        }
    }
    match tokio::time::timeout(SHUTDOWN_WINDOW, serve.as_mut()).await {
        Ok(Ok(())) => eprintln!("pursecraft-api: drained; exiting"),
        Ok(Err(e)) => {
            eprintln!("pursecraft-api: server error while draining: {e}");
            std::process::exit(1);
        }
        Err(_) => eprintln!(
            "pursecraft-api: shutdown window of {}s elapsed with requests in flight; exiting — the next boot repairs any torn tail",
            SHUTDOWN_WINDOW.as_secs()
        ),
    }
}
