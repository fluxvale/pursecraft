//! The relay binary (ADRs 0013, 0024): local dev binds `127.0.0.1:8080`,
//! one process per data directory.
//!
//! Environment: `PURSECRAFT_DATA_DIR` (default `data`) and
//! `PURSECRAFT_BIND` (default `127.0.0.1:8080`). First boot writes the
//! enrollment secret to `<data>/enrollment.secret` — read it once, keep
//! it off the network (ADR 0024).

use std::path::Path;
use std::sync::Arc;

use pursecraft_api::{AppState, router};

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
    if let Err(e) = axum::serve(listener, router(state)).await {
        eprintln!("pursecraft-api: server error: {e}");
        std::process::exit(1);
    }
}
