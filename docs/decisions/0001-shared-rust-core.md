# 0001 — Shared Rust Core Across All Platforms

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Pursecraft is an offline-first budgeting app targeting browser, desktop, iOS, and
Android. The hard parts — budget engine (category math, credit-card handling),
sync protocol, and local persistence — must behave identically everywhere. Writing
them once per platform guarantees eventual divergence and double the bug surface.

## Decision

Implement the domain logic, sync engine, and persistence layer as a single Rust
crate. Compile it:

- natively for desktop (Tauri, in-process), mobile (via UniFFI bindings), and the
  backend (Axum)
- to WASM for the browser

The Rust core is the product; all UIs are thin shells that render state and
dispatch commands.

## Alternatives considered

- **Kotlin Multiplatform shared core** — viable, but the backend would be a second
  implementation or a JVM dependency in the server; Rust covers all targets
  including server natively.
- **Per-platform implementations** — the default for most apps; rejected because
  sync and money math are exactly the code that must never diverge.

## Consequences

- One test suite validates the engine everywhere.
- FFI surface (UniFFI, wasm-bindgen) is extra friction, but UIs are thin so the
  surface stays small.
- Rust's iteration speed is slower; mitigated by heavy unit testing of the pure
  core, where AI assistance is most effective.
