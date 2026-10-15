# 0002 — Rust (Axum) Backend Over Elixir

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

The backend is primarily a rendezvous point for the sync protocol: it stores
operations, assigns canonical order, and distributes deltas. Household-scale
concurrency (dozens of devices) is the upper bound for the foreseeable future,
plus a hosted cloud tier.

## Decision

Use Rust with Axum and PostgreSQL, shipped as a single Docker image. Compile the
shared core crate directly into the server so validation, conflict rules, and
domain logic are literally the same code as the clients.

## Alternatives considered

- **Elixir/Phoenix** — best-in-class realtime fan-out (PubSub), faster iteration.
  Rejected because its strengths (massive concurrency, hot reload) are irrelevant
  at our scale, and the domain/sync logic could not be shared with clients —
  the budget engine would exist twice in two languages.
- **Go** — good ops story, but no path to sharing the core crate.

## Consequences

- One budget engine everywhere; server-side validation uses the same code as
  clients.
- Single-binary/self-contained deployment makes self-hosting trivial — a key
  selling point for the open-source release.
- Slower backend iteration; acceptable because the backend is intentionally
  thin (store, order, relay).
