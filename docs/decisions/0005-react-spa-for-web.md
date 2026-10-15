# 0005 — React SPA for Web, No SSR

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

The browser is the primary planning surface. With E2EE (ADR 0009), the server
cannot render user data — it never sees plaintext — so all rendering is
client-side by necessity. The frontend must talk to the Rust core compiled to
WASM, stay offline-capable, and be shared with the Tauri desktop shell.

## Decision

Build a plain client-side SPA: React + TypeScript + Vite + Tailwind +
shadcn/ui + TanStack Query. A small `CoreHost` adapter interface isolates how the
UI reaches the core:

- `WasmCoreHost` (browser): wasm-bindgen bindings; SQLite via wa-sqlite on OPFS
- `TauriCoreHost` (desktop): Tauri commands into the native core

TypeScript types are generated from the Rust core (`ts-rs` or `specta`).
PWA support via `vite-plugin-pwa` for an offline app shell.

## Alternatives considered

- **Next.js / SvelteKit / Remix (SSR)** — server rendering is incompatible with
  E2EE and adds dead machinery; rejected outright.
- **Svelte / Vue / Solid** — all viable; Solid's signals map especially well to
  core subscriptions. React chosen for the largest AI-assistant competence and
  OSS contributor pool; performance differences are irrelevant in a thin view
  layer.
- **Leptos / Yew / Dioxus (Rust UIs)** — pure-stack appeal, but immature
  ecosystems, thin component libraries, and weak AI-assistant support — a bad
  fit for this project's workflow and its contributors.

## Consequences

- One SPA serves browser and desktop; mobile is native, so the SPA can use
  desktop-grade layouts without touch-screen compromises.
- The `CoreHost` adapter keeps future hosts cheap (e.g., Tauri mobile if ever).
- OPFS-backed SQLite gives the browser full offline planning.
