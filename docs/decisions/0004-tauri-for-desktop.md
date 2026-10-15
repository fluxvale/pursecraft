# 0004 — Tauri for Desktop

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Desktop is the planning surface alongside the browser, but it is the least
important platform — mobile capture and the web app take priority. The Rust core
runs natively in-process, so any desktop shell is a thin view layer.

## Decision

Wrap the web SPA in Tauri v2. The Tauri shell talks to the native Rust core
in-process via Tauri commands (the `TauriCoreHost` adapter), using a real local
SQLite file — no FFI layer beyond Tauri's own IPC, no separate browser-engine
runtime like Electron.

## Alternatives considered

- **Electron** — heavier (bundled Chromium, high RAM) for no benefit over Tauri.
- **Slint / egui / iced** — genuinely native Rust UIs. Slint is the designated
  escape hatch if webview pain ever dominates; egui/iced lack the polish for a
  consumer finance app today.
- **Per-OS native (SwiftUI + WinUI + GTK)** — best look, three UIs to maintain;
  poor use of effort given desktop's priority.

## Consequences

- The desktop app is nearly free once the web SPA exists — same frontend, small
  adapter swap.
- WebKitGTK quirks on Linux are the known pain point; acceptable for v1.
- The UI layer is swappable by design; choosing Tauri now forecloses nothing.
