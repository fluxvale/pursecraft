# 0003 — Native Mobile (SwiftUI + Jetpack Compose) Over Flutter

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Mobile is a capture-first daily driver (quick-add transactions while out
shopping), so platform feel — instant startup, haptics, correct keyboards,
biometrics, home-screen widgets — matters more than usual. The business logic
already lives in the shared Rust core (see ADR 0001), so the UI layer is thin by
design.

## Decision

Build two native UIs: SwiftUI for iOS and Jetpack Compose for Android, both
consuming the Rust core through UniFFI-generated bindings.

## Alternatives considered

- **Flutter** — the usual rationale ("share logic across platforms") is already
  solved by Rust; it would only dedupe the deliberately thin view layer while
  adding Dart, a second runtime, and FFI bridging. It would also form an orphaned
  third UI stack alongside the web SPA. Its non-native look/feel fights the
  checkout-line use case.
- **Compose Multiplatform** — the honest middle ground and the fallback if mobile
  scope ever grows into a full editing app; UniFFI speaks Kotlin natively.
  Rejected for v1 because two thin UIs are cheaper than one non-standard one.
- **PWA only** — a native icon that opens instantly with biometrics beats a PWA
  in a checkout line.

## Consequences

- Two languages and two codebases: every screen and fix happens twice.
- Scope discipline is essential — capture-first scope (ADR 0011) keeps the 2x
  tax small.
- OSS contributors need per-platform skills; both talent pools are large.
