# 0012 — CLI, MCP, Webhooks, and Direct API Access

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Users will want programmatic access — AI agents (MCP), scripts, CLIs, and their
own services. Under E2EE (ADR 0009), any consumer of plaintext must hold the
user's keys. This ADR fixes what is and isn't possible.

## Decision

The rule: **anything holding the user's keys sees data; everything else sees
only ciphertext.**

Sanctioned access paths:

1. **`pursecraft` CLI + MCP server** — one binary, a headless E2EE client over
   the same Rust core. `pursecraft mcp` (stdio JSON-RPC) and CLI subcommands.
   Supports reads and writes (agents can log transactions; ops are attributed to
   the agent's device, auditable and revocable per device).
2. **Device pairing** — WhatsApp-Web-style flow (CLI generates a keypair, an
   existing device approves and wraps budget keys to it). Reused for mobile
   onboarding; built in the core from the start.
3. **"Create API device"** — in-app export of a key bundle (device keypair +
   API token) so scripts skip the interactive dance.
4. **`pursecraft serve`** — plain REST/JSON API on localhost over the decrypted
   local SQLite, for ordinary HTTP clients and agent frameworks; remote
   integrations run the headless client on the user's own server.
5. **Webhooks** — server-sent notifications carrying metadata only (budget_id,
   sequence range, device_id, event type) or encrypted payloads. Receivers must
   be E2EE clients. Per-endpoint secrets for revocation.

Not possible, by design: third-party SaaS reading plaintext without keys.

**Protocol spec:** the sync protocol, key hierarchy, op/snapshot formats, and
crypto choices are documented publicly and versioned. Once CLI/MCP/webhooks
ship, the spec is frozen (versioned changes only) so third parties can build on
it.

## Alternatives considered

- **Server-side REST API returning plaintext JSON** — incompatible with E2EE;
  also loses the offline story. A headless client speaking the sync protocol is
  what we want anyway.
- **Sharing keys with SaaS integrations as a supported feature** — users may
  choose it at their own risk; the product does not facilitate it beyond a
  warning (Bitwarden's line).

## Consequences

- E2EE costs the API story nothing — access moves from "server endpoint" to
  "headless client," which offline support needs regardless.
- Ecosystem flywheel: a documented, stable spec turns power users into
  integrators.
- Audit trail synergy: agent/script writes are first-class ops with device
  attribution.
