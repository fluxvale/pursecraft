# 0013 — Domains, Hosting, and Single-Image Deployment

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Pursecraft ships as open source (self-hostable) with an optional hosted cloud
tier. The hosted product needs a marketing surface, an app surface, and an API
surface, without compromising the privacy posture of the app itself.

## Decision

Domain topology:

| Host | Purpose | Tech |
| --- | --- | --- |
| `pursecraft.com` | Marketing: SEO, blog, pricing, docs | Astro (+ Starlight for docs) |
| `app.pursecraft.com` | The SPA + WASM core | Static files (React/Vite build) |
| `api.pursecraft.com` | Sync server | Axum + Postgres (Docker) |

- The SPA + WASM bundle is a static artifact — hosted on Cloudflare Pages like
  the marketing site; the API runs on a VPS (Hetzner/Fly.io).
- Auth uses `Authorization`-header device tokens (no cookies), so CORS is a
  simple allowlist (`app.pursecraft.com` + the Tauri origin) with no CSRF
  machinery.
- Marketing and app live on **separate origins** so analytics/trackers never
  touch the app origin — consistent with the "we can't see your data" pitch.
- **The cloud runs the same Docker image self-hosters run.** The image serves
  the SPA + API on one port; cloud and self-host are the same artifact at
  different scales. The marketing site is not part of the image.

## Alternatives considered

- **SSR-hosted app (Next.js/Vercel)** — incompatible with E2EE rendering
  (ADR 0005); rejected.
- **Single domain with path routing** — workable, but separate origins give
  cleaner privacy separation and independent caching/deploy of marketing vs app.
- **Separate cloud-only backend image** — rejected: self-hosting would bit-rot.
  Running production on the self-host artifact guarantees it always works
  (dogfooding).

## Consequences

- One deploy pipeline for the product artifact; marketing deploys
  independently.
- Self-hosters get the exact software the cloud runs, on day one, forever.
- Local dev stays boring: Vite `:5173`, Axum `:8080`, Astro `:4321`.
