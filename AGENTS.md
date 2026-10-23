# AGENTS.md

Instructions for AI coding agents working in this repository.

Pursecraft is an offline-first, source-available budgeting app (YNAB-style) with a
shared Rust core, native mobile apps, a React SPA, and a self-hostable Axum
backend. Before making architectural decisions, read `docs/decisions/` — the
ADRs record what was decided, why, and which alternatives were rejected. Do not
re-litigate settled decisions.

## Rules

### 1. Be lazy (in the good way)

Optimize for the least total work that fully solves the problem — now and in the
future.

- **Be concise, not verbose.** The shortest solution that fully solves the task
  wins. No speculative features, no defensive code for impossible cases, no
  premature configurability, no extra comments explaining obvious code.
- **Don't repeat yourself.** When logic appears twice, extract an abstraction.
  When an abstraction gets repeated, question the abstraction. Repetition is a
  bug incubator.
- **Automate anything done twice.** Manual steps become scripts; recurring
  checks become CI. If you solve a problem with a manual procedure, leave
  behind the automation instead of instructions.
- **Look before you build.** Search the codebase (and its dependencies) for an
  existing utility before writing a new one. The best new code is often none.
- **Prefer deletion.** Removing dead code, unused dependencies, and
  unnecessary options is progress. Don't work around code that should be
  deleted.
- **Small diffs.** Touch only what the task requires; leave unrelated code
  alone.

### 2. Decisions live in ADRs

Every "why" behind the codebase belongs in `docs/decisions/` — not in chat,
memory, or scattered prose.

- **Refer before explaining.** When a question is answered by an existing ADR,
  point to it instead of re-explaining or re-deciding.
- **Record as you go.** When a task makes a new decision or changes one, create
  a new ADR (next 4-digit number) or supersede an existing one — as part of the
  task, not an afterthought.
- **Link, don't restate.** In Markdown documents, always link to the ADR file
  (e.g. [ADR 0007](docs/decisions/0007-oplog-sync-protocol.md)) rather than
  retelling its rationale.
- **Short refs in code.** Code comments may cite the ADR number alone:
  `// See ADR 0007`. Don't duplicate the reasoning in the comment.

### 3. Plan in GitHub issues

Planning and task tracking live in GitHub issues at
[fluxvale/pursecraft](https://github.com/fluxvale/pursecraft).

- **Decide before building.** Design decisions are settled in the issue before
  any implementation starts. Don't open a PR that settles an undecided design.
- **Reference ADRs in issues.** Link relevant ADRs so discussions build on
  settled context; the issue states what's new, not what's already decided.
- **Graduate outcomes.** When an issue settles a lasting decision, capture it in
  a new (or superseding) ADR — see Rule 2 — then implement.

### 4. Review before you open a PR

- **Hostile subagent review.** Before opening a PR, start a subagent to review
  the pending work adversarially — bugs, edge cases, security issues, scope
  creep, ADR violations. Fix what it finds before the PR goes up.
- **Re-review deltas.** Any commit pushed after the hostile review — including
  fixes it demanded — gets a delta re-check (same reviewer, fresh diff) before
  the merge is requested. A green CI run is not a review.
- **Run CI locally.** Run the exact tools CI runs (lint, typecheck, format,
  tests) and make them pass before opening a PR. CI is the last check, never
  the first.

### 5. Commits and PR titles

- **Conventional commits.** Commit messages follow the conventional commits
  format: `type(scope): short imperative description` — e.g.
  `feat(core): parse HLC timestamps`.
- **Squash merges only.** PRs are squash-merged, so the PR title becomes the
  commit message. Write PR titles as conventional commits that summarize the
  whole PR, not the last commit on it.

### 6. Work in git worktrees

All work happens in a dedicated git worktree, never in the primary checkout —
this is what lets multiple agents work in parallel on the same repo.

- **One worktree per task.** Branch off `main` and create the worktree in one
  step, named `pursecraft-<issue_number>-<part-of-the-issue-name-in-kebab-case>`
  — e.g. issue #12 "Design the data model" becomes
  `git worktree add ../pursecraft-12-data-model -b <branch>`. One branch, one
  worktree, one issue.
- **Keep the primary checkout clean.** It stays on `main` as the reference
  point; no direct edits there.
- **Clean up when merged.** Remove the worktree (`git worktree remove`) and
  delete its branch after the PR merges.

### 7. One source of truth for agent tooling

Agent configuration follows the core-and-adapters pattern (see
[ADR 0001](docs/decisions/0001-shared-rust-core.md)): implement once, adapt
thinly.

- **Instructions.** `AGENTS.md` is canonical. Tools with their own entry-file
  convention get a symlink (e.g. `CLAUDE.md` → `AGENTS.md`), never a copy;
  tools that read `AGENTS.md` natively need nothing.
- **Checks.** Each automated check lives once in `scripts/ci/` as a plain
  runnable script. Tool hooks and plugins are thin adapters that invoke the
  scripts — never re-implement a check inline in a tool's config.
- **Adapters only where supported.** Wire adapters only for tools with
  project-level hook support (e.g. `.claude/settings.json`,
  `.opencode/plugin/`). Tools without it (e.g. Codex CLI) rely on the scripts
  being documented and runnable (e.g. `make check`) — Rules 1 and 4 already
  point agents at them.
