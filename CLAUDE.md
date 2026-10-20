# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`audit` is a Go CLI for a Linux workstation. Each scanning command (`system`, `environment`, `packages`, `repos`, `files`, `configs`, `scripts`, `ai`) produces findings that are saved to SQLite, turned into prioritized tasks, rendered to the terminal, optionally reviewed by an AI CLI (`claude` or `codex`), and optionally written as an HTML report. Some have action subcommands that change the machine (`packages update`, `repos sync`, `files clean`, `configs clean`): planned, confirmed, verified and saved. Bare `audit` is a Bubble Tea dashboard.

Roadmap, open issues and proposals live in `TODO.md`, tagged `(p1)`/`(p3)` (untagged is p2); the global `/todo` and `/todo-pop` commands and SessionStart hook from `~/.shell` read it.

## Commands

- `just` — list the recipes (`justfile`; there is no Makefile).
- `just build` — build `bin/audit`. `just run <args>` builds and runs it.
- `just lint` — `golangci-lint` (v2; goimports local prefix `github.com/njhoffman/audit`).
- `just test` — `go test -race -count=1 ./...`. Renderer: `just test gotestsum|gotestfmt|tparse`.
- `just test-one ./internal/config TestLoad` — one test.
- `just manpage` — render `man/audit.1` from `man/audit.1.md`.
- The justfile exports `GOTOOLCHAIN=local` so the system Go is used.
- Pre-commit gate: `just check` (gofmt check, lint, test, build).
- `just release [patch|minor|major]` — run the gate, then `tools/release`: bump from the CHANGELOG's Unreleased headings (Removed or BREAKING major, Added/Changed/Deprecated minor, else patch; before 1.0 a major bump moves the minor unless `--allow-major`), date the section, commit `Release vX.Y.Z`, annotated tag, `git push --atomic origin main vX.Y.Z`, then `just install` so the binary on PATH (`$(go env GOPATH)/bin/audit`) is the new version. `-n` is a dry run.

## Architecture

```
cmd/audit/cmd/          cobra wiring: root (dashboard/summary/html), one file per command, todo, history, config, export,
                        analyze, tasks web page, sudo session, TUI backend (tui.go: defaultScanner); bins install lives here too
internal/core/          Engine: Resolve (auto/rescan/saved-only), Execute (scan, ignore, save, prune, reconcile tasks), Analyze;
                        one scanner adapter per command, core.Commands, core.ScopeFlags
internal/system/        system scanner over internal/scan/{procs,services,users,logs,programs,storage,resources,updates,security}
internal/environment/   login-shell capture, startup tracing, PATH/env/script checks
internal/packages/      package-manager collectors (uv, pnpm, cargo, go, gem, gh, apt, snap, flatpak, bins), checks,
                        update plans, runtimes
internal/registry/      PyPI, npm, crates.io, Go proxy, rubygems, GitHub lookups feeding the cached packages.Meta
internal/repos/         git repo discovery, local-only inspection and checks; GitHub data via gh api graphql; sync plans
internal/files/         disk usage walk, reclaimable space (caches, build dirs, orphaned data, duplicates); clean plans
internal/configs/       config syntax, program validators, readable credentials, orphaned configs
internal/scripts/       script inventory, header descriptions, static checks (shellcheck, syntax, interpreters, PATH)
internal/ai/            AI CLIs, provider keys by name, ollama, MCP servers, Claude Code hooks/permissions, AI projects
internal/finding/       Finding, Severity, filters, ignore rules
internal/todo/          Priority, Status, Derive and Reconcile
internal/run/           Run, Stat, freshness
internal/store/         SQLite (modernc): runs, findings, tasks, package/repo/runtime meta and tags, updates, script
                        descriptions, tracked bins, LLM cache; schema_version in meta
internal/llm/           claude -p / codex exec client with prompt-hash cache; prompts for reviews, suggestions, explanations
internal/render/        terminal output (lipgloss, glamour)
internal/htmlreport/    self-contained HTML reports, index and tasks page
internal/taskserver/    tasks page served on 127.0.0.1 with a status/note API (per-run token, loopback Host check)
internal/export/        JSON snapshots in the export dir (documented contract: man audit, EXPORT FILES)
internal/tui/           Bubble Tea dashboard, report viewer, task editor (Backend interface)
internal/keys/          dashboard actions, their screens and default keys; validation of tui.keys and tui.fzf_keys
internal/fzf/           fzf interface: list lines, fzf arguments and binds calling back into the hidden fzf-helper command
internal/progress/      stderr progress bar / spinner
internal/exec/          command runner with a Fake for tests
internal/config/        viper loader, defaults and Template (kept in sync by a test); AUDIT_* env; XDG paths
internal/log/           charmbracelet/log setup from the verbosity flags
internal/version/       version, commit, date set by -ldflags
tools/release/          `just release`: changelog-driven semver bump, commit, tag, push
```

A new scanning command implements `core.Scanner` (and `core.Owner` if it supports a narrowed scope) with an adapter in `internal/core/`, gets added to `core.Commands` (and `core.ScopeFlags` if it has a scope flag), a `newXCmd` in its own file under `cmd/audit/cmd/` added to `root.AddCommand`, a case in `defaultScanner` (`cmd/audit/cmd/tui.go`), and a config section.

## Conventions

- Logging: `github.com/charmbracelet/log`; never stdlib `log` or `fmt.Print*` for diagnostics.
- Every flag has a long and a single-letter short form (enforced by `TestEveryFlagHasShortForm`).
- Output options (`--report`, `--list`, `--summary`, `--json`) never scan unless `--rescan` is given.
- Never persist raw shell xtrace output; it echoes variable values. Keep file paths only.
- A new config key goes in `defaults()`, the `Template` (with a comment) and `validate()` if it has a range; `TestTemplateMatchesDefaults` fails if the template drifts.
- When adding or changing a command or flag, update `man/audit.1.md`, `README.md` and `CHANGELOG.md` in the same change.
- Versioning is semver through git tags (`vX.Y.Z`; the binary reports `git describe`). After each finished feature or fix is committed, cut a release with `just release` so every update is tagged and pushed.
