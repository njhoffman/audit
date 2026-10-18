# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`audit` is a Go CLI for a Linux workstation. Each scanning command (`system`, `environment`, `packages`) produces findings that are saved to SQLite, turned into prioritized tasks, rendered to the terminal, optionally reviewed by the `claude` CLI, and optionally written as an HTML report. Bare `audit` is a Bubble Tea dashboard.

Planned commands not yet built: `repos`, `files`, `configs`, `scripts`, `ai`, and the package update/registry phases of `packages`.

## Commands

- `just` — list the recipes (`justfile`; there is no Makefile).
- `just build` — build `bin/audit`. `just run <args>` builds and runs it.
- `just lint` — `golangci-lint` (v2; goimports local prefix `github.com/njhoffman/audit`).
- `just test` — `go test -race -count=1 ./...`. Renderer: `just test gotestsum|gotestfmt|tparse`.
- `just test-one ./internal/config TestLoad` — one test.
- `just manpage` — render `man/audit.1` from `man/audit.1.md`.
- The justfile exports `GOTOOLCHAIN=local` so the system Go is used.
- Pre-commit gate: `just check` (gofmt check, lint, test, build).

## Architecture

```
cmd/audit/cmd/        cobra wiring: root (dashboard/summary/html), scan commands, todo, history, config, TUI backend
internal/core/        Engine: Resolve (auto/rescan/saved-only), Execute (scan, ignore, save, prune, reconcile tasks), Analyze; scanner adapters
internal/system/      system scanner over internal/scan/{procs,services,users,logs,programs}
internal/environment/ login-shell capture, startup tracing, PATH/env/script checks
internal/packages/    package-manager collectors and checks
internal/finding/     Finding, Severity, filters, ignore rules
internal/todo/        Priority, Status, Derive and Reconcile
internal/run/         Run, Stat, freshness
internal/store/       SQLite (modernc): runs, findings, tasks, LLM cache
internal/llm/         claude -p client with prompt-hash cache
internal/render/      terminal output (lipgloss, glamour)
internal/htmlreport/  self-contained HTML reports and index
internal/tui/         Bubble Tea dashboard, report viewer, task editor (Backend interface)
internal/progress/    stderr progress bar / spinner
internal/exec/        command runner with a Fake for tests
internal/config/      viper loader, defaults and Template (kept in sync by a test); AUDIT_* env; XDG paths
```

A new scanning command implements `core.Scanner` (and `core.Owner` if it supports a narrowed scope), gets added to `core.Commands` and `core.ScopeFlags`, a subcommand in `cmd/audit/cmd/scan.go`, and a case in `app.defaultScanner`.

## Conventions

- Logging: `github.com/charmbracelet/log`; never stdlib `log` or `fmt.Print*` for diagnostics.
- Every flag has a long and a single-letter short form (enforced by `TestEveryFlagHasShortForm`).
- Output options (`--report`, `--list`, `--summary`, `--json`) never scan unless `--rescan` is given.
- Never persist raw shell xtrace output; it echoes variable values. Keep file paths only.
- A new config key goes in `defaults()`, the `Template` (with a comment) and `validate()` if it has a range; `TestTemplateMatchesDefaults` fails if the template drifts.
- When adding or changing a command or flag, update `man/audit.1.md`, `README.md` and `CHANGELOG.md` in the same change.
