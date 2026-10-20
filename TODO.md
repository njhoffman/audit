# audit task list

Roadmap features first, then issues found in the code. Everything here is a
proposal to discuss, not a decision; items under "Decisions to make" need an
answer before work starts.
Tag an item `(p1)` (high) or `(p3)` (low); untagged items are `p2` (normal).
`(due YYYY-MM-DD)` adds a date and an OVERDUE flag. `~/.shell/scripts/todo-status`,
`/todo` and `/todo-pop` (sorted by urgency) read both.

## 1. Rescan everything and run unattended

Today every scan is started by hand, one command at a time; bare `audit` has
no `--rescan`, and nothing tells you when a scan would turn up something new.

- [ ] **`audit -r` rescans every stale command.** (p1) Root-level `--rescan`
  (with `-O`/`--only` taking command names) runs the stale scanners, saves,
  reconciles tasks and prints the summary. Scanners that only read local state
  (system, environment, configs, scripts, ai) could run concurrently; repos
  and packages hit the network and should stay sequential or capped.
- [ ] **Scheduled scans through a systemd user timer.** `audit schedule
  install|remove|status` writes `~/.config/systemd/user/audit.{service,timer}`
  running `audit -r -q`. Config key for the calendar spec (default daily) and
  which commands it covers. No sudo, no network-heavy commands by default.
- [ ] **Notify on new high-priority tasks.** After an unattended scan,
  `notify-send` (when a session bus exists) with the count of tasks that are
  new since the previous run, and a pointer to `audit todo`. Opt-in
  `notify.enabled`, `notify.min_priority`.

Decisions to make: whether a scheduled run may use the AI review (it costs
money per run unless the cache hits); whether `audit -r` belongs on the root
or as `audit scan [command...]`.

## 2. Change tracking between runs

Runs are pruned to `history` per command, but nothing compares them. Tasks
show the current state, not what moved.

- [ ] **`audit <command> --diff`** (and `audit history diff A B`): findings
  added and resolved between the last two runs (or two run IDs), keyed by
  command, check and subject, the same key ignore rules use.
- [ ] **Deltas on the dashboard and summary.** `+3 / -5` next to each
  command's finding count, and a "new since last run" filter in the task
  editor and tasks page.
- [ ] **Trend in the HTML index.** (p3) Finding counts per severity over the kept
  runs, as a small inline chart per command.

## 3. New scanners (candidates)

Each one implements `core.Scanner`, joins `core.Commands`, gets a subcommand
and a `defaultScanner` case (see section 5 for collapsing those).

- [ ] **`audit containers`** (p3): docker and podman dangling images, unused
  volumes, stopped containers older than N days, images far behind their tag,
  rootless vs rootful. `files` already reports docker's cache size; this
  would own the per-object view and `containers clean`.
- [ ] **`audit backups`**: last snapshot age and last check result for
  restic, borg, timeshift or a configured command; paths in a configured list
  that no backup covers. High value, small surface.
- [ ] **Firmware in `system updates`** (p3): `fwupdmgr get-updates` (no sudo
  needed to list) as `updates.firmware`.

Decisions to make: which of these is worth building at all; whether
`backups` should be config-driven only (no auto-detection).

## 4. Data retention in the store

`Prune` only trims `runs`. Everything else grows without bound.

- [ ] **Prune `llm_cache`.** Entries are keyed by prompt hash, so every
  changed result set adds a row that is never read again. Drop entries older
  than a configured age (`ai.cache_max_age`, default 90d) on open or after
  each AI call.
- [ ] **Prune `updates` / `update_items`.** Package updates, runtime
  migrations, repo syncs and cleanups are all saved and never removed; keep
  the newest N per kind (`history` would do).
- [ ] **Prune closed tasks.** (p3) Resolved and done tasks accumulate forever and
  feed `tasks.html` and `tasks.json`. Delete ones closed longer than a
  configured age; keep `wont-do`, since it suppresses re-creation.
- [ ] **Migration ladder instead of `if v == "1"`.** (p3) `checkVersion` handles
  one hard-coded upgrade. A slice of `func(*sql.Tx) error` indexed by
  version, each step in its own transaction, scales to the next schema change
  and makes each step testable on its own.

## 5. Architecture cleanups

- [ ] **One scanner registry.** Adding a command touches `core.Commands`,
  `core.ScopeFlags`, `defaultScanner` in `cmd/audit/cmd/tui.go`, the
  `root.AddCommand` list and the scan subcommand. A single table of
  `{name, scopeFlag, build func, newCmd func}` in core (or cmd) would make
  the list, the TUI backend and cobra wiring all derive from it, and a test
  could assert every entry is complete.
- [ ] **Move bins install out of the cmd package.** `cmd/audit/cmd/bins.go`
  holds the release download, sha256 check, untar/unzip/gunzip and atomic
  replace (`installBin` through `copyFile`). That is package logic with
  security-relevant edge cases (archive member paths, symlinks); it belongs
  in `internal/packages` (or `internal/bins`) behind the exec runner, where
  it can be tested without cobra.
- [ ] **Thin the cmd layer generally.** (p3) `cmd/audit/cmd` is about 7.6k lines
  of non-test code; `update.go`, `runtimes.go` and `packages.go` carry
  planning and cleanup logic (`cleanupPlan`, `installedPythons`,
  `rememberNodeMajor`) that would sit better in core or packages.

## 6. Test coverage gaps

All packages pass and lint is clean (checked 2026-10-20); these are the thin
spots from `go test -cover`.

- [ ] **`internal/core` at 41.7%.** (p1) This is the engine (Resolve, Execute,
  task reconcile across commands). Narrowed-scope resolution and the
  rescan/saved-only paths are the riskiest parts to leave untested.
- [ ] **Legacy system scanners at 34-43%**: `scan/procs`, `scan/services`,
  `scan/logs`, `scan/programs` (the sysaudit-era code). The newer
  `scan/resources`, `scan/updates`, `scan/security` are at 88-94%; bring the
  old ones up with the same fixture style.
- [ ] **`tools/release` at 36.7%.** It bumps versions, commits, tags and
  pushes. The bump-inference from CHANGELOG headings and the pre-1.0 rule
  are pure functions worth table tests; the git side can go through a fake.

## 7. Housekeeping

- [x] **Remove the committed test artifact**
  `cmd/audit/cmd/tool-v2.0-linux-amd64.tar.gz` (150 bytes, mode 0600). It
  was written by an early version of the bins install test and committed in
  dd52728; the current code downloads into `os.MkdirTemp`, so nothing needs
  it.
- [x] **CLAUDE.md architecture tree is stale.** (p1) The overview line about
  `repos`/`files`/`configs`/`scripts`/`ai` being planned is fixed; the tree
  still omits `internal/{ai,configs,export,files,registry,
  repos,scripts,taskserver}` and `internal/scan/{resources,security,storage,
  updates}`.
