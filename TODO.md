# audit task list

Roadmap features first, then issues found in the code. Everything here is a
proposal to discuss, not a decision; items under "Decisions to make" need an
answer before work starts.
Tag an item `(p1)` (high) or `(p3)` (low); untagged items are `p2` (normal).
`(due YYYY-MM-DD)` adds a date and an OVERDUE flag. `~/.shell/scripts/todo-status`,
`/todo` and `/todo-pop` (sorted by urgency) read both.

Refreshed 2026-10-22 against the current working tree. Checked items may be
implemented but not released yet. Issues below are based on source review;
suggestions describe proposed behavior rather than existing guarantees.

## 1. Rescan everything and run unattended

`audit -r` rescans every stale command, but only when started by hand, and
nothing tells you when a scan would turn up something new.

- [ ] **Scheduled scans through a systemd user timer.** `audit schedule
  install|remove|status` writes `~/.config/systemd/user/audit.{service,timer}`
  running `audit -r -q`. Config key for the calendar spec (default daily) and
  which commands it covers. No sudo, no network-heavy commands by default.
- [ ] **Notify on new high-priority tasks.** After an unattended scan,
  `notify-send` (when a session bus exists) with the count of tasks that are
  new since the previous run, and a pointer to `audit todo`. Opt-in
  `notify.enabled`, `notify.min_priority`.

- [ ] **Rescan every stale command from the dashboard.** A key (say `R`) that
  runs what `audit -r` runs, with the dashboard rows as its progress.

Decisions to make: whether a scheduled run may use the AI review (it costs
money per run unless the cache hits).

## 2. Change tracking between runs

Runs are pruned to `history` per command, but nothing compares them. Tasks
show the current state, not what moved.

- [ ] **`audit <command> --diff`** (and `audit history runs diff A B`): findings
  added and resolved between the last two runs (or two run IDs), keyed by
  command, check and subject, the same key ignore rules use.
- [ ] **Deltas on the dashboard and summary.** `+3 / -5` next to each
  command's finding count, and a "new since last run" filter in the task
  editor and tasks page.
- [ ] **Trend in the HTML index.** (p3) Finding counts per severity over the kept
  runs, as a small inline chart per command.
- [ ] **History of fixes and what audit has done.** A log that outlives run
  pruning: every task resolved by a rescan or closed by hand, every package
  update, repo sync, files or configs clean, history prune, with the date,
  command, check, subject and what changed (space reclaimed, versions moved, task title and
  details as they were, without shell command text). A summary view
  (`audit history runs fixes`, a dashboard panel, an HTML page) totals it:
  problems fixed per command and severity,
  space reclaimed, packages updated. The past entries double as diagnostics:
  when a finding comes back, its task and the explain prompt can show that it
  was fixed before, when and how.

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

Runs are bounded per command. Update runs are also pruned, but share one
global limit; AI cache entries and closed tasks still have no age limit.

- [ ] **Prune `llm_cache`.** Entries are keyed by prompt hash, so every
  changed result set adds a row that is never read again. Drop entries older
  than a configured age (`ai.cache_max_age`, default 90d) on open or after
  each AI call.
- [x] **Bound saved update runs.** `Store.PruneUpdates` keeps the newest
  `history` update runs; package updates and the shared `finishUpdate` path
  call it after saving.
- [ ] **Keep update history per action kind.** `PruneUpdates` currently
  applies one global limit. Frequent package updates can evict the last repo
  sync, runtime migration or cleanup, making that action's `--last` empty.
  Keep the newest N per kind and test mixed-kind runs and child-row cleanup.
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

Latest validation in this session: `just check` passed (formatting, lint, race tests and
build); the final bash-record pruning fix also passed focused race tests,
lint and build. Coverage percentages below are from 2026-10-20, not a new
coverage run.

- [ ] **`internal/core` at 84.8%** (was 41.7%). (p3) What is left: the
  Prune and SaveTodos failure branches of Execute (testing them needs
  `Engine.Store` as an interface), the `time.Now` fallbacks, and the
  json.Marshal errors of the adapters.
- [ ] **Legacy system scanners at 34-43%**: `scan/procs`, `scan/services`,
  `scan/logs`, `scan/programs` (the sysaudit-era code). The newer
  `scan/resources`, `scan/updates`, `scan/security` are at 88-94%; bring the
  old ones up with the same fixture style.
- [ ] **`tools/release` at 36.7%.** It bumps versions, commits, tags and
  pushes. The bump-inference from CHANGELOG headings and the pre-1.0 rule
  are pure functions worth table tests; the git side can go through a fake.

## 7. Housekeeping

- [ ] **Refresh history-related documentation wording.** (p3) `CLAUDE.md`
  omits the history scanner and prune action from its overview and tree.
  README's scanner paragraph says histories are never modified; qualify
  that as scanning behavior so it agrees with the prune workflow below it.
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

## 8. Package management integration

The Python `pkgm` prototype is integrated into `audit packages`, starting in
v0.2.0: persisted inventories and versions; cached registry release checks;
updates through uv, pnpm, cargo, go, gem, gh, apt, snap and flatpak; runtime
updates and migrations; and GitHub-tracked loose binaries. Keep these in
`audit packages` as the single package inventory and update workflow.
`system programs` currently checks service configuration only.

- [x] **List outdated packages directly.** `audit packages outdated`
  refreshes installed/registry versions; `-F` forces registry lookups,
  `-M`/`-f` filter the view, and output flags can read saved results.
- [x] **Update all or selected packages.** `audit packages update` supports
  named `manager:name` packages, manager filters, dry-run plans, confirmation,
  opt-in major updates, post-update verification and saved failures.
- [ ] **Keep update hints within the displayed scope.** (p1)
  `cmd/audit/cmd/outdated.go` prints a bare `audit packages update` even
  after `-M` or `-f` narrows the list. Following that hint plans packages
  outside the view. Carry manager filters forward, and generate explicit
  package refs or clearly identify that an update covers all managers.
- [ ] **Distinguish current packages from unchecked ones.** An empty
  outdated view says "No known outdated packages" even when lookups failed
  or versions are unknown. Show checked/unchecked/failed counts and cache
  age, including the age of system package lists. Offer the appropriate
  refresh command; `--force` only forces registry lookups, not apt lists.
- [ ] **Return inventory-rendering errors to callers.** The outdated view
  logs annotation errors and returns from a callback, leaving the command
  successful without its requested package list. Let inventory views return
  errors and cover failed cache/tag reads in both text and JSON output.
- [ ] **Show package versions and updates beside program checks.** Match each
  configured program to its package inventory entry and owning manager;
  include installed/latest versions and registry freshness in the program
  summary, linking to `audit packages info` and `audit packages update`.
  Handle executable/package name differences and ambiguous ownership.
  Reuse package data and update plans rather than adding another updater.
- [ ] **Verify parity with the original pkgm toolsets.** Compare its package
  groups, manager self-updates and install/update recipes against audit's
  managers and tracked binaries; document remaining gaps before retiring
  the prototype. The original prototype was not found in this checkout.

## 9. Shell history follow-ups

- [x] **Scan shell histories.** Dashboard and `audit history` find repeated
  entries, large multiline entries and configured literal substring matches
  in zsh, bash and fish. Findings retain counts and locations, not commands.
- [x] **Prune identified entries.** `audit history prune` supports category
  and file selection, previews, confirmation, ignore rules, private backups,
  whole-record preservation, changed-file and lock checks, and a rescan.
  Saved audit runs now live under `audit history runs`.
- [ ] **Give patterns stable identities.** Findings and ignore rules use
  `PATH:pattern-N`; reordering `shell_history.patterns` changes which pattern
  a saved task or ignore rule refers to. Support named pattern IDs without
  storing pattern values in findings, and test reorder/add/remove behavior.
- [ ] **Make history formats explicit for custom paths.** `formatOf` guesses
  from filenames and content; a plain zsh history at a custom path is treated
  as bash, losing multiline boundaries. Allow a per-source format and show
  what was detected. Never infer multiline bash boundaries without timestamps.
- [ ] **Handle CRLF timestamps and leading blank lines consistently.** Bash
  timestamp detection runs before CR stripping, so CRLF files are treated as
  untimestamped. Leading blank command lines are dropped during parsing.
  Normalize format detection and preserve logical line counts and raw record
  ranges; add scan/prune regression fixtures with CRLF and blank boundaries.
- [ ] **Share history classification and record boundaries.** Scan and prune
  independently implement duplicate/multiline/pattern selection, and prune
  reconstructs byte ranges from line numbers. Have one parser expose raw
  ranges and one classifier select records so reporting and deletion agree.
- [ ] **Test concurrent writers and replacement durability.** (p1) The
  advisory lock belongs to the old inode, and a writer ignoring it can append
  between the final comparison and rename. Test that interval, investigate
  shell-compatible locking, and state the limits precisely. Sync the parent
  directory after replacement if crash durability is promised. Closing other
  shell sessions remains the current operating guidance.
- [ ] **Manage backups and record prune outcomes.** Add a backup list and
  verified restore preview, plus explicit cleanup by age/count. Backups retain
  removed secrets and currently accumulate beside histories. Persist prune
  counts, backup paths and per-file errors without command text so a partial
  prune can be inspected later; connect this to the action log in section 2.
- [ ] **Normalize configured history paths.** `NewHistory` leaves relative
  paths relative, while explicit prune arguments become absolute, so a
  configured relative path can be rejected as unconfigured. Use consistent
  absolute paths and test `~`, relative paths, `$XDG_DATA_HOME` and
  `${XDG_DATA_HOME}` with the variable unset.

Decisions to make: whether backup cleanup is manual-only or opt-in retention;
whether format detection should refuse pruning ambiguous histories.

## 10. Dashboard actions

- [ ] **Preview package updates and history pruning from reports.** (p3)
  Offer outdated-only inventory, selected-package update plans and history
  prune plans from the dashboard/fzf interfaces. Keep scope visible, require
  confirmation for changes, and display failures and backup locations.

## 11. Tips

- [ ] **Proactive tips, not tied to a problem.** Advice on performance,
  organization and good practice found while scanning (a slow startup file
  that could be lazy-loaded, aliases scattered over many files, a cache
  directory worth moving, a config that could use a newer option), as their
  own lowest level below suggestions: a `tip` finding kind and a `tip` task
  priority, hidden from counts and the dashboard's columns by default and
  shown in their own report section. Suggestions today (`Kind ==
  Suggestion`) still answer a detected issue; tips need no issue.

Decisions to make: whether tips become tasks at all or only show in reports;
whether they come from static checks, the AI review, or both; how to keep
them from being noise (one per check, dismissable like ignore rules).
