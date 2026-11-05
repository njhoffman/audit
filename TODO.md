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

Reviewed: 2026-11-05

## 1. Rescan everything and run unattended

`audit -r` rescans every stale command, but only when started by hand, and
nothing tells you when a scan would turn up something new.

- [ ] **Scheduled scans through a systemd user timer.** (p2) [feature] `audit schedule
  install|remove|status` writes `~/.config/systemd/user/audit.{service,timer}`
  running `audit -r -q`. Config key for the calendar spec (default daily) and
  which commands it covers. No sudo, no network-heavy commands by default.
- [ ] **Notify on new high-priority tasks.** (p3) [feature] After an unattended scan,
  `notify-send` (when a session bus exists) with the count of tasks that are
  new since the previous run, and a pointer to `audit todo`. Opt-in
  `notify.enabled`, `notify.min_priority`.

- [ ] **Rescan every stale command from the dashboard.** (p2) [feature] A key (say `R`) that
  runs what `audit -r` runs, with the dashboard rows as its progress.

Decisions to make: whether a scheduled run may use the AI review (it costs
money per run unless the cache hits).

## 2. Change tracking between runs

Runs are pruned to `history` per command, but nothing compares them. Tasks
show the current state, not what moved.

- [ ] **`audit <command> --diff`** (p2) [feature] (and `audit history runs diff A B`): findings
  added and resolved between the last two runs (or two run IDs), keyed by
  command, check and subject, the same key ignore rules use.
- [ ] **Deltas on the dashboard and summary.** (p3) [feature] `+3 / -5` next to each
  command's finding count, and a "new since last run" filter in the task
  editor and tasks page.
- [ ] **Trend in the HTML index.** [feature] (p3) Finding counts per severity over the kept
  runs, as a small inline chart per command.
- [ ] **History of fixes and what audit has done.** (p3) [feature] A log that outlives run
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

- [ ] **`audit containers`** [feature] (p3): docker and podman dangling images, unused
  volumes, stopped containers older than N days, images far behind their tag,
  rootless vs rootful. `files` already reports docker's cache size; this
  would own the per-object view and `containers clean`.
- [ ] **`audit backups`** (p2) [feature] : last snapshot age and last check result for
  restic, borg, timeshift or a configured command; paths in a configured list
  that no backup covers. High value, small surface.
- [ ] **Firmware in `system updates`** [feature] (p3): `fwupdmgr get-updates` (no sudo
  needed to list) as `updates.firmware`.

Decisions to make: which of these is worth building at all; whether
`backups` should be config-driven only (no auto-detection).

## 4. Data retention in the store

Runs are bounded per command. Update runs are also pruned, but share one
global limit; AI cache entries and closed tasks still have no age limit.

- [ ] **Prune `llm_cache`.** (p2) [chore] Entries are keyed by prompt hash, so every
  changed result set adds a row that is never read again. Drop entries older
  than a configured age (`ai.cache_max_age`, default 90d) on open or after
  each AI call.
- [x] **Bound saved update runs.** `Store.PruneUpdates` keeps the newest
  `history` update runs; package updates and the shared `finishUpdate` path
  call it after saving.
- [ ] **Keep update history per action kind.** (p2) [bug] `PruneUpdates` currently
  applies one global limit. Frequent package updates can evict the last repo
  sync, runtime migration or cleanup, making that action's `--last` empty.
  Keep the newest N per kind and test mixed-kind runs and child-row cleanup.
- [ ] **Prune closed tasks.** [chore] (p3) Resolved and done tasks accumulate forever and
  feed `tasks.html` and `tasks.json`. Delete ones closed longer than a
  configured age; keep `wont-do`, since it suppresses re-creation.
- [ ] **Migration ladder instead of `if v == "1"`.** [refactor] (p3) `checkVersion` handles
  one hard-coded upgrade. A slice of `func(*sql.Tx) error` indexed by
  version, each step in its own transaction, scales to the next schema change
  and makes each step testable on its own.

## 5. Architecture cleanups

- [ ] **One scanner registry.** (p2) [refactor] Adding a command touches `core.Commands`,
  `core.ScopeFlags`, `defaultScanner` in `cmd/audit/cmd/tui.go`, the
  `root.AddCommand` list and the scan subcommand. A single table of
  `{name, scopeFlag, build func, newCmd func}` in core (or cmd) would make
  the list, the TUI backend and cobra wiring all derive from it, and a test
  could assert every entry is complete.
- [ ] **Move bins install out of the cmd package.** (p2) [refactor] `cmd/audit/cmd/bins.go`
  holds the release download, sha256 check, untar/unzip/gunzip and atomic
  replace (`installBin` through `copyFile`). That is package logic with
  security-relevant edge cases (archive member paths, symlinks); it belongs
  in `internal/packages` (or `internal/bins`) behind the exec runner, where
  it can be tested without cobra.
- [ ] **Thin the cmd layer generally.** [refactor] (p3) `cmd/audit/cmd` is about 7.6k lines
  of non-test code; `update.go`, `runtimes.go` and `packages.go` carry
  planning and cleanup logic (`cleanupPlan`, `installedPythons`,
  `rememberNodeMajor`) that would sit better in core or packages.

## 6. Test coverage gaps

Latest validation in this session: `just check` passed (formatting, lint, race tests and
build); the final bash-record pruning fix also passed focused race tests,
lint and build. Coverage percentages below are from 2026-10-20, not a new
coverage run.

- [ ] **`internal/core` at 84.8%** [test] (was 41.7%). (p3) What is left: the
  Prune and SaveTodos failure branches of Execute (testing them needs
  `Engine.Store` as an interface), the `time.Now` fallbacks, and the
  json.Marshal errors of the adapters.
- [ ] **Legacy system scanners at 34-43%** (p2) [test] : `scan/procs`, `scan/services`,
  `scan/logs`, `scan/programs` (the sysaudit-era code). The newer
  `scan/resources`, `scan/updates`, `scan/security` are at 88-94%; bring the
  old ones up with the same fixture style.
- [ ] **`tools/release` at 36.7%.** (p2) [test] It bumps versions, commits, tags and
  pushes. The bump-inference from CHANGELOG headings and the pre-1.0 rule
  are pure functions worth table tests; the git side can go through a fake.

## 7. Housekeeping

- [ ] **Refresh history-related documentation wording.** [docs] (p3) `CLAUDE.md`
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

- [ ] **Bring CLAUDE.md and the TODO intro up to date.** (p3) [docs] CLAUDE.md's overview
  and architecture tree omit the `history` scanner and internal/history, though
  core.Commands includes it, and its "untagged is p2" (also in this file's intro)
  contradicts the rule that every open item has an explicit priority.

- [x] **Fix CI lint, failing on main since at least v0.22.1.** (p1) [bug] CI pins golangci-lint
  v2.11.4 and the local copy is 2.15.0, so `just lint` passes while CI stops at two gosec
  G115 errors in internal/history/prune.go:168,171 and never reaches its test step. Fix or
  annotate those conversions and use one version in both places, since `just release`
  cannot catch what only CI reports.

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
- [x] **Keep update hints within the displayed scope.** (p1)
  `cmd/audit/cmd/outdated.go` prints a bare `audit packages update` even
  after `-M` or `-f` narrows the list. Following that hint plans packages
  outside the view. Carry manager filters forward, and generate explicit
  package refs or clearly identify that an update covers all managers.
- [ ] **Distinguish current packages from unchecked ones.** (p2) [bug] An empty
  outdated view says "No known outdated packages" even when lookups failed
  or versions are unknown. Show checked/unchecked/failed counts and cache
  age, including the age of system package lists. Offer the appropriate
  refresh command; `--force` only forces registry lookups, not apt lists.
- [ ] **Return inventory-rendering errors to callers.** (p2) [bug] The outdated view
  logs annotation errors and returns from a callback, leaving the command
  successful without its requested package list. Let inventory views return
  errors and cover failed cache/tag reads in both text and JSON output.
- [ ] **Show package versions and updates beside program checks.** (p2) [feature] Match each
  configured program to its package inventory entry and owning manager;
  include installed/latest versions and registry freshness in the program
  summary, linking to `audit packages info` and `audit packages update`.
  Handle executable/package name differences and ambiguous ownership.
  Reuse package data and update plans rather than adding another updater.
- [ ] **Verify parity with the original pkgm toolsets.** (p2) [test] Compare its package
  groups, manager self-updates and install/update recipes against audit's
  managers and tracked binaries; document remaining gaps before retiring
  the prototype. The original prototype was not found in this checkout.

- [ ] **Show the package inventory and outdated list in the dashboard.** (p2) [feature]
  tuiBackend.Report (cmd/audit/cmd/tui.go) renders findings only, and internal/tui
  has no inventory view, so installed versions and available updates cannot be
  reached from bare `audit`. Add a packages screen: per manager, name, installed,
  latest, gap; filter to outdated; preview and run updates from it (overlaps
  "Preview package updates" in section 10).
- [ ] **Show the package table without a wall of findings.** (p2) [feature] Bare
  `audit packages` and `-R` print no version table at all, `-l` puts it after every
  finding, and `outdated` prints 225 finding rows before its first package. Make
  `outdated` lead with (or print only) the table, and have the default view say how
  many packages are behind and which command lists them.
- [ ] **Say how far behind a package is in text.** (p2) [feature] The gap
  (patch/minor/major) is only the color of LATEST (gapStyle in internal/render/views.go),
  so it disappears with `-n` or in a pipe. RELEASED is the age of the latest release,
  not how long the install has trailed it. Add a gap column, the age of the installed
  version where the registry gives it, and per-manager behind counts in the summary.
- [ ] **Refresh registry data on a normal packages rescan.** (p2) [bug] Only `outdated`,
  `update`, `registry` and `bins` set Scanner.Refresh. `audit packages -r` and the
  dashboard rescan only read the cache, so a machine that never ran those shows
  `unchecked` in LATEST with no `registry.*` findings (seen on the 2026-10-30 run:
  "registry never checked"). Refresh when the cache is past `registry.max_age`, or
  have the dashboard prompt for it.
- [ ] **Do not offer prereleases as the latest version.** (p2) [bug] `pnpm:node` shows
  `24.22.0 -> 27.0.0-alpha.0.0.0` with a `registry.major_behind` notice, because the
  npm lookup trusts the `latest` dist-tag (internal/registry/registry.go:378). Only
  the crates lookup filters prereleases (latestCrate). Apply one rule to every registry
  when the install is stable, and check what `packages update --major` plans here.
- [x] **Say when configured managers leave out system packages.** (p3) [feature] With
  `packages.managers` limited to user managers, `outdated` prints nothing about apt,
  snap or flatpak, while those had 1, 3 and 4 updates pending on 2026-11-05. An empty or
  partial list reads as complete. Name the managers not checked, with the flag to include them.
- [x] **Keep a narrowed scan from replacing the saved package results.** (p2) [bug]
  `audit packages -M apt,snap,flatpak -r` becomes the run that `audit packages -l` reads
  (scope `apt,snap,flatpak`), hiding the other managers until the next full scan, which
  then resolves the narrowed run's tasks (reproduced 2026-11-05: runs 69 and 70). Export
  already uses the latest full run. Default the saved views to that too, and keep tasks of
  explicitly requested managers open. Check whether `outdated -M` does the same.

- [ ] **Update git-installed crates through cargo-update.** (p3) [feature] `packages update`
  skips 31 packages installed from git or a path because they have no registry
  version. `cargo install-update -g` can update git crates, but audit has no latest
  version to compare or verify against, so decide how such a package counts as updated.
- [ ] **Check system packages when a rescan follows a fix.** (p3) [bug] Under
  `packages.system_managers: ask`, the rescan after `audit todo fix` and fzf's rescan
  (defaultScanner) skip apt, snap and flatpak without asking. A fixed system-package
  task stays open until a scan that includes them. Include them when the task is theirs.
- [ ] **Refresh the saved view after a narrowed update.** (p3) [bug] `audit packages
  update -M uv` rescans only uv, and that scoped run no longer reaches `audit packages -l`,
  which keeps showing the updated packages as behind until the next full scan.
  Merge a scoped run's inventories into the full view, or rescan fully after an update.

## 9. Shell history follow-ups

- [x] **Scan shell histories.** Dashboard and `audit history` find repeated
  entries, large multiline entries and configured literal substring matches
  in zsh, bash and fish. Findings retain counts and locations, not commands.
- [x] **Prune identified entries.** `audit history prune` supports category
  and file selection, previews, confirmation, ignore rules, private backups,
  whole-record preservation, changed-file and lock checks, and a rescan.
  Saved audit runs now live under `audit history runs`.
- [ ] **Give patterns stable identities.** (p2) [refactor] Findings and ignore rules use
  `PATH:pattern-N`; reordering `shell_history.patterns` changes which pattern
  a saved task or ignore rule refers to. Support named pattern IDs without
  storing pattern values in findings, and test reorder/add/remove behavior.
- [ ] **Make history formats explicit for custom paths.** (p2) [bug] `formatOf` guesses
  from filenames and content; a plain zsh history at a custom path is treated
  as bash, losing multiline boundaries. Allow a per-source format and show
  what was detected. Never infer multiline bash boundaries without timestamps.
- [ ] **Handle CRLF timestamps and leading blank lines consistently.** (p2) [bug] Bash
  timestamp detection runs before CR stripping, so CRLF files are treated as
  untimestamped. Leading blank command lines are dropped during parsing.
  Normalize format detection and preserve logical line counts and raw record
  ranges; add scan/prune regression fixtures with CRLF and blank boundaries.
- [ ] **Share history classification and record boundaries.** (p2) [refactor] Scan and prune
  independently implement duplicate/multiline/pattern selection, and prune
  reconstructs byte ranges from line numbers. Have one parser expose raw
  ranges and one classifier select records so reporting and deletion agree.
- [ ] **Test concurrent writers and replacement durability.** [test] (p1) The
  advisory lock belongs to the old inode, and a writer ignoring it can append
  between the final comparison and rename. Test that interval, investigate
  shell-compatible locking, and state the limits precisely. Sync the parent
  directory after replacement if crash durability is promised. Closing other
  shell sessions remains the current operating guidance.
- [ ] **Manage backups and record prune outcomes.** (p2) [feature] Add a backup list and
  verified restore preview, plus explicit cleanup by age/count. Backups retain
  removed secrets and currently accumulate beside histories. Persist prune
  counts, backup paths and per-file errors without command text so a partial
  prune can be inspected later; connect this to the action log in section 2.
- [ ] **Normalize configured history paths.** (p2) [bug] `NewHistory` leaves relative
  paths relative, while explicit prune arguments become absolute, so a
  configured relative path can be rejected as unconfigured. Use consistent
  absolute paths and test `~`, relative paths, `$XDG_DATA_HOME` and
  `${XDG_DATA_HOME}` with the variable unset.

Decisions to make: whether backup cleanup is manual-only or opt-in retention;
whether format detection should refuse pruning ambiguous histories.

## 10. Dashboard actions

- [ ] **Preview package updates and history pruning from reports.** [feature] (p3)
  Offer outdated-only inventory, selected-package update plans and history
  prune plans from the dashboard/fzf interfaces. Keep scope visible, require
  confirmation for changes, and display failures and backup locations.
- [ ] **Markers and icons in the printed task list.** (p3) [feature]
  The task editor now marks priorities and shows command icons (internal/tui/tasks.go),
  but `audit todo` (render.Printer.Todos in internal/render/summary.go) and the fzf
  task lines still print bare words. Use the same Glyphs there so the three agree.

## 11. Tips

- [ ] **Proactive tips, not tied to a problem.** (p3) [feature] Advice on performance,
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

## 12. AI review and fix workflow

- [ ] **Commit AI fixes made inside a git repo.** (p2) [feature] After `audit todo fix`
  (fixTask in cmd/audit/cmd/ai.go) succeeds and the rescan closes the task, check
  whether the files it changed are in a git work tree. If they are, offer a
  commit of only those files with a message naming the task (`audit: fix #ID
  <title>`). Today the change is left uncommitted, so it is easy to lose or to
  mix into unrelated work.
  Decisions: commit on its own or after a prompt (config `ai.commit_fixes`);
  how to find the changed files (diff `git status` before and after, or ask the
  session to report them); refuse when the tree was already dirty.
- [ ] **Pass the task's explanation to AI fix.** (p2) [feature] `audit todo explain`
  answers are kept only in `llm_cache` under a prompt hash, and FixTaskPrompt
  (internal/llm/prompts.go) sends just the task and its findings. Look up the
  cached explanation for the task (or save explanations against the task id) and
  add it to the fix prompt as context, marked as an earlier AI answer and not as
  instructions.
- [ ] **AI review as part of scanning, with suggestions as findings.** (p2) [feature]
  `--ai`/`-a` already adds a review to a scan (Engine.Analyze), but only when
  given, and the review is prose in `run.Analysis`, so its points never become
  tasks. Add config `ai.review_on_scan` (off by default) and ask for structured
  output (JSON list of issues/suggestions) that turns into findings of a
  dedicated `ai-review` check, deduped against the existing findings.
  Decisions: which commands it applies to; cost limit per scan; whether
  AI-sourced findings get a lower default priority.
- [ ] **Show remaining AI usage on the dashboard.** (p3) [feature] Before an AI
  review or fix, show how much of the provider's usage window is left, and skip
  automatic reviews (above) when it is under a threshold. Needs research first:
  `claude` and `codex` report usage differently (rate-limit info in session
  output, cost per call in our cache); the cost summed from `llm_cache` is a
  fallback that only counts audit's own calls.

## 13. Dashboard readability

- [ ] **Describe the selected command under the list.** (p3) [feature] As the cursor
  moves over the top-level rows (system, packages, repos, ...), show one line
  below the table on what that command scans for, taken from each cobra
  command's Short so the two cannot drift.
- [ ] **Make finding and task count columns distinguishable.** (p2) [bug] The
  dashboard rows read `● 21 ▲ 138 ◆ 95 ○ 116 | ● 4 ◐ 1 ○ 96 ◇ 12`, and the
  styles in FindingCounts/TaskCounts (internal/render/summary.go) do not line up:
  `◆ 95` (suggestion) and `○ 96` (low priority) share a color with different
  icons, while `○ 116` (info) and `◇ 12` reuse the same shapes with other
  colors. Pick one mapping (shared shape and color where a severity maps to a
  priority, distinct otherwise), add a vertical separator between the findings
  and the open tasks columns, and keep the header legend matching.
