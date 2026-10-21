# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0] - 2026-10-20

### Added

- The dashboard's report screen opens collapsed: one line per finding (a colored severity marker, the check and the message) and only the summary of the shell in `$SHELL`. `x` (`toggle_details` in `tui.keys`) expands every finding with all its detail lines and both shells' stats, and collapses them again, keeping the scroll position.

### Changed

- `-v/--verbose` no longer lifts the `display.details` cap on printed reports; it only shows info logs (and package sources and executables in `audit packages`). The dashboard's expanded report shows every detail line.

## [0.18.0] - 2026-10-20

### Changed

- Report summaries are laid out as columns: dim labels, numbers in bold and right-aligned, and what qualifies them (`1936 (notty)`, `7 unexpected line(s)`, `105 mine`) dimmer after them. Environment startup rows drop `exit 0` and a zero output count.
- Terminal output (reports, task lists, the dashboard and fzf) shows paths under your home directory as `~`. JSON exports and HTML reports keep full paths.

### Added

- Summary stats carry an optional `note`, and `extra` on lines only the expanded view shows (the stats of a shell other than `$SHELL`), in the run JSON and the export files.

## [0.17.3] - 2026-10-20

### Fixed

- `ai.hook_broken` no longer reports a hook command that starts with a shell builtin or keyword (`cd`, `[`, `if`, a subshell) as a program that is not installed.

## [0.17.2] - 2026-10-20

### Fixed

- `ai.hook_broken` splits a hook command the way sh does (quotes, backslash escapes, `~` and `$VAR`), so a script path with spaces is checked whole. A word using a variable that is only set when the hook runs, such as `$CLAUDE_PROJECT_DIR`, is no longer reported as missing, and a command that leaves a quote open is reported.

## [0.17.1] - 2026-10-20

### Fixed

- `ai.hook_broken` no longer reports a Claude Code hook whose script path is quoted (`"\"$HOME/bin/hook\""` in settings.json) as missing, and now checks a quoted script argument too.

## [0.17.0] - 2026-10-20

### Added

- An fzf interface for the dashboard and the task editor: `tui.interface: fzf`, or `-F`/`--fzf` on bare `audit` and `audit todo` (`--fzf=false` for the TUI). The command list previews saved reports; the task list previews tasks and changes them through alt- keys (`tui.fzf_keys`, validated like `tui.keys`), reloading after each change. Needs fzf 0.51 or later.

## [0.16.0] - 2026-10-20

### Added

- `audit environment` counts what each login shell defines once startup is done, with and without a terminal: aliases, functions, parameters, exported and integer variables, arrays, PATH entries, programs on PATH, commands, completions and key bindings, plus fpath entries, widgets and zinit plugins and snippets in zsh. Each count is a summary row, with the no-terminal count when it differs. Only names are collected.
- New environment checks: `shell.alias_broken` (an alias runs a command that does not exist; one rolled-up task with a file:line per definition), `shell.alias_shadows` (info: aliases that hide a program of the same name), `shell.fpath_missing`, `shell.fpath_duplicate`, and `shell.notty_definitions` (info: fewer aliases or functions without a terminal).

## [0.15.0] - 2026-10-20

### Added

- Configurable dashboard and task editor keys: `tui.keys` binds each action to any number of keys, `[]` unbinds one, and setting one action keeps the defaults of the rest. Conflicts on a screen, unknown actions and `ctrl+c` are config errors, and the help line is built from the bindings. `man audit` (KEYS) lists the actions.
- `g`/`G` (`home`/`end`) jump to the top and bottom of reports, task details and explanations.

### Changed

- `d` no longer scrolls half a page in reports and explanations (it marks a task done in the task list, and one action now has the same keys on every screen); `ctrl+d` still does. `l`/`right` no longer scroll reports sideways.

## [0.14.2] - 2026-10-20

### Fixed

- The source tree no longer ships `cmd/audit/cmd/tool-v2.0-linux-amd64.tar.gz`, an archive left behind by an early version of the bins install test.
- `CLAUDE.md` lists every scanning command and package; `TODO.md` holds the roadmap and known issues with priorities.

## [0.14.1] - 2026-10-20

### Fixed

- `audit environment` also leaves files under `scripts.roots` that a shell sources at startup to `audit scripts`, so no file is linted by both commands.

## [0.14.0] - 2026-10-20

### Changed

- `audit environment` no longer parses or shellchecks files under `scripts.roots` that no shell sources at startup; `audit scripts` owns them, so the same file no longer shows up in both commands' lint tasks.

## [0.13.0] - 2026-10-20

### Added

- Tasks page: `audit todo -H` writes `tasks.html` next to the reports with search, priority cards, status/command/source filters, grouping, sorting and expandable details, linked from the index and rewritten whenever the database changes; `-o` opens it. `audit todo -s` serves it on 127.0.0.1 (`-P` port) with status buttons and note editing, behind a per-run token and a loopback Host check. `audit -H` writes it too.
- `audit todo show ID -l` prints only the detail lines, `FILE:LINE: message` for lint tasks, ready for `vim -q`.
- Task editor: `enter` shows a task's every field and detail line; `v` opens its file locations in `$VISUAL`/`$EDITOR` (a quickfix list in vim and neovim).

### Changed

- shellcheck and parse errors (`shell.shellcheck`, `shell.syntax`, `script.shellcheck`, `script.syntax`, `config.syntax`) become one task per check and priority, such as "Fix shellcheck errors in 20 shell files", instead of one task per file; the details list every file and line. The per-file tasks resolve on the next scan.

## [0.12.0] - 2026-10-19

### Added

- `audit ai`: AI CLIs (claude, codex, gh copilot, aichat, ollama) with versions and login state, provider keys in the environment by name, ollama's server and models, MCP servers from Claude Code, Codex and mcphub (`ai.mcp_missing`), Claude Code hooks with missing programs or scripts (`ai.hook_broken`), allow rules that permit any command (`ai.permissions_broad`), large instruction files (`ai.instructions_large`, `ai.instruction_limit_kb`), and AI projects from repos.roots plus Claude Code's session directories (markers, git state, commands, skills, agents, MCP servers, sessions; `ai.stale_sessions`). `-p/--ping` sends one tiny request per logged-in provider.

## [0.11.0] - 2026-10-19

### Added

- `audit scripts`: inventories scripts under `scripts.roots` (~/bin, ~/.local/bin, ~/.config/*/scripts), describes each from its header comment or docstring, and checks them without running them: shellcheck (batched), `zsh -n`, a Python ast parse plus ruff syntax rules, `node --check`, `luac -p`, `ruby -c`, `fish -n`, missing shebang interpreters, missing exec bits, CRLF endings, PATH shadowing, commands not installed (heuristic) and dead scripts (suggestion). `-f/--find` filters the list. Config section `scripts`.
- `audit scripts describe [script...] [-a] [-A]` fills missing descriptions through the AI CLI in batches of ten, cached by content hash; `audit scripts info SCRIPT`.

## [0.10.0] - 2026-10-19

### Added

- `audit configs`: parses json/jsonc/yaml/toml/ini/xml files under `configs.roots` (`config.syntax`), runs read-only validators (`git config --global --list`, `ssh -G`, `systemd-analyze --user verify`, `i3 -C`, `sway -C`, `fish -n`, `tmux source-file -n` with a running server; `config.validator`), flags readable files holding credential-looking values by key name only (`config.permissions`), and matches every ~/.config entry and home dotfile to its program (inventories, apt with dpkg file lists, flatpak, snap, PATH) so orphans are reported with a likely apt package (`config.orphaned`). `-O/--orphans` lists them. Config section `configs`.
- `audit configs clean [path...]`: moves orphaned configs to the trash, confirmed, verified and saved like other cleanups; ignored orphans are never planned.

### Changed

- `just release` reinstalls the binary (`just install`) after pushing the tag, so `audit` on PATH is always the latest release.

## [0.9.0] - 2026-10-19

### Added

- `audit files clean [path...] [-C categories]`: plans the cleanup of the saved files results. Default categories `cache` (each cache's own cleaner, `sudo -n` for apt, the journal and snap revisions, else deleted), `build` and `cores` (deleted); opt-in `orphaned`, `downloads`, `duplicates` (to the trash with `gio trash`, the first duplicate kept) and `trash` (emptied). Targets must exist, lie inside `files.roots` and be neither a root nor home. Confirmed, verified and saved like updates (`-N`, `-y`, `-x`, `-j`, `-L`, `-e`).

## [0.8.0] - 2026-10-19

### Added

- `audit files`: one parallel, single-filesystem walk of `files.roots` measuring allocated space, the largest directories, and reclaimable space: tool and system caches (uv, pip, go, pnpm, npm, yarn, cargo, thumbnails, apt archives, the journal, disabled snap revisions, docker), idle projects' build and dependency directories (tools' own installs excluded), data of programs that look uninstalled, large files, old downloads, the trash, hash-confirmed duplicates, core dumps, empty directories and broken links. Git internals, caches, dependency trees and repo working trees are never offered as large files or duplicates. Config section `files`.

## [0.7.0] - 2026-10-19

### Added

- `audit system` parts `storage` (space and inode fullness per mount, read-only remounts, zfs pool health; opt-in `system.storage.smart` runs `smartctl -H` and btrfs device stats through `sudo -n`), `resources` (PSI memory/I/O/CPU pressure, available memory, swap, OOM kills in the last week, load against cores, temperatures near critical, thermal throttling, battery wear), `updates` (reboot required, newer kernel installed than running, pending security updates, failed unattended-upgrades/apt-daily runs and recent log errors, old kernels beyond `system.keep_kernels`) and `security` (no active firewall, ports listening beyond loopback with risky services as warnings, `~/.ssh` permissions and passphrase-less keys, world-writable PATH entries, clock sync). Config `system.storage.{warn_pct,error_pct,smart}` and `system.keep_kernels`.

## [0.6.0] - 2026-10-19

### Added

- `audit repos sync [repo...]`: fetches (unless `-o/--offline`), then plans per repo `set-url` after a GitHub rename or transfer (same URL form), `set-head` plus a local branch rename and new upstream after a default-branch rename, `fast-forward` (`git merge --ff-only`) for clean repos behind their upstream, `push` for your own repos that are only ahead (`-p/--push`) and `move` to the ghq path with links repointed (`-m/--move`, never onto a taken path). Dirty, mid-operation and diverged repos are listed with the reason and left alone. Confirmed and verified like package updates (`-y`, `-N`, `-x`, `-j`, `-e`); results are saved and `-L/--last` shows them.

## [0.5.0] - 2026-10-19

### Added

- `audit repos`: finds git repositories under `repos.roots` (ghq root and home to `repos.max_depth`, skipping `repos.exclude`) and checks them with local git only (remote URLs saved without credentials): operations in progress, uncommitted changes, unpushed commits, no remote, duplicate clones, behind, untracked, stashes, no upstream, detached HEAD, stale fetch, ghq layout, broken links in `repos.link_dirs`, plus `repo.missing`, `repo.moved`, `repo.default_branch` and `repo.archived` from the GitHub cache. The list shows branch, state, last commit, last fetch and tags (mine/others, host, language, local, fork, archived, GitHub topics); `-t`, `-f`, `-O mine|others|OWNER`, `-d`, `-u` filter it.
- `audit repos refresh [-F] [-N]` fetches every repo (concurrent, non-interactive) and refreshes GitHub data with batched `gh api graphql` queries; `repos tag REPO TAG... [-d]`, `repos info REPO`.
- Config section `repos` (`roots`, `max_depth`, `exclude`, `link_dirs`, `ghq_root`, `concurrency`, `fetch_timeout`, `stale_fetch`, `meta_max_age`); `repos.json` export file.

## [0.4.0] - 2026-10-19

### Added

- `packages` phase 5b: loose binaries (`bins` manager, on by default) are the regular executables in `packages.scan_dirs`, with kind `elf` or `script`. `audit packages bins` lists them; `bins track NAME OWNER/REPO[:ASSET-GLOB] [-s VERSION]` records a GitHub origin (version from `NAME --version` unless given) and looks the latest release up; `bins untrack NAME`; `bins install NAME [-r TAG] [-k] [-F]` downloads the asset with `gh release download`, verifies its sha256 (GitHub digest or the release's checksum file; refused without one unless `-k`), unpacks tar/zip/gzip in process (tar.xz and tar.zst through `tar`, members kept inside the work dir), replaces the binary atomically and keeps the old one under `<data_dir>/bins/`. Tracked binaries get registry lookups and are planned by `packages update`.
- Check `bins.untracked`: compiled loose binaries with no recorded origin (one task).

## [0.3.0] - 2026-10-19

### Added

- `packages` phase 5a: apt, snap and flatpak managers (on by default). apt inventories manually installed packages plus anything upgradable (`dpkg-query`, `apt-mark`, `apt list --upgradable` over the cached lists), snap uses `snap refresh --list`, flatpak covers system and user installations with `flatpak remote-ls --updates`. Scans never use sudo. Pending updates show in LATEST and `--outdated` and count as `registry.outdated` (gap `update` when the versions do not say how far), never as major.
- `packages update` updates them with one command per manager (`sudo -n apt-get install -y --only-upgrade ...` non-interactively, keeping config files; `sudo -n snap refresh ...`; `sudo -n flatpak update --system ...`; `flatpak update --user ...`), verifying each package. apt lists are refreshed first (`sudo apt-get update`) when apt is covered. Sudo is authenticated once (`sudo -v`, password on the terminal) and kept alive; without a terminal or cached credentials the root items are skipped with the reason. Held apt packages are skipped.
- Checks `apt.stale_lists` (lists older than a week) and `apt.held` (held packages with upgrades waiting).

## [0.2.0] - 2026-10-19

The project is renamed from `sysaudit` to `audit` and restructured around saved, task-tracked scans.

### Added

- Subcommands `system`, `environment`, `packages`, `todo`, `history` and `config`. Bare `audit` opens a Bubble Tea dashboard in a terminal and prints the summary otherwise; `-s/--summary`, `-H/--html` and `-o/--open` work on the root.
- `environment`: captures each login shell with and without a tty, traces sourced startup files, times start-up, and checks PATH, environment variables and startup scripts (syntax, shellcheck).
- `packages`: inventory and checks for uv, pnpm, cargo, go, gem and gh (ported from the Python `pkgm` prototype, phase 1).
- SQLite store (`$XDG_DATA_HOME/audit/audit.db`) for runs, findings, tasks and the AI cache; `history` setting prunes old runs.
- Freshness: a bare scan command reuses saved results younger than `stale.warn` and rescans otherwise; `-R/--report`, `-l/--list`, `-s/--summary`, `-j/--json` never scan unless `-r/--rescan` is given. Saved results carry an age banner, yellow when stale and red when old.
- Tasks: findings become tasks by severity (high, medium, low, suggestion); info findings share one task per check. Rescans add and resolve tasks; user statuses (in progress, done, won't do) persist. Narrowed scans only resolve tasks of the parts they scanned. `audit todo` lists, filters, shows, sets, notes, adds and removes tasks; `-i` opens the task editor.
- `ignore` config rules (`command:check:subject`, `command:check`, `check`), re-applied when saved runs are shown.
- Self-contained HTML reports per command plus an index page, with severity and text filters and light/dark themes.
- `-a/--ai`, `-A/--ai-refresh`, `-L/--level`: opt-in review through the `claude` CLI (`claude -p`, tools disabled, no session persistence), cached by prompt hash.
- `-m/--min-severity` and `-k/--check` filters; `-W/--width`, `-n/--no-color`, `-c/--config` global flags.
- `audit config` prints the effective configuration; `--init` writes a commented starter file.
- The first run creates `~/.config/audit.yaml` with every default written out and commented. A file passed with `-c` is never created; a missing one is an error.
- Config keys `display.details`, `ai.max_details`, `system.log_max_lines`, `system.log_patterns`, `system.programs`, `system.procs.*`, `system.services.*` and `environment.shellcheck.{severity,exclude}`, replacing values that were hard-coded.
- `packages` runs against the environment of a fresh login shell (`packages.env: login`, the default; `process` restores the old behaviour), so a terminal opened before a PATH change no longer reports stale problems. If the shell cannot start it falls back and reports `packages.login_env`. The summary shows which environment was used.
- `packages` phase 2: `audit packages registry [pkg...]` looks packages up on PyPI, npm, crates.io (sparse index, API only on new releases, one request per second), the Go module proxy (honours `GOPROXY`, `GONOPROXY`, `GOPRIVATE`), rubygems.org and GitHub through `gh`, and caches latest version, release date, description, repository, homepage, license, keywords and deprecated, yanked and archived status in the store. `-F/--force` ignores cache age; `-a/--ai-tags` and `-A/--ai-retag` tag packages through the `claude` CLI from the `packages.tags` vocabulary.
- The packages inventory shows LATEST (colored by how far behind), RELEASED (age of the latest release) and TAGS, read from the cache with a header saying how old it is; plain scans never contact a registry. The HTML report adds tag, text and outdated filters.
- `audit packages -t/--tag`, `-f/--find`, `-u/--outdated` filter the inventory and imply `--list`; `--json` adds the annotated inventory as `packages`.
- `packages` phase 3: `audit packages update [pkg...]` updates outdated packages one at a time with each manager's command (`uv tool upgrade`, `pnpm add -g NAME@latest`, `cargo install --locked`, `go install PKG@latest`, `gem update --user-install`, `gh extension upgrade`) behind a progress bar with a status line per package. It refreshes the registry cache first, prints the plan and asks `[y/N]` (`-y/--yes` skips it and is required without a terminal; `-N/--dry-run` stops after the plan with the commands). Major releases need `-m/--major`; git and path installs and `packages.update.exclude` entries are skipped; `-x/--stop-on-error` stops at the first failure. Updates are verified against a fresh inventory, so a command that exits 0 without changing the version fails. Results and the tail of failed output are saved; `-L/--last` shows the last update, the `packages` report shows its counts, and a failed attempt is noted on the package's outdated task. Config `packages.update.timeout` (15m) and `packages.update.exclude`.
- `audit packages info <pkg>` and `audit packages tag [<pkg> [tag...]] [-d]`. Automatic tags (manager, runtime, `git`, `local`, `mine`) are derived; user and AI tags are stored.
- Checks `registry.outdated` (one task per manager), `registry.major_behind`, `registry.deprecated`, `registry.yanked`, `registry.archived`, `registry.unmaintained` and `registry.error`.
- Config keys `github_user`, `packages.registry.{max_age,metadata_max_age,concurrency,timeout,unmaintained_after}` and `packages.tags`.
- AI providers: `ai.provider` picks `claude` (as before) or `codex` (`codex exec --sandbox read-only --ephemeral` from an empty temp dir, prompt on stdin, told not to run commands); per-provider `ai.claude.{command,model}` and `ai.codex.{command,model}`; `-I/--ai-provider` overrides it for one run. Cache entries are keyed by provider too; existing claude entries stay valid.
- `audit analyze`: one AI review across every command's saved results, the open tasks and the last update's failures. `-t/--tasks` asks for structured suggestions (JSON schema) and files them as tasks with source `ai`, reconciled across runs without overriding statuses you set; scans never resolve them.
- `audit todo explain ID` and the task editor's `e` key: an AI explanation of one task with every detail of the findings behind it.
- `-e/--explain` on `packages update` and `packages runtimes update|migrate`, after a run with failures or with `-L`: an AI explanation of the failed items from their command output.
- `packages` phase 4: `audit packages runtimes` lists python, node, rust, go and ruby with their owner (uv, pnpm, rustup, system, manual), the newest release of the installed line and overall, and how many packages run on another version; releases come from `uv python list`, nodejs.org, go.dev and `rustup check`, cached in the store (`-F/--force` refreshes). `runtimes update [rt...]` runs `uv python upgrade MINOR`, `pnpm runtime set node VERSION -g` and `rustup update TOOLCHAIN`, within the installed line unless `-m/--major` (new python minor, newest node LTS); system-owned go and ruby are reported and skipped. `runtimes migrate [rt...]` reinstalls uv tools on the default python, pnpm globals after a node major change, and user gems from an old ruby ABI dir, plus with `-b/--rebuild` cargo and go binaries built by an older toolchain; afterwards it offers to trash stale runtime dirs (`gio trash`) and uninstall replaced python patches, kept under `-y` unless `-P/--prune`. Both confirm, verify against a fresh scan, save results (`-L/--last`) and share `-N`, `-y`, `-x`, `-j` with `packages update`.
- Check `runtime.outdated` (from the runtime cache). `runtime.drift` now covers pnpm globals after a node major change (audit remembers the major they were installed under), is a notice for uv and pnpm, and hints at `audit packages runtimes migrate`.
- `packages.json` in the export carries the runtimes; `updates.json` items carry `kind` (`package`, `runtime`, `migration`).
- Export files for dashboards and scripts: `summary.json`, `<command>.json`, `tasks.json` and `updates.json` in `export.dir` (default `$XDG_DATA_HOME/audit/export`), versioned with `schema_version`, written atomically after every command that saves something (also when it then fails) and on demand with `audit export [-d DIR]`. Raw scanner data and update command output are not exported. Config `export.enabled` and `export.dir`.
- `just release [patch|minor|major]` (`tools/release`): semver bump inferred from this file, dated section, `Release vX.Y.Z` commit, annotated tag, atomic push of `main` and the tag.
- A `justfile` with `build`, `run`, `install`, `test` (runner argument), `test-one`, `cover`, `lint`, `vet`, `fmt`, `fmt-check`, `check`, `manpage` and `clean`.

### Changed

- `ai.command` and `ai.model` move to `ai.claude.command` and `ai.claude.model`; the old keys are ignored, so `audit config --init --force` (or editing the file) carries a custom value over.

- The database schema is version 2 (`update_items.kind`); a version 1 database is upgraded in place on open.
- `audit packages update -L` shows the last package update, not a runtime update or migration.

- The "N task(s) updated" notice counts only tasks created, reopened, resolved or with new content; a rescan that only sees the same problems again is silent. Content changes now bump a task's `updated_at`.
- Registry findings carry the release date (`released 2026-10-13`, `no release since ...`) instead of a relative age, so task titles do not change every day.
- Config moves to `~/.config/audit.yaml`; environment overrides use the `AUDIT_` prefix.
- Shell start-up time excludes background jobs a startup file leaves running; the time is stamped by the shell itself.
- Task titles no longer repeat the subject when the finding message already starts with it.
- The `--procs`/`--services`/`--users`/`--logs`/`--programs`/`--all` switches are replaced by `audit system -O procs,services,users,logs,programs`.

### Removed

- The Anthropic SDK client and API-key configuration (`--tokens`, `--model`, `--claude-verbosity`, `--no-claude`); AI review now goes through the `claude` CLI and is off by default.
- Markdown file output (`--output`); use `--json` or the HTML report.
- The Makefile; use `just`.

### Previously unreleased

### Added

- End-to-end integration tests for `runRoot` covering `--version`, `--help` (asserts every flag is documented), `--procs --no-claude` smoke (stdout shape), `--procs --no-claude --output FILE` (markdown file shape), `--logs=invalid_source` (validation error), `--programs=typo` (validation error), `--users --no-claude`, `--all --no-claude`, and YAML config loading from `XDG_CONFIG_HOME`.
- `runRoot` now writes the stdout report to `cmd.OutOrStdout()` instead of `os.Stdout` directly so tests can capture output via `cmd.SetOut(buf)`. No behavior change for users — `OutOrStdout()` defaults to `os.Stdout`.

- `--programs` analyzers expanded from `{sshd, nginx}` to `{sshd, nginx, postgres, apache, docker, cron}`. Each new analyzer follows the existing skipped-when-absent pattern so a host that lacks the program produces a clean "no <X> config" note rather than an error.
  - **postgres**: globs `/etc/postgresql/*/main/postgresql.conf`, parses key=value directives, and audits `listen_addresses` (warns on `*` / `0.0.0.0`), `ssl off` (warning), `password_encryption md5` (notice; deprecated since PG 10), `log_statement all` (notice). Sibling `pg_hba.conf` adds two rules: `trust` auth method (critical) and plain `host` (non-`hostssl`) on a non-loopback address (warning).
  - **apache**: detects `apache2.conf` (Debian/Ubuntu) or `httpd.conf` (RHEL/Fedora). Runs `apache2ctl|apachectl|httpd|apache2 -t` for syntax. Reads main config plus `conf.d`, `conf-enabled`, `sites-enabled`, `mods-enabled` `*.conf` files. Findings: `ServerTokens Full|OS` (notice), `ServerSignature On` (notice), `TraceEnable On` (warning), `Options Indexes` (warning), deprecated `SSLProtocol` (error), weak `SSLCipherSuite` (RC4/DES/MD5/NULL) (error).
  - **docker**: parses `/etc/docker/daemon.json`. Findings: `tcp://` host without `tlsverify=true` (critical — anyone reaching the socket has root on the host), explicit `icc=true` (notice), `live-restore=false` (notice), `no-new-privileges=false` (notice), `json-file` log driver without `max-size` log-opt (notice — disk-fill vector). Parse failures themselves surface as an error finding so the user knows the engine is reading invalid JSON.
  - **cron**: walks `/etc/crontab`, `/etc/anacrontab`, and `/etc/cron.d/*`. Findings: world-writable cron file (critical), group-writable (warning), insecure `http://` curl/wget/fetch fetch in a job command (warning).
- `--programs` (no value) now defaults to every supported analyzer (was `sshd,nginx`).

## [0.1.0] - 2026-04-27

Initial release. Every spec subcommand switch is implemented end-to-end and exercised by tests.

### Added

#### Scanners

- `internal/scan/procs`: process scanner via `gopsutil/v4`. Surfaces zombies, high CPU, high memory, and high thread counts.
- `internal/scan/services`: systemd services on system and user buses via `systemctl --output=json` + `systemctl show`. Findings for failed, masked, load-error, missing-fragment, world-writable unit files, and high restart counts. Gracefully skips user scope when no session bus is reachable.
- `internal/scan/users`: parses `/etc/passwd`, `/etc/group`, and (best-effort) `/etc/shadow`. Findings for extra UID 0 users, UID/GID collisions, system accounts with login shells, members of privileged groups (`sudo`/`wheel`/`root`/`adm`/`docker`/`lxd`/`kvm`/`disk`, with the trivial `root`-in-`root` case suppressed), empty/locked password hashes, and loose mode/owner on the three system files. When `/etc/shadow` is unreadable, the scan continues with an info-severity finding noting that hash checks were skipped.
- `internal/scan/logs`: per-source dispatcher with bucketed pattern aggregation (Normalize collapses PIDs / IPs / UUIDs / hex / paths / numbers) and high-priority rules: kernel panic, OOM kill, hardware error, kernel BUG, segfault, I/O error, filesystem error, auth failure, sudo-not-in-sudoers, audit failed.
  - `journal` runs `journalctl` with the user's `--journal` passthrough flags plus a forced `--output=json` for stable parsing.
  - `dmesg` prefers `dmesg --kernel --ctime` and falls back to `/var/log/dmesg` when the kernel ring buffer is restricted.
  - `boot` reads `/var/log/boot.log`; falls back to `journalctl -b -p err` when the file is missing/empty.
  - `auth` reads `/var/log/auth.log`; falls back to `journalctl SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 -p info` (auth + authpriv facilities).
  - `kern` reads `/var/log/kern.log`; falls back to `journalctl -k` (kernel transport).
  - `misc` walks `/var/log/` recursively, skipping compressed archives (gz/xz/zst/bz2/lz4/zip/7z), `.journal` binaries, the `journal/` and `private/` subdirectories, files already covered by other sources, rotated tails (`*.log.1`, etc.), and per-file >5 MiB (with a truncation flag). Honors a global per-walk line cap so the walk terminates promptly.
- `internal/scan/programs`: per-program configuration audits.
  - **sshd**: parses `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` (first-occurrence-wins per OpenSSH semantics, Match blocks skipped). Findings: `PermitRootLogin yes` (critical), `PermitRootLogin without-password|prohibit-password` (notice), `PasswordAuthentication yes` (warning), `PermitEmptyPasswords yes` (critical), Protocol 1 (critical), `X11Forwarding yes` (notice), `PermitTunnel` non-no (notice), `LogLevel QUIET|FATAL|ERROR` (notice), `MaxAuthTries > 6` (notice). The `sshd -t -f` syntax check is run; the unprivileged "no hostkeys available" failure is downgraded to a note instead of a false-positive finding.
  - **nginx**: skipped gracefully when not on PATH. Otherwise runs `nginx -t` for syntax check and `nginx -T` for the effective config dump, then matches: `server_tokens on` (notice), `autoindex on` (warning), deprecated `ssl_protocols` (TLSv1/TLSv1.1/SSLv2/SSLv3) (error), weak `ssl_ciphers` (RC4/DES/MD5/NULL) (error).

#### CLI / Infrastructure

- `cmd/sysaudit` cobra CLI implementing the full subcommand-switch surface from the spec: `--procs`, `--services`, `--users`/`--groups`, `--logs[=LIST]`, `--journal=FLAGS`, `--programs[=LIST]`, `--all`, plus global `--verbose`/`--debug`/`--quiet`/`--output`/`--version` and Claude controls (`--tokens`, `--model`, `--analysis-level`, `--claude-verbosity`, `--no-claude`).
- `internal/log` wrapping `charmbracelet/log`, level driven by `--verbose`/`--debug`/`--quiet`.
- `internal/config`: viper-backed loader for `~/.config/sysaudit/config.yaml` (XDG-aware); CLI flags override config values; `ANTHROPIC_API_KEY` honored as a fallback.
- `internal/claude`: wraps `anthropic-sdk-go`. Honors token budget, analysis level, and verbosity. Renders the scan digest as a JSON-payload prompt with a level-tuned system prompt.
- `internal/report`: stdout (colorful via `lipgloss` + Claude analysis rendered with `glamour`) and Markdown file output. Honors `NO_COLOR`.

#### Build / Distribution

- `Makefile` targets: `build`, `lint`, `test` (with `TEST_RUNNER=go|gotestsum|gotestfmt|tparse`), `test-one`, `cover`, `manpage`, `tools`, `help`.
- `make manpage` renders `man/sysaudit.1` from `man/sysaudit.1.md` via `go run github.com/cpuguy83/go-md2man/v2` — pure Go, no pandoc required.
- `golangci-lint` v2 configuration with `errcheck`, `govet`, `staticcheck`, `revive`, `gocritic`, `gosec`, `unconvert`, plus `gofmt`/`goimports` formatters.
- GitHub Actions CI workflow: gofmt verification, `go vet`, golangci-lint pinned to v2.11.4, `make test` (race + count=1), `make build`, `make manpage`. Concurrency-grouped, contents:read only.
- GoReleaser v2 release workflow: linux amd64 + arm64 static binaries, ldflags-injected version, archives include README/CHANGELOG/manpage, checksums.txt, GitHub release with auto-derived changelog.

#### Documentation

- `README.md`: overview, quickstart, scanner table, configuration, dev cheat sheet, doc pointers.
- `man/sysaudit.1.md`: full manpage source with NAME/SYNOPSIS/DESCRIPTION/OPTIONS/CONFIGURATION/EXAMPLES/EXIT STATUS/FILES/ENVIRONMENT/SEE ALSO sections.
- `CLAUDE.md`: spec + package layout + conventions for Claude Code instances working in this repo.
