# audit

[![CI](https://github.com/njhoffman/audit/actions/workflows/ci.yml/badge.svg)](https://github.com/njhoffman/audit/actions/workflows/ci.yml)

`audit` scans a Linux workstation and keeps the results: system health, the shell environment and its startup scripts, and user-level packages. Every issue and suggestion becomes a prioritized task you can track from the command line or an interactive dashboard, and every command can write a self-contained HTML report.

Scans are saved in a SQLite database. Viewing a command again shows the saved results while they are fresh and says how old they are, highlighting results that are stale (yellow) or old (red). `--rescan` scans again.

## Commands

| Command | What it scans |
|---|---|
| `audit system` | processes, systemd units, user and group accounts, the journal, dmesg and boot logs, program configs (sshd, nginx, apache, postgres, docker, cron), storage (fullness, inodes, read-only mounts, opt-in SMART), resources (PSI pressure, memory, swap, OOM kills, load, temperatures, throttling, battery wear), updates (reboot pending, newer kernel, security updates, failed unattended upgrades, old kernels) and security (firewall, exposed ports, ~/.ssh permissions and passphrases, world-writable PATH, time sync) |
| `audit environment` | each configured login shell with and without a terminal: unexpected startup output, which files are sourced, startup time, PATH problems, environment variables, startup script syntax and shellcheck (files under `scripts.roots` are left to `audit scripts`); counts of aliases, functions, variables, commands, completions, key bindings, fpath, widgets and zinit plugins; aliases that run a missing command or hide a program, and fpath problems |
| `audit packages` | user package managers (uv, pnpm, cargo, go, gem, gh) and system ones (apt, snap, flatpak, no sudo needed to scan): inventory, broken and shadowed executables, runtime drift, stale runtime dirs, misplaced installs; checked against a fresh login shell's PATH and variables, not the terminal's; latest releases, release age, deprecation and archive status from a cached registry lookup; tags |
| `audit packages registry` | look packages up on PyPI, npm, crates.io, the Go proxy, rubygems.org and GitHub, cache the results, optionally AI-tag them |
| `audit packages outdated` | refresh the inventory and registry cache, then show outdated packages with installed/latest versions; `-F` forces registry checks, `-l` reads saved results |
| `audit packages update` | update outdated packages one at a time with their own managers (apt, snap and flatpak in one command each, under one `sudo -v` session; apt lists refreshed first), verify the new versions, save and itemize failures |
| `audit packages runtimes` | python, node, rust, go and ruby: installed version, owner (uv, pnpm, rustup, system), newest release of the line and overall, packages on another version |
| `audit packages runtimes update` / `migrate` | update uv pythons, pnpm's node and rustup toolchains (same line by default, `-m` for a new python minor or node LTS); reinstall packages onto the current runtime, then offer to trash stale runtime dirs |
| `audit packages bins` | loose binaries in `packages.scan_dirs`; `bins track NAME OWNER/REPO[:GLOB]` records a GitHub origin, then `packages update` (or `bins install`) keeps it at the latest release: `gh release download`, sha256 check, atomic replace, backup |
| `audit packages info` / `tag` | one package's cached details; list, add or remove tags |
| `audit repos` | git repositories under the ghq root and home: uncommitted changes, unpushed commits, stashes, behind/no upstream, operations in progress, no remote, duplicates, ghq layout, broken `~/git` links; yours vs others, language and GitHub topics as tags; `refresh` fetches all and reads GitHub data (renamed, default branch, archived, deleted) through `gh api graphql` |
| `audit repos sync` | fetch, then fast-forward clean repos behind their upstream and apply GitHub migrations (new origin after a rename, renamed default branch); `-p` pushes your own repos that are only ahead, `-m` moves clones to their ghq path; never merges, rebases, stashes or force-pushes |
| `audit configs` | syntax of json/jsonc/yaml/toml/ini/xml configs, read-only program validators (git, ssh, systemd units, i3/sway, fish, tmux), credentials in files others can read, and configs of uninstalled programs with their likely package; `configs clean` trashes orphans |
| `audit scripts` | your scripts with descriptions from their headers (or `scripts describe` via AI, cached by content), checked without running them: shellcheck and language syntax checks, missing interpreters, exec bit, CRLF, PATH shadowing, commands not installed, dead scripts; `scripts info NAME` |
| `audit ai` | AI CLIs (installed, logged in), provider keys by name, ollama, MCP servers whose commands are missing, Claude Code hooks and over-broad permissions, AI projects with their sessions; `--ping` checks providers answer |
| `audit files` | where disk space goes (largest directories) and what can be reclaimed: tool and system caches, idle projects' node_modules/target/.venv, data of uninstalled programs, large files, old downloads, the trash, duplicates (hash-confirmed), core dumps, empty dirs, broken links |
| `audit files clean` | reclaim it: caches through their own cleaners (sudo once for apt, journal, snaps), idle build dirs and core dumps deleted, your own files (orphaned data, old downloads, duplicate copies) to the trash; `-C all` adds those and emptying the trash |
| `audit todo` | the tasks scans create, plus tasks added by hand; `todo explain ID` asks the AI about one |
| `audit analyze` | AI review across every command's saved results, open tasks and failed updates; `-t` files AI suggestions as tasks |
| `audit history` | shell history: duplicate entries within each file, large multiline entries and configured literal substring matches; counts and file locations only |
| `audit history sync` | rebuild the configured zsh history file from histdb, preserving its timestamps and durations and keeping a private backup |
| `audit history prune` | preview and remove duplicates or selected unwanted entries, preserving whole records and keeping private backups; `-O patterns,multiline` selects other checks |
| `audit history runs` | saved audit runs (formerly `audit history`) |
| `audit config` | the effective configuration; `--init` rewrites the default file |
| `audit export` | write the JSON snapshots other programs read (they are also rewritten after every command that saves) |

`audit` with no command opens the dashboard in a terminal, or prints the summary when output is redirected (or with `--summary`).

## Usage

```sh
just build                     # or: just install

audit                          # dashboard: every command's last run, age, findings, open tasks
audit -s                       # the same overview as text
audit -r                       # rescan every stale command, several at once, then the overview
audit -r -a -O repos,files     # rescan these two even if fresh
audit system                   # saved results if fresh, otherwise scan
audit system -r -O logs,services   # rescan only some parts
audit packages -l              # one line per finding plus the package inventory (never scans)
audit environment -R           # full saved report (never scans)
audit packages -j              # saved run as JSON
audit history -r               # check saved zsh, bash and fish histories
audit history prune -N         # preview duplicate removals (keeps the first occurrence)
audit history prune            # confirm, back up, remove duplicates, then rescan
audit history prune -O all -N  # preview duplicates, large entries and pattern matches
audit history prune -O patterns # remove configured substring matches after confirmation
audit history runs packages    # list saved audit runs for packages
audit packages registry        # refresh the registry cache (entries younger than 24h are reused), then report
audit packages registry -a     # also AI-tag packages that have no AI tags yet
audit packages update -N       # show what would be updated and the commands
audit packages outdated        # refresh and list installed/latest versions of outdated packages
audit packages outdated -F     # force fresh registry lookups
audit packages outdated -l     # view saved outdated packages without scanning
audit packages update          # update outdated packages (minor and patch), after confirming
audit packages update gh:ok    # update one named package (manager:name)
audit packages update -m       # also permit major releases
audit packages update -L       # show the last update and its failures again
audit packages -u              # outdated packages, with latest version and release age
audit packages -t cli -f json  # packages tagged cli whose name or description mentions json
audit packages info ruff       # cached details and tags of one package (uv:ruff when ambiguous)
audit packages tag ruff linter # add a tag; -d removes; no arguments lists tag counts
audit system -m warning -k logs.   # hide findings below warning, only checks starting with logs.
audit system -a                # add an AI review through the claude CLI (cached per result set)
audit environment -o           # write the HTML report and open it
audit -o                       # write every report plus the index page and open the index

audit todo                     # open and in-progress tasks
audit todo -i                  # browse and change tasks in a terminal UI
audit todo -F                  # the same in fzf (or tui.interface: fzf for -i and bare audit)
audit todo -C packages -p high,medium
audit todo set 12 done -N "removed in dotfiles"
audit todo set 7 wont-do       # a won't-do task stays closed across rescans
audit todo add "split aliases/system.sh" -p low -C environment
audit todo -o                  # searchable tasks page (tasks.html), opened in the browser
audit todo -s -o               # the same page served on 127.0.0.1, with status and note editing
vim -q <(audit todo show 12 -l) # every file:line of a lint task as a quickfix list
```

### Freshness

A bare `audit <command>` reuses saved results younger than the warn threshold (default 24h) and scans otherwise. `--report`, `--list`, `--summary` and `--json` never scan; if nothing is saved they fail with the command to run. `--rescan` always scans. On bare `audit`, `-r` rescans every stale or never-run command (`-a` all of them, `-O` some), `scan.concurrency` at a time after `packages`, then prints the overview.

### Tasks

Errors and criticals become high-priority tasks, warnings medium, notices low, and suggestions suggestion. Informational findings of one check are rolled into a single low-priority task, and shellcheck and parse errors become one task per check and priority (for example "Fix shellcheck errors in 20 shell files") listing every file and line. Rescans keep tasks in sync: new findings add tasks, findings that disappear resolve theirs, and statuses you set (in progress, done, won't do) are kept. A scan limited with `--only`/`--manager` only resolves tasks for the parts it scanned.

### AI review

AI features go through a local CLI picked by `ai.provider` (or `-I/--ai-provider` per run): `claude` in print mode with tools disabled and no session persistence, or `codex exec` in its read-only sandbox, ephemeral, from an empty temp directory. Prompts carry findings, stats and task titles, not raw logs, hostnames or timestamps. Responses are cached by a hash of the provider, model and prompt, so asking again about an unchanged result set is free; `--ai-refresh` asks again. `--level` picks brief, standard or deep.

- `--ai` on any scan: a review of that run.
- `audit analyze`: one review across all commands (shared root causes, the errors that matter, a fix order). `-t` asks for structured suggestions instead and files them as tasks with source `ai`; later runs keep repeated suggestions, add new ones and resolve dropped ones, but never override a status you set, and scans leave them alone.
- `audit todo explain ID`, or `e` in the task editor: cause, impact, fix and how to confirm it for one task, with the full findings behind it.
- `-e/--explain` on `packages update` and `packages runtimes update|migrate` (also with `-L`): why the failed items failed. This sends the tail of their command output.

The dashboard lines up each command's finding counts by severity (`◉` critical, `●` error, `▲` warning, `◆` notice, `○` info) and its open tasks by priority (`●` high, `◐` medium, `○` low, `◇` suggestion). With a Nerd Font, `display.nerd_fonts: true` (or `-G`) swaps the markers for icons and adds icons to commands, report sections and summary groups.

### Dashboard keys

Reports open collapsed: one line per finding, and a compact summary with each group on as few lines as fit and only the stats of the shell in `$SHELL`. `x` expands every finding (hint, all details, key) and both shells' stats, and collapses them again; printed reports (`--report`) are always expanded.

The defaults:

| Screen | Keys |
|---|---|
| dashboard | `j`/`k` move, `enter` report, `r` rescan, `t` tasks, `q` quit |
| report | `j`/`k`/`pgup`/`pgdn` scroll, `g`/`G` top and bottom, `x` expand or collapse findings, `r` rescan, `esc` back |
| tasks | `o` open, `i` in progress, `d` done, `w` won't do, `n` note, `e` explain with AI, `v` editor, `/` find, `c` cycle command, `a` show closed, `esc` back |
| explanation | `j`/`k`/`pgup`/`pgdn` scroll, `r` ask again, `esc` back to tasks |

Every action can be rebound, to as many keys as you like, under `tui.keys` in the config (`status_done: [d, x]`, `editor: []` to unbind); the help line follows the bindings. `man audit` (KEYS) lists the actions and the screens they work on.

### fzf interface

`tui.interface: fzf` (or `-F`/`--fzf` on bare `audit` and `audit todo`) uses fzf lists instead of the terminal UI: the command list previews saved reports, the task list previews tasks, and typing filters as usual. Since letters go to the query, actions are on alt- keys under `tui.fzf_keys`: `enter` report or details in `$PAGER`, `alt-r` rescan, `alt-t` tasks, `alt-o`/`alt-i`/`alt-d`/`alt-w` status, `alt-n` note, `alt-e` explain, `alt-v` editor, `alt-c` cycle command, `alt-a` show closed. Needs fzf 0.51 or later; `man audit` (FZF) has the details.

## Configuration

`~/.config/audit.yaml` (or `$XDG_CONFIG_HOME/audit.yaml`). The first run creates it with every default written out and commented, so the file doubles as the reference; edit or delete any key. `-c FILE` uses another file instead, and that file is never created for you. `audit config` prints the effective settings, `audit config --init --force` restores the defaults, and any key can also be set from the environment as `AUDIT_<KEY>`, dots as underscores (for example `AUDIT_STALE_WARN=12h`).

Besides history, freshness thresholds, ignore rules and the AI settings, the file sets how many detail lines each finding shows (`display.details`), the system scanner's limits (log lines read, process CPU/memory/thread thresholds, service restart threshold, user units, programs checked) which environment the packages scan uses (`packages.env`: `login` or `process`), the registry cache ages, concurrency, timeout and unmaintained threshold (`packages.registry.*`), the per-package update timeout and packages never updated (`packages.update.*`), the AI tag vocabulary (`packages.tags`), your GitHub login for the `mine` tag (`github_user`, detected through `gh` when empty), and the environment scanner's shells, startup files, slow-startup threshold and shellcheck severity and excludes.

Data lives in `$XDG_DATA_HOME/audit`: `audit.db` (runs, findings, tasks, package registry cache and tags, saved updates, AI cache) `reports/` (HTML) and `export/`: JSON snapshots for a dashboard or script to read without touching the database. `summary.json` has each command's freshness, finding counts and open tasks, `<command>.json` the latest run's findings (`packages.json` also the annotated inventory and the runtimes), `tasks.json` every task, `updates.json` the saved package updates. Files are replaced atomically and carry `schema_version`, `generated_at` and `host`; raw scanner data and command output are left out. `export.enabled` and `export.dir` control them; `man audit` (EXPORT FILES) documents the fields.

Shell history checks use `shell_history.files` (default `~/.zsh_history`, `~/.bash_history`, and `$XDG_DATA_HOME/fish/fish_history`), `shell_history.patterns` (case-sensitive literal substrings), `shell_history.max_lines` (10 or more lines per entry), and `shell_history.max_mb` (32 MB per file; larger files are skipped with a scan error). Missing files are skipped. Set `files` explicitly for custom history paths. Bash needs timestamped history to distinguish multiline entries; plain bash history is checked one physical line at a time. Duplicate checks ignore leading and trailing whitespace and compare entries within each file. Findings retain counts and up to 100 file:line locations per check and file, never command text or pattern values. Histories are never modified. The top-level `history: 20` setting still controls saved audit run retention.

Package management from the Python `pkgm` prototype is integrated into `audit packages`: installed versions, cached registry releases, updates through the owning managers, runtime updates and migrations, and tracked loose binaries. `audit system -O programs` checks service configuration; the roadmap in `TODO.md` tracks exposing package version and update information alongside those checks.

`audit history prune` rechecks current history files and honors ignore rules. `--only`/`-O` selects `duplicates` (default), `multiline`, `patterns`, or `all`; optional paths limit it to specific configured files. `-N` previews counts and start lines; `-j -N` produces a JSON plan. Without `-N`, confirm the plan or use `-y`; `-j` execution requires `-y`. It removes whole records with their timestamps/metadata, keeps the first duplicate, creates a mode-0600 `.NAME.audit-backup-*` beside each changed file, replaces the file atomically, and rescans to reconcile tasks. Changed or locked files are refused, as are symlinks, hard links and files owned by others. Close other shell sessions before pruning so they cannot save old entries back from memory. Backups contain the original commands, including removed secrets; restore by copying a backup over its original history path while shells are closed, and remove backups when no longer needed.

`audit packages outdated` refreshes the inventory and registry data subject to cache age; `-F` forces registry lookups. `-M gh,uv` limits managers and `-f TEXT` filters the displayed packages. `-l`, `-R`, `-s` and `-j` use saved results unless `-r` or `-F` is also supplied. System-manager checks use their existing package lists; `audit packages update` refreshes apt lists before applying updates. Preview with `audit packages update -N`, then run `audit packages update` (all eligible packages) or `audit packages update manager:name` (selected packages). Updates require confirmation or `-y`, and major versions require `-m`.

## Development

```sh
just                    # list the recipes
just build              # bin/audit
just run system -l      # build, then run with arguments
just lint               # golangci-lint
just test               # go test -race -count=1 ./...
just test tparse        # or gotestsum, gotestfmt
just test-one ./internal/config TestLoad
just check              # gofmt check, lint, test, build: run before committing
just release -n         # dry run of a release: version bump inferred from CHANGELOG.md
just release            # gate, bump, date the changelog, commit, tag vX.Y.Z, push main + tag, reinstall
just manpage            # man/audit.1 from man/audit.1.md
just cover              # coverage.html
```

Lint and tests must pass before any commit. See [`man/audit.1.md`](man/audit.1.md) for every option and [`CHANGELOG.md`](CHANGELOG.md) for history.
