# audit

[![CI](https://github.com/njhoffman/audit/actions/workflows/ci.yml/badge.svg)](https://github.com/njhoffman/audit/actions/workflows/ci.yml)

`audit` scans a Linux workstation and keeps the results: system health, the shell environment and its startup scripts, and user-level packages. Every issue and suggestion becomes a prioritized task you can track from the command line or an interactive dashboard, and every command can write a self-contained HTML report.

Scans are saved in a SQLite database. Viewing a command again shows the saved results while they are fresh and says how old they are, highlighting results that are stale (yellow) or old (red). `--rescan` scans again.

## Commands

| Command | What it scans |
|---|---|
| `audit system` | processes, systemd units, user and group accounts, the journal, dmesg and boot logs, and program configs (sshd, nginx, apache, postgres, docker, cron) |
| `audit environment` | each configured login shell with and without a terminal: unexpected startup output, which files are sourced, startup time, PATH problems, environment variables, startup script syntax and shellcheck |
| `audit packages` | user package managers (uv, pnpm, cargo, go, gem, gh): inventory, broken and shadowed executables, runtime drift, stale runtime dirs, misplaced installs |
| `audit todo` | the tasks scans create, plus tasks added by hand |
| `audit history` | saved runs |
| `audit config` | the effective configuration; `--init` rewrites the default file |

`audit` with no command opens the dashboard in a terminal, or prints the summary when output is redirected (or with `--summary`).

## Usage

```sh
just build                     # or: just install

audit                          # dashboard: every command's last run, age, findings, open tasks
audit -s                       # the same overview as text
audit system                   # saved results if fresh, otherwise scan
audit system -r -O logs,services   # rescan only some parts
audit packages -l              # one line per finding plus the package inventory (never scans)
audit environment -R           # full saved report (never scans)
audit packages -j              # saved run as JSON
audit system -m warning -k logs.   # hide findings below warning, only checks starting with logs.
audit system -a                # add an AI review through the claude CLI (cached per result set)
audit environment -o           # write the HTML report and open it
audit -o                       # write every report plus the index page and open the index

audit todo                     # open and in-progress tasks
audit todo -i                  # browse and change tasks in a terminal UI
audit todo -C packages -p high,medium
audit todo set 12 done -N "removed in dotfiles"
audit todo set 7 wont-do       # a won't-do task stays closed across rescans
audit todo add "split aliases/system.sh" -p low -C environment
```

### Freshness

A bare `audit <command>` reuses saved results younger than the warn threshold (default 24h) and scans otherwise. `--report`, `--list`, `--summary` and `--json` never scan; if nothing is saved they fail with the command to run. `--rescan` always scans.

### Tasks

Errors and criticals become high-priority tasks, warnings medium, notices low, and suggestions suggestion. Informational findings of one check are rolled into a single low-priority task. Rescans keep tasks in sync: new findings add tasks, findings that disappear resolve theirs, and statuses you set (in progress, done, won't do) are kept. A scan limited with `--only`/`--manager` only resolves tasks for the parts it scanned.

### AI review

`--ai` sends the findings (not raw logs, hostnames or timestamps) to the `claude` CLI in print mode with tools disabled and no session persistence. Responses are cached by a hash of the prompt, so asking again about an unchanged result set is free; `--ai-refresh` asks again. `--level` picks brief, standard or deep.

### Dashboard keys

| Screen | Keys |
|---|---|
| dashboard | `j`/`k` move, `enter` report, `r` rescan, `t` tasks, `q` quit |
| report | `j`/`k`/`pgup`/`pgdn` scroll, `r` rescan, `esc` back |
| tasks | `o` open, `i` in progress, `d` done, `w` won't do, `n` note, `/` find, `c` cycle command, `a` show closed, `esc` back |

## Configuration

`~/.config/audit.yaml` (or `$XDG_CONFIG_HOME/audit.yaml`). The first run creates it with every default written out and commented, so the file doubles as the reference; edit or delete any key. `-c FILE` uses another file instead, and that file is never created for you. `audit config` prints the effective settings, `audit config --init --force` restores the defaults, and any key can also be set from the environment as `AUDIT_<KEY>`, dots as underscores (for example `AUDIT_STALE_WARN=12h`).

Besides history, freshness thresholds, ignore rules and the AI settings, the file sets how many detail lines each finding shows (`display.details`), the system scanner's limits (log lines read, process CPU/memory/thread thresholds, service restart threshold, user units, programs checked) and the environment scanner's shells, startup files, slow-startup threshold and shellcheck severity and excludes.

Data lives in `$XDG_DATA_HOME/audit`: `audit.db` (runs, findings, tasks, AI cache) and `reports/` (HTML).

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
just manpage            # man/audit.1 from man/audit.1.md
just cover              # coverage.html
```

Lint and tests must pass before any commit. See [`man/audit.1.md`](man/audit.1.md) for every option and [`CHANGELOG.md`](CHANGELOG.md) for history.
