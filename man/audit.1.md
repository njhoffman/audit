audit 1 "October 2026" "audit Manual"
=====================================

# NAME

audit \- scan system health, the shell environment and installed packages, and track what to fix

# SYNOPSIS

**audit** [_global options_] [**-s**|**-H**|**-o**]

**audit** **system** [_scan options_] [**-O** _parts_]

**audit** **environment** [_scan options_]

**audit** **packages** [_scan options_] [**-M** _managers_] [**-t** _tag_]... [**-f** _text_] [**-u**]

**audit** **packages** **registry** [**-M** _managers_] [**-F**] [**-a**|**-A**] [**-j**|**-l**] [_package_...]

**audit** **packages** **update** [**-M** _managers_] [**-N**] [**-y**] [**-m**] [**-x**] [**-j**] [_package_...]

**audit** **packages** **update** **-L** [**-j**]

**audit** **packages** **info** [**-j**] _package_

**audit** **packages** **tag** [**-d**] [**-j**] [_package_ [_tag_...]]

**audit** **todo** [**show**|**set**|**note**|**add**|**rm**] ...

**audit** **history** [_command_] [**-l** _n_] [**-j**]

**audit** **config** [**-i** [**-f**]] [**-p**]

# DESCRIPTION

**audit** scans a Linux workstation and saves the results in a database. Each issue and suggestion a scan finds becomes a task with a priority and a status. Saved results are shown again on later runs with their age; results older than the stale thresholds are highlighted.

Without a command, **audit** opens an interactive dashboard when stdin and stdout are terminals, and prints the summary otherwise.

# COMMANDS

**system**
:   Processes, systemd units, user and group accounts, logs (journal, dmesg, boot, auth, kern, misc) and program configurations (sshd, nginx, apache, postgres, docker, cron).

**environment**
:   Starts each configured login shell with and without a terminal, records unexpected output and which startup files are sourced, times start-up, and checks PATH, environment variables and the startup scripts (syntax and shellcheck).

**packages**
:   Inventories uv, pnpm, cargo, go, gem and gh, and checks for broken or shadowed executables, runtime drift, stale runtime directories and misplaced installs. By default it runs against the environment of a fresh login shell (the first of **environment.shells**), so a terminal opened before a PATH change does not report stale problems; if that shell cannot start, it falls back to its own environment and reports **packages.login_env**.

    The inventory (**\-\-list**) shows each package's latest release, how long ago it was published and its tags, read from the registry cache. The header says when the cache was last refreshed; a plain scan never contacts a registry. Cached data adds the checks **registry.outdated** (info, one task per manager), **registry.major_behind** (notice), **registry.deprecated**, **registry.yanked** and **registry.archived** (warnings), **registry.unmaintained** (a suggestion when the latest release is older than **packages.registry.unmaintained_after**) and **registry.error** (info, a failed lookup).

**packages registry** [_package_...]
:   Looks installed packages up on PyPI, npm, crates.io, the Go module proxy, rubygems.org and GitHub (through **gh**), caches the latest version, release date, description, repository, homepage, license, keywords and deprecation, archive and yank status, then rescans so findings and tasks reflect it. Entries younger than **packages.registry.max_age** are reused unless **-F** is given; named packages are always looked up. Descriptions are refreshed after **packages.registry.metadata_max_age** where that costs extra requests. Go modules matched by **GONOPROXY**/**GOPRIVATE**, or with **GOPROXY** set to **direct** or **off**, are not looked up. Requests to crates.io are spaced one second apart, as its crawler policy asks.

**packages update** [_package_...]
:   Updates packages behind their latest release, one at a time, with each manager's own command: **uv tool upgrade**, **pnpm add -g** _name_**@latest**, **cargo install \-\-locked**, **go install** _package_**@latest** (each Go binary by its own package path), **gem update \-\-user-install** and **gh extension upgrade**. The inventory is scanned and the registry cache refreshed first, then the plan is printed and confirmed with **[y/N]**; without a terminal, **-y** is required. Without packages, every outdated package is planned except major releases (**-m** includes them), **packages.update.exclude** entries and packages installed from git or a path. Named packages are always listed, with the reason when one is skipped; a name that matches nothing is an error.

    Each update prints a status line under the progress bar. A command that exits 0 counts as updated only when a fresh inventory shows a new version; one that leaves the version unchanged, or removes the package, is a failure. Commands are stopped after **packages.update.timeout**. Failures are itemized with the command and the tail of its output, and saved with the update; the exit status is 1 when any failed. The inventory is rescanned afterwards so tasks follow, a failed attempt is noted on the package's **registry.outdated** item until its version changes, and the **packages** report shows the last update's counts. **-L** shows the last update again.

**packages info** _package_
:   Shows the cached details and tags of one package from the saved inventory, without scanning.

**packages tag** [_package_ [_tag_...]]
:   Without arguments, lists every tag with how many packages carry it and where the tags came from. With a package, shows its tags; with tags, adds them as user tags, or removes them with **-d**. Automatic tags (the manager, the runtime, **git**, **local** and **mine** for repositories owned by **github_user**) are derived and cannot be removed. Tags are lowercased with words joined by dashes.

    A _package_ is a name or Go module path, or _manager_**:**_name_ when the name is ambiguous.

**todo**
:   Lists open and in-progress tasks. Subcommands: **show** _ID_, **set** _ID_ _STATUS_ [**-N** _note_], **note** _ID_ _TEXT_, **add** _TITLE_ [**-p** _priority_] [**-C** _command_] [**-H** _hint_] [**-N** _note_], **rm** _ID_ (manual tasks only).

**history** [_command_]
:   Lists saved runs, newest first.

**config**
:   Prints the effective configuration and the file it came from. **-i** writes the default file (**-f** overwrites), **-p** prints the path.

# GLOBAL OPTIONS

**-c**, **\-\-config** _file_
:   Config file. Default **$XDG_CONFIG_HOME/audit.yaml**, created with the defaults on first run. A file given with **-c** must exist.

**-n**, **\-\-no-color**
:   Disable colors. Colors are also off when **NO_COLOR** is set or stdout is not a terminal.

**-W**, **\-\-width** _n_
:   Wrap output at _n_ columns. Default: the terminal width, unlimited when redirected.

**-v**, **\-\-verbose**
:   Show every detail line and info logs.

**-D**, **\-\-debug**
:   Show debug logs.

**-q**, **\-\-quiet**
:   Errors only: no progress bars or notices.

**-V**, **\-\-version**
:   Print the version.

**-h**, **\-\-help**
:   Help for any command.

# ROOT OPTIONS

**-s**, **\-\-summary**
:   Print every command's last run, its age, its findings and its open tasks.

**-H**, **\-\-html**
:   Write the HTML report of every command's latest run and the index page.

**-o**, **\-\-open**
:   Like **\-\-html**, then open the index with **xdg-open**.

# SCAN OPTIONS

These apply to **system**, **environment** and **packages**. Without an output option, saved results younger than the warn threshold are shown and older ones trigger a scan.

**-r**, **\-\-rescan**
:   Scan now even if saved results are fresh.

**-R**, **\-\-report**
:   Print the full saved report. Never scans unless **-r** is given.

**-l**, **\-\-list**
:   Print one line per finding plus the command's inventory. Never scans unless **-r** is given.

**-s**, **\-\-summary**
:   Print the header and statistics only. Never scans unless **-r** is given.

**-j**, **\-\-json**
:   Print the run as JSON (**{"saved": bool, "run": {...}}**). Never scans unless **-r** is given.

**-H**, **\-\-html**
:   Write the HTML report and print its path on stderr.

**-o**, **\-\-open**
:   Write the HTML report and open it.

**-a**, **\-\-ai**
:   Add an AI review through the **claude** CLI. Cached per result set.

**-A**, **\-\-ai-refresh**
:   Like **\-\-ai**, but ask again instead of using the cache.

**-L**, **\-\-level** _level_
:   AI analysis level: **brief**, **standard** or **deep**.

**-m**, **\-\-min-severity** _severity_
:   Hide findings below **critical**, **error**, **warning**, **notice** or **info**.

**-k**, **\-\-check** _prefix_
:   Show only findings whose check id starts with _prefix_.

**-O**, **\-\-only** _parts_ (system)
:   Scan only these parts: **procs**, **services**, **users**, **logs**, **programs**.

**-M**, **\-\-manager** _names_ (packages, packages registry)
:   Inventory only these managers.

**-t**, **\-\-tag** _tag_ (packages)
:   List only packages carrying every given tag. Repeatable; implies **\-\-list**.

**-f**, **\-\-find** _text_ (packages)
:   List only packages whose name, description or executables contain _text_, ignoring case. Implies **\-\-list**.

**-u**, **\-\-outdated** (packages)
:   List only packages behind their latest release. Implies **\-\-list**.

With **\-\-json**, **packages** adds the inventory joined with the registry cache and tags (filtered by **-t**, **-f** and **-u**) as **packages**.

**\-\-report**, **\-\-list**, **\-\-summary** and **\-\-json** are mutually exclusive.

# PACKAGES REGISTRY OPTIONS

**-F**, **\-\-force**
:   Look everything up, ignoring the age of cached entries.

**-a**, **\-\-ai-tags**
:   After the lookup, ask the **claude** CLI to tag packages that have registry data and no AI tags yet, choosing up to four tags each from **packages.tags**.

**-A**, **\-\-ai-retag**
:   Like **-a**, but tag every package again and bypass the AI cache. Tags removed with **packages tag -d** are only put back by this option.

**-j**, **\-\-json** / **-l**, **\-\-list**
:   Print the result as JSON, or as findings plus the inventory, instead of the report.

# PACKAGES UPDATE OPTIONS

**-M**, **\-\-manager** _names_
:   Update only these managers.

**-N**, **\-\-dry-run**
:   Print the plan with the command each package would run, then stop.

**-y**, **\-\-yes**
:   Update without asking.

**-m**, **\-\-major**
:   Also update across major releases.

**-x**, **\-\-stop-on-error**
:   Skip the remaining updates after the first failure. By default every planned update runs.

**-L**, **\-\-last**
:   Show the last update with every result and the output of its failures; update nothing. Takes no packages, **-N** or **-y**.

**-j**, **\-\-json**
:   Print the plan (with **-N**) or the update as JSON.

# PACKAGES TAG OPTIONS

**-d**, **\-\-delete**
:   Remove the given tags, whatever assigned them.

**-j**, **\-\-json**
:   Print as JSON (also for **packages info**).

# TODO OPTIONS

**-C**, **\-\-cmd** _command_
:   Only tasks of this command.

**-p**, **\-\-priority** _list_
:   Only these priorities: **high**, **medium**, **low**, **suggestion**.

**-S**, **\-\-status** _list_
:   Only these statuses: **open**, **in-progress**, **done**, **wont-do**, **resolved**.

**-a**, **\-\-all**
:   Include closed tasks.

**-f**, **\-\-find** _text_
:   Only tasks whose title, key or note contains _text_.

**-j**, **\-\-json**
:   Print tasks as JSON.

**-i**, **\-\-interactive**
:   Browse and change tasks in a terminal UI.

# TASKS

Errors and criticals become **high** tasks, warnings **medium**, notices **low**, and suggestions **suggestion**. Info findings of one check share a single **low** task. A rescan adds tasks for new findings and marks tasks **resolved** when their finding is gone; **won't do** tasks stay closed. A scan narrowed with **\-\-only** or **\-\-manager** only resolves tasks of the parts it scanned.

# CONFIGURATION

The first run creates **~/.config/audit.yaml** with every key set to its default and commented; edit or delete any key. **audit config \-\-init \-\-force** restores it. The defaults:

    data_dir: ""               # empty: $XDG_DATA_HOME/audit
    github_user: ""            # empty: detected with gh api user on the first registry run
    history: 20                # saved runs kept per command
    no_color: false
    stale:
      warn: 24h
      old: 168h
      commands:
        files: {warn: 168h, old: 720h}
    ignore: []                 # command:check:subject, command:check or check
    display:
      details: 5               # detail lines per finding; -v shows all
    ai:
      command: claude
      model: claude-sonnet-5-5
      analysis_level: standard
      timeout: 5m
      max_details: 10          # detail lines per finding in the prompt
    system:
      journal: "-p 4 -b -n 500 --no-pager"
      logs: [boot, dmesg, journal]
      log_max_lines: 5000
      log_patterns: 10
      programs: [sshd, nginx, postgres, apache, docker, cron]
      procs: {top: 10, high_cpu: 80, high_mem: 25, high_threads: 1000}
      services: {user_units: true, high_restarts: 5, unit_file_perms: true}
    packages:
      env: login               # login (fresh login shell) or process
      managers: [uv, pnpm, cargo, go, gem, gh]
      scan_dirs: [~/.local/bin]
      registry:
        max_age: 24h           # reuse cached versions younger than this
        metadata_max_age: 168h # refetch descriptions that cost extra requests
        concurrency: 8
        timeout: 10s           # per package
        unmaintained_after: 26280h  # 3 years; 0 disables registry.unmaintained
      update:
        timeout: 15m           # per package update command
        exclude: []            # packages never updated, e.g. [cargo:ripgrep, black]
      tags: [cli, tui, gui, library, lsp, formatter, linter, ...]  # AI tag vocabulary
    environment:
      shells: [zsh, bash]
      startup_files: [~/.profile, ~/.bash_profile, ~/.bashrc, ~/.zshenv, ~/.zshrc, ...]
      startup_dirs: [~/.shell]
      known_output: ['^\s*--\s+[0-9.]+s\s+::']
      startup_timeout: 15s
      slow_startup: 500ms
      shellcheck: {severity: warning, exclude: [SC2034]}

Keys can also be set as **AUDIT_**_KEY_ environment variables, with dots as underscores (**AUDIT_STALE_WARN=12h**).

# EXAMPLES

Open the dashboard:

    audit

Rescan only the logs and services:

    audit system -r -O logs,services

Show saved package problems at warning or worse, with the inventory:

    audit packages -l -m warning

Refresh the registry cache, tag new packages with AI, then list outdated Python tools:

    audit packages registry -a
    audit packages -u -t uv

Preview the updates, run them, then show the failures again:

    audit packages update -N
    audit packages update
    audit packages update -L

Update one package across a major release without asking:

    audit packages update -m -y cargo:ripgrep

Tag a package and show it:

    audit packages tag ripgrep search
    audit packages info cargo:ripgrep

Ask for a deep AI review of the environment results and open the HTML report:

    audit environment -a -L deep -o

Mark task 12 done with a note:

    audit todo set 12 done -N "fixed in dotfiles"

# EXIT STATUS

**0** on success, **1** on any error (including **\-\-report**, **\-\-list**, **\-\-summary** or **\-\-json** with no saved run).

# FILES

**~/.config/audit.yaml**
:   Configuration, created with the defaults on first run.

**~/.local/share/audit/audit.db**
:   Runs, findings, tasks, the package registry cache and tags, saved package updates, and the AI response cache.

**~/.local/share/audit/reports/**
:   HTML reports and **index.html**.

# ENVIRONMENT

**XDG_CONFIG_HOME**, **XDG_DATA_HOME**
:   Base directories for the config file and the data directory.

**NO_COLOR**
:   Disables colors.

**AUDIT_***
:   Overrides config keys.

# SEE ALSO

**claude**(1), **journalctl**(1), **shellcheck**(1)
