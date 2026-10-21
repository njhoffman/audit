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

**audit** **packages** **update** **-L** [**-j**|**-e**]

**audit** **packages** **runtimes** [**-F**] [**-j**]

**audit** **packages** **runtimes** **update** [**-N**] [**-y**] [**-m**] [**-x**] [**-j**] [_runtime_...]

**audit** **packages** **runtimes** **update** **-L** [**-j**]

**audit** **packages** **runtimes** **migrate** [**-N**] [**-y**] [**-b**] [**-P**] [**-x**] [**-j**] [_runtime_...]

**audit** **packages** **info** [**-j**] _package_

**audit** **packages** **tag** [**-d**] [**-j**] [_package_ [_tag_...]]

**audit** **repos** [_scan options_] [**-t** _tag_]... [**-f** _text_] [**-O** _owner_] [**-d**] [**-u**]

**audit** **repos** **refresh** [**-F**] [**-N**] [**-j**|**-l**]

**audit** **repos** **sync** [**-N**] [**-y**] [**-p**] [**-m**] [**-o**] [**-x**] [**-j**|**-e**] [_repo_...]

**audit** **repos** **sync** **-L** [**-j**|**-e**]

**audit** **repos** **tag** [**-d**] _repo_ _tag_...

**audit** **repos** **info** [**-j**] _repo_

**audit** **configs** [_scan options_] [**-O**]

**audit** **configs** **clean** [**-N**] [**-y**] [**-x**] [**-j**|**-e**] [_path_...]

**audit** **scripts** [_scan options_] [**-f** _text_]

**audit** **scripts** **describe** [**-a**] [**-A**] [**-j**] [_script_...]

**audit** **scripts** **info** [**-j**] _script_

**audit** **ai** [_scan options_] [**-p**]

**audit** **files** [_scan options_]

**audit** **files** **clean** [**-C** _categories_] [**-N**] [**-y**] [**-x**] [**-j**|**-e**] [_path_...]

**audit** **files** **clean** **-L** [**-j**|**-e**]

**audit** **todo** [**show**|**set**|**note**|**add**|**rm**|**explain**] ...

**audit** **analyze** [**-t**] [**-A**] [**-L** _level_] [**-j**]

**audit** **history** [_command_] [**-l** _n_] [**-j**]

**audit** **config** [**-i** [**-f**]] [**-p**]

**audit** **export** [**-d** _dir_]

# DESCRIPTION

**audit** scans a Linux workstation and saves the results in a database. Each issue and suggestion a scan finds becomes a task with a priority and a status. Saved results are shown again on later runs with their age; results older than the stale thresholds are highlighted.

Without a command, **audit** opens an interactive dashboard when stdin and stdout are terminals, and prints the summary otherwise.

# COMMANDS

**system**
:   Processes, systemd units, user and group accounts, logs (journal, dmesg, boot, auth, kern, misc), program configurations (sshd, nginx, apache, postgres, docker, cron), and:

    **storage**: filesystem space and inode use per mount against **system.storage.warn_pct** and **error_pct**, filesystems mounted read-only (the kernel does so after errors), zfs pools that are not healthy, and with **system.storage.smart** each disk's SMART health (**smartctl -H**) and btrfs device errors, both through **sudo -n**, so they need cached credentials or a NOPASSWD rule.

    **resources**: memory, I/O and CPU stall time over five minutes (PSI), available memory and swap use, OOM kills in the last week's kernel log, the 15-minute load against the core count, temperatures within 5 C of their critical trip point, thermal throttling since boot, and battery wear (peripheral batteries left out).

    **updates**: a reboot a package asked for, a newer kernel installed than the one running, security updates pending in apt's cached lists, failed **unattended-upgrades**, **apt-daily** and **apt-daily-upgrade** runs and errors in the unattended-upgrades log of the last week, and more kernels installed than **system.keep_kernels**.

    **security**: no active firewall service (ufw, firewalld, nftables), TCP ports listening beyond loopback (a warning for risky services such as rpcbind, smb, nfs, databases, redis, vnc; UDP only for those), **~/.ssh** permissions (directory, private keys, config, authorized_keys) and private keys without a passphrase (checked with **ssh-keygen -y -P ""**), world-writable PATH directories and files, and clock synchronization.

**environment**
:   Starts each configured login shell with and without a terminal, records unexpected output and which startup files are sourced, times start-up, and checks PATH, environment variables and the startup scripts (syntax and shellcheck). Once startup is done, each shell also counts what it defines: aliases, functions, parameters, exported and integer variables, arrays, PATH entries, programs on PATH, commands, completions and key bindings, and in zsh fpath entries, widgets and zinit plugins and snippets (plugins zinit loads after the first prompt are not counted). The summary shows each count, with the count without a terminal when it differs. Only names are collected, never alias bodies or variable values. Findings: **shell.alias_broken** for an alias whose first word is not a command, rolled up into one task with a **FILE:LINE** per definition; **shell.alias_shadows** (info) for aliases named like a program on PATH that run something else; **shell.fpath_missing** and **shell.fpath_duplicate**; and **shell.notty_definitions** (info) when the shell defines fewer aliases or functions without a terminal, which is how IDEs and AI agents start it. Files under **scripts.roots** are left to **audit scripts**, even when a shell sources them at startup, so no file is linted by both commands.

**packages**
:   Inventories uv, pnpm, cargo, go, gem, gh, apt, snap, flatpak and loose binaries (**bins**), and checks for broken or shadowed executables, runtime drift, stale runtime directories and misplaced installs. By default it runs against the environment of a fresh login shell (the first of **environment.shells**), so a terminal opened before a PATH change does not report stale problems; if that shell cannot start, it falls back to its own environment and reports **packages.login_env**.

    System packages come from the managers themselves and never need sudo to scan: apt lists manually installed packages plus any package with an upgrade pending, from **dpkg-query**, **apt-mark** and **apt list \-\-upgradable** over apt's cached lists; snap lists installed snaps with **snap refresh \-\-list**; flatpak lists apps and runtimes of the system and user installations with **flatpak remote-ls \-\-updates**. Their pending updates count as **registry.outdated** (never **registry.major_behind**: distribution upgrades are not releases to review), with the gap **update** when the versions do not tell how far (a new flatpak build, a snap revision). **apt.stale_lists** (notice) says when apt's lists were last refreshed more than a week ago; **apt.held** (info) lists held packages with upgrades waiting.

    Loose binaries are the regular executable files in **packages.scan_dirs** (symlinks belong to the managers that made them), with their kind (**elf** or **script**, also an automatic tag). A binary tracked with **packages bins track** carries its GitHub repo and installed release, so the registry lookup finds its latest release and **packages update** plans it like any package. **bins.untracked** (info, one task) lists compiled binaries with no recorded origin.

    The inventory (**\-\-list**) shows each package's latest release, how long ago it was published and its tags, read from the registry cache. The header says when the cache was last refreshed; a plain scan never contacts a registry. Cached data adds the checks **registry.outdated** (info, one task per manager), **registry.major_behind** (notice), **registry.deprecated**, **registry.yanked** and **registry.archived** (warnings), **registry.unmaintained** (a suggestion when the latest release is older than **packages.registry.unmaintained_after**) and **registry.error** (info, a failed lookup).

    Runtime checks: **runtime.drift** reports packages installed against another version of their runtime (a notice for uv tools and pnpm globals, info for cargo and go binaries, which are self-contained) with the **runtimes migrate** command that moves them; **runtime.outdated** reports, from the runtime cache, a runtime behind the newest release of its line (a notice when uv, pnpm or rustup owns it, info for a system or manual install) or with a newer line available (info). pnpm records no node version per global, so audit remembers the node major the globals were installed under, starting with the major it first sees.

**packages registry** [_package_...]
:   Looks installed packages up on PyPI, npm, crates.io, the Go module proxy, rubygems.org and GitHub (through **gh**), caches the latest version, release date, description, repository, homepage, license, keywords and deprecation, archive and yank status, then rescans so findings and tasks reflect it. Entries younger than **packages.registry.max_age** are reused unless **-F** is given; named packages are always looked up. Descriptions are refreshed after **packages.registry.metadata_max_age** where that costs extra requests. Go modules matched by **GONOPROXY**/**GOPRIVATE**, or with **GOPROXY** set to **direct** or **off**, are not looked up. Requests to crates.io are spaced one second apart, as its crawler policy asks.

**packages update** [_package_...]
:   Updates packages behind their latest release, one at a time, with each manager's own command: **uv tool upgrade**, **pnpm add -g** _name_**@latest**, **cargo install \-\-locked**, **go install** _package_**@latest** (each Go binary by its own package path), **gem update \-\-user-install**, **gh extension upgrade**, and for system packages one command per manager: **sudo -n apt-get install -y \-\-only-upgrade** (non-interactive, keeping changed config files) for every selected apt package, **sudo -n snap refresh**, **sudo -n flatpak update \-\-system** and **flatpak update \-\-user**; each package is still verified on its own. Held apt packages are skipped. When apt is among the managers and no package is named (or one is named **apt:**_name_), apt's lists are refreshed first with **sudo apt-get update**. Sudo is authenticated once with **sudo -v**, asking for the password on the terminal, and kept fresh until the update ends; without a terminal it needs cached credentials or a NOPASSWD rule, and otherwise the items that need it are skipped with the reason. A dry run never uses sudo. The inventory is scanned and the registry cache refreshed first, then the plan is printed and confirmed with **[y/N]**; without a terminal, **-y** is required. Without packages, every outdated package is planned except major releases (**-m** includes them), **packages.update.exclude** entries and packages installed from git or a path. Named packages are always listed, with the reason when one is skipped; a name that matches nothing is an error.

    Each update prints a status line under the progress bar. A command that exits 0 counts as updated only when a fresh inventory shows a new version; one that leaves the version unchanged, or removes the package, is a failure. Commands are stopped after **packages.update.timeout**. Failures are itemized with the command and the tail of its output, and saved with the update; the exit status is 1 when any failed. The inventory is rescanned afterwards so tasks follow, a failed attempt is noted on the package's **registry.outdated** item until its version changes, and the **packages** report shows the last update's counts. **-L** shows the last update again.

**packages runtimes**
:   Lists python, node, rust, go and ruby with the installed version, the owner (**uv**, **pnpm**, **rustup**, **system** or **manual**), the newest release of the installed line, the newest release overall (the newest LTS for node) and how many packages run on another version. uv-managed pythons and rustup toolchains are listed one per row. Releases come from **uv python list** (local), nodejs.org, go.dev and **rustup check**, cached for **packages.registry.max_age**; **-F** looks them up again. Ruby belongs to the system package manager and is not looked up. The packages scan is saved, so runtime tasks follow.

**packages runtimes update** [_runtime_...]
:   Updates runtimes with their owner's command: **uv python upgrade** _minor_ for each uv-managed python with a newer patch, **pnpm runtime set node** _version_ **-g**, and **rustup update** _toolchain_ for each rustup toolchain with a newer release (toolchains follow their channel and are not limited). By default python and node stay on their line; **-m** also installs the newest python minor (**uv python install**) and moves node to the newest LTS major. System and manual installs are listed when behind and skipped. Releases are looked up first, the plan is confirmed like **packages update**, and an update counts only when the runtime reports the new version afterwards. Installed packages keep the interpreter they were installed with; the command says when **runtimes migrate** has work to do. **-L** shows the last runtime update or migration.

**packages runtimes migrate** [_runtime_...]
:   Reinstalls packages that run on another version of their runtime: uv tools with **uv tool upgrade \-\-reinstall \-\-python** _minor_ (uv tools keep the exact interpreter they were installed with, so a new patch needs this too, and the tool is also upgraded within its constraints); every pnpm global after a node major change with **pnpm add -g \-\-force** _name_**@**_version_; user gems found only in another ruby's gem directory with **gem install \-\-user-install** _name_ **-v** _version_; and with **-b**, cargo crates and go binaries built by an older toolchain (**cargo install \-\-locked \-\-force**, **go install** _pkg_**@**_version_). **packages.update.exclude** entries and git or path installs are skipped. Results are checked against a fresh inventory. Afterwards audit lists stale runtime directories (**runtime.stale_dirs**), to be moved to the trash with **gio trash**, and uv-managed python patches that a newer patch replaced and no tool uses, to be removed with **uv python uninstall**; it asks before removing them, and with **-y** keeps them unless **-P** is given.

**packages bins**
:   Lists the loose binaries now, with kind, tracked repo, installed release and the latest release from the registry cache. Nothing is scanned or downloaded.

**packages bins track** _name_ _owner/repo_[**:**_asset-glob_] [**-s** _version_]
:   Records that _name_ comes from the GitHub releases of _owner/repo_ and looks the latest release up. The glob picks the release asset when the automatic choice is ambiguous or wrong; automatically, audit takes the asset built for this OS and architecture, preferring glibc over musl builds and tar.gz over other archives over a bare file, and ignores packages (.deb, .rpm), checksums and signatures. The installed version is **-s**, or the first version in the output of _name_ **\-\-version** (the binary is run for this). **packages bins untrack** _name_ forgets it; the file stays.

**packages bins install** _name_ [**-r** _tag_] [**-k**] [**-F**]
:   Downloads the release asset of a tracked binary with **gh release download**, checks its sha256 against GitHub's asset digest or a checksum file in the release (**checksums.txt**, **SHA256SUMS**, _asset_**.sha256**), unpacks it (tar, tar.gz, tar.bz2, zip and gzip in process; tar.xz and tar.zst through **tar**), and replaces the binary through a temporary file and a rename, after copying the old one to _data_dir_**/bins/**_name_**-**_version_. A release without a checksum is refused unless **-k** is given; a mismatch always is. **-r** installs another release, **-F** reinstalls the tracked one. **packages update** runs this for tracked binaries behind their latest release.

**packages info** _package_
:   Shows the cached details and tags of one package from the saved inventory, without scanning.

**packages tag** [_package_ [_tag_...]]
:   Without arguments, lists every tag with how many packages carry it and where the tags came from. With a package, shows its tags; with tags, adds them as user tags, or removes them with **-d**. Automatic tags (the manager, the runtime, **git**, **local** and **mine** for repositories owned by **github_user**) are derived and cannot be removed. Tags are lowercased with words joined by dashes.

    A _package_ is a name or Go module path, or _manager_**:**_name_ when the name is ambiguous.

**repos**
:   Finds the git repositories under **repos.roots** (by default the ghq root and home, up to **repos.max_depth** directories deep, skipping **repos.exclude**: plugin managers' checkouts, caches, node_modules, vendor) and inspects each with local git commands only; ahead and behind are as of the repo's last fetch, which the list shows. Remote URLs are saved without credentials. Checks: **repo.operation** (a merge, rebase, cherry-pick, revert or bisect in progress, or conflicts; warning), **repo.dirty** (uncommitted changes; notice), **repo.unpushed** (commits not on the upstream; notice), **repo.no_remote** (not backed up; notice), **repo.duplicate** (the same remote cloned twice; warning), **repo.behind**, **repo.untracked**, **repo.stash**, **repo.no_upstream**, **repo.detached**, **repo.stale_fetch** (older than **repos.stale_fetch**) and **repo.layout** (a clone under the ghq root away from its host/owner/name path), each info and grouped into one task, **repo.error**, and **links.broken** for symlinks in **repos.link_dirs** that point nowhere. From the GitHub cache: **repo.missing** (deleted or private; warning), **repo.moved** (renamed or transferred), **repo.default_branch** (renamed, e.g. master to main) and **repo.archived**.

    The list (**\-\-list**) shows each repo's slug (or path), branch, state, last commit, last fetch and tags. Your repos (owner **github_user**, detected through **gh** and remembered) are highlighted and tagged **mine**, others' **others**; automatic tags also cover the host, the main language (by file extension), **local** for repos without a remote, and from GitHub **fork**, **archived** and the repo's topics. **-t**, **-f**, **-O** (**mine**, **others** or an owner), **-d** (local work: changes, untracked files, stashes or unpushed commits) and **-u** (behind upstream) filter the list and imply **\-\-list**.

**repos refresh**
:   Runs **git fetch \-\-all \-\-prune** in every repo with a remote (**repos.concurrency** at a time, **repos.fetch_timeout** each, with **GIT_TERMINAL_PROMPT=0** and ssh in batch mode so nothing prompts), asks GitHub about the github.com repos through **gh api graphql** (50 per request; entries younger than **repos.meta_max_age** are reused unless **-F**), then saves a fresh scan. **-N** skips the fetch.

**repos sync** [_repo_...]
:   Fetches every repo (unless **-o**), refreshes stale GitHub data, and plans, per repo: **set-url** (origin's new URL after GitHub reports a rename or transfer, in the same form), **set-head** (**git remote set-head origin \-\-auto** after the default branch was renamed, and when you are on the old branch with no operation in progress, **git branch -m** _old_ _new_ and the new upstream), **fast-forward** (**git merge \-\-ff-only** for clean repos on a branch behind its upstream), **push** (with **-p**, **git push** for your own repos that are only ahead) and **move** (with **-m**, a clone under the ghq root moved to its host/owner/name path, never onto a taken one, and links in **repos.link_dirs** repointed). Nothing is merged, rebased, stashed or force-pushed: repos with local changes, an operation in progress or diverged history are listed with the reason and left alone. The plan is confirmed like **packages update** (**-y**, **-N**, **-x**); each step is checked against a rescan, results are saved (**-L** shows the last sync) and **-e** explains failures with AI.

**repos tag** _repo_ _tag_...
:   Adds tags to a repo, or removes them with **-d**. A _repo_ is its path, host/owner/name, owner/name or name when unambiguous.

**repos info** _repo_
:   Shows the saved state, GitHub data and tags of one repo.

**configs**
:   Parses the json, jsonc, yaml, toml, ini and xml files under **configs.roots** (default **~/.config**, to **configs.max_depth**, skipping **configs.exclude** and files over **configs.max_kb**) and reports **config.syntax** errors (JSON with comments and concatenated JSON values are accepted; a byte-order mark is ignored). **config.validator** runs the read-only checks programs offer: **git config \-\-global \-\-list**, **ssh -G -F ~/.ssh/config**, **systemd-analyze \-\-user verify** on user units, **i3 -C** and **sway -C**, **fish -n**, and **tmux source-file -n** when a tmux server is already running (audit never starts one). **config.permissions** reports config files others can read that hold a credential-looking value, naming the key only. Every ~/.config entry and home dotfile is matched to the program it belongs to (package inventories, apt packages with executables traced through dpkg's file lists, flatpaks, snaps, PATH executables, a program name plus a common suffix such as **.zshenv** or **.rgignore**); **config.orphaned** lists the rest, with an uninstalled apt package of the same name when apt-cache knows one. audit's own config is never an orphan. **-O** lists only the orphans and implies **\-\-list**.

**configs clean** [_path_...]
:   Moves the orphaned configs of the saved results to the trash (**gio trash**), confirmed like **packages update**. Orphans you ignored (**configs:config.orphaned:**_path_) are never planned; each must still exist and lie in home.

**scripts**
:   Inventories the scripts under **scripts.roots** (default **~/bin**, **~/.local/bin** and every **~/.config/\*/scripts**; globs expanded, symlinked roots followed, to **scripts.max_depth**): files with a shebang or a script extension, never compiled binaries or symlinks. Each is described from its header comment or Python docstring (with its usage text), or by a cached AI description. Nothing is executed: **script.shellcheck** (one batched **shellcheck** call with the **environment.shellcheck** severity and excludes; the stats say when shellcheck is missing), **script.syntax** (**zsh -n**, a Python **ast** parse plus ruff's syntax rules when installed, **node \-\-check**, **luac -p**, **ruby -c**, **fish -n**; not **perl -c**, which runs BEGIN blocks), **script.interpreter** (the shebang names a missing interpreter), **script.not_executable**, **script.crlf**, **script.shadowed** (another command of the same name comes first on PATH), **script.missing_commands** (commands a shell script appears to call that are not installed; a heuristic, ignore false matches per script) and **script.dead** (a suggestion: broken and unchanged for **scripts.stale_after**). **\-\-list** shows each script's language, issue count and description; **-f** filters by path or description.

**scripts describe** [_script_...]
:   Sends scripts without a header description (every one with **-a**, or the named ones) to the AI CLI, ten per request with each script's first 4000 bytes, and saves one-sentence descriptions by content hash, so a script is described again only after it changes; then rescans. Script contents leave the machine only with this command.

**scripts info** _script_
:   Shows one script's path, language, interpreter, description and its source, usage, and findings.

**ai**
:   Reports the AI tooling: the **claude**, **codex**, **gh copilot**, **aichat** and **ollama** CLIs (installed, version, logged in from **claude auth status** and **codex login status**, ollama's local server and models; **ai.not_logged_in**, **ai.ollama_down**), provider keys in the environment by name only, and the MCP servers configured in **~/.claude.json** (user and per project), **~/.codex/config.toml** and mcphub, with **ai.mcp_missing** when a server's command is not on PATH. Claude Code's settings are checked for hooks whose program or script is missing, or whose command leaves a quote open (**ai.hook_broken**; the command is split and expanded as sh would, and a word using a variable only set when the hook runs, such as **$CLAUDE_PROJECT_DIR**, is not checked, nor is a command starting with a shell builtin or keyword) and allow rules that let it run any command (**ai.permissions_broad**); unreadable configs are **ai.config_syntax**. AI projects are the repos under **repos.roots** with CLAUDE.md, .claude, AGENTS.md, GEMINI.md, .mcp.json, .cursor or copilot instructions, plus every directory Claude Code has sessions for, each with git branch and changes, instruction size, commands, skills, agents, MCP servers, session count and last session; **ai.instructions_large** flags instruction files over **ai.instruction_limit_kb**, **ai.stale_sessions** sessions of projects that are gone. Nothing is sent to a provider unless **-p**/**\-\-ping** is given, which sends one tiny request to each logged-in CLI (and asks ollama for its version) and implies **\-\-rescan**.

**files**
:   Measures **files.roots** (home by default) in one parallel walk that stays on each root's filesystem and counts allocated blocks, like **du**, and finds space to reclaim: **files.cache** (tool caches with their own cleaners: uv, pip, go build and modules, pnpm store, npm, yarn, cargo registry, thumbnails; apt archives, the systemd journal, disabled snap revisions, docker's reclaimable space; other large children of **~/.cache**), **files.build** (node_modules, target, .venv, venv, .tox, .gradle and .next of projects unchanged for **files.stale_after**; a tool's own install, such as an LSP under ~/.local/share or a gh extension, never counts), **files.orphaned** (children of ~/.local/share and ~/.local/state whose name matches no installed program: PATH executables, apt packages, flatpaks, snaps, desktop entries), **files.large**, **files.downloads** (files in **files.downloads** older than **files.old_downloads**), **files.trash**, **files.duplicates** (same size, then the same hash of both ends, then of the whole file, reading at most **files.hash_limit_gb**), **files.core_dumps**, **files.empty_dirs** and **files.broken_links**. Version-control internals, caches, dependency trees and files inside git working trees are never listed as large files or duplicates. **\-\-list** shows the largest directories and every candidate; nothing is deleted.

**files clean** [_path_...]
:   Plans the cleanup of the saved files results by category (**-C**, default **cache,build,cores**; **all** for every one): **cache** runs each cache's own cleaner (**uv cache clean**, **go clean -cache** and **-modcache**, **pnpm store prune**, **npm cache clean**, **pip cache purge**, **yarn cache clean**, **docker system prune**, and through **sudo -n** **apt-get clean**, **journalctl \-\-vacuum-size=500M** and **snap remove \-\-revision**) or deletes it; **build** and **cores** delete; **orphaned**, **downloads** and **duplicates** (every copy but the first in sorted order) move to the trash with **gio trash**; **trash** empties it, which cannot be undone. Paths limit the plan. Each target must still exist, lie inside **files.roots** and be neither a root nor home. Confirmed like **packages update**; sudo is asked once when system caches are planned; results are saved and **-L** shows the last cleanup.

**todo**
:   Lists open and in-progress tasks. **-H** writes **tasks.html** into the report directory: every task, closed ones included, with search (press **/**), priority cards, filters by status, command and source, grouping, sorting and expandable details; lint and parse errors are listed per file with line numbers. The filters live in the URL, so a filtered view can be bookmarked. The index links the page, and any later command that changes the database rewrites it, so it never shows stale statuses. **-o** writes and opens it. **-s** serves the same page on **127.0.0.1** (**-P** picks the port, default any free one) with buttons that set the status and a field that saves the note; the printed URL carries a random token that every request needs, requests naming another host are refused, and ctrl+c stops it. In the task editor (**-i**), **enter** shows every field and detail line of a task and **v** opens its file locations in **$VISUAL** or **$EDITOR** (vim and neovim get them all as a quickfix list). Subcommands: **show** _ID_ [**-l**] (**-l** prints only the detail lines, **FILE:LINE: message** for lint tasks, for **vim -q <(audit todo show** _ID_ **-l)**), **set** _ID_ _STATUS_ [**-N** _note_], **note** _ID_ _TEXT_, **add** _TITLE_ [**-p** _priority_] [**-C** _command_] [**-H** _hint_] [**-N** _note_], **rm** _ID_ (manual tasks only), and **explain** _ID_ [**-A**] [**-L** _level_] [**-j**], which sends the task with every detail of the saved findings behind it to the AI CLI and prints the likely cause, whether it matters, the fix and how to confirm it. **e** in the task editor does the same for the selected task.

**analyze**
:   Sends the latest saved results of every command, the open tasks and the last update's failures to the AI CLI and prints one review: problems that share a root cause across commands, the errors that matter and an order to fix them in. Nothing is scanned. With **-t**, asks instead for at most ten structured suggestions that no open task covers, and files them as tasks with source **ai** under the command they concern (or **ai**). A later **-t** run keeps the suggestions it repeats, adds new ones and resolves open AI tasks it no longer suggests; AI tasks you moved to in progress, done or won't do keep their status, and scans never resolve them. **-A** asks again instead of using the cache, **-L** sets the level, **-j** prints JSON.

**history** [_command_]
:   Lists saved runs, newest first.

**config**
:   Prints the effective configuration and the file it came from. **-i** writes the default file (**-f** overwrites), **-p** prints the path.

**export**
:   Writes the export files (see **EXPORT FILES**) into **export.dir**, or into _dir_ with **-d**, and prints the directory. Nothing is scanned. With **export.enabled**, the default, the files are already rewritten after every command that saves something, including one that then fails; this writes them on demand.

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

**-I**, **\-\-ai-provider** _name_
:   The AI CLI for this run, **claude** or **codex**, instead of **ai.provider**.

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

**-F**, **\-\-fzf**
:   Open the dashboard in fzf instead of the terminal UI (see FZF). **\-\-fzf=false** opens the terminal UI when **tui.interface** is **fzf**.

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
:   Add an AI review through the AI CLI (**ai.provider**). Cached per result set.

**-A**, **\-\-ai-refresh**
:   Like **\-\-ai**, but ask again instead of using the cache.

**-L**, **\-\-level** _level_
:   AI analysis level: **brief**, **standard** or **deep**.

**-m**, **\-\-min-severity** _severity_
:   Hide findings below **critical**, **error**, **warning**, **notice** or **info**.

**-k**, **\-\-check** _prefix_
:   Show only findings whose check id starts with _prefix_.

**-O**, **\-\-only** _parts_ (system)
:   Scan only these parts: **procs**, **services**, **users**, **logs**, **programs**, **storage**, **resources**, **updates**, **security**.

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
:   After the lookup, ask the AI CLI to tag packages that have registry data and no AI tags yet, choosing up to four tags each from **packages.tags**.

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

**-e**, **\-\-explain**
:   After an update with failures, or with **-L** for the last update, send the failed items (command, reason and the tail of their output) to the AI CLI and print why they failed and what to do. Command output can hold whatever the package manager printed; it only leaves the machine with this option. Not with **-j**. **runtimes update** and **runtimes migrate** take it too.

# PACKAGES RUNTIMES OPTIONS

**-F**, **\-\-force** (**runtimes**)
:   Look the releases up again, ignoring the cache age.

**-N**, **\-\-dry-run** / **-y**, **\-\-yes** / **-x**, **\-\-stop-on-error** / **-j**, **\-\-json**
:   As for **packages update**.

**-m**, **\-\-major** (**update**)
:   Also install the newest python minor and move node to the newest LTS major.

**-L**, **\-\-last** (**update**)
:   Show the last runtime update or migration; update nothing.

**-b**, **\-\-rebuild** (**migrate**)
:   Also rebuild cargo and go binaries built by an older toolchain.

**-P**, **\-\-prune** (**migrate**)
:   With **-y**, also remove the stale runtime directories and replaced pythons.

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
:   Browse and change tasks in a terminal UI, or in fzf when **tui.interface** is **fzf**.

**-F**, **\-\-fzf**
:   Browse and change tasks in fzf (implies **-i**; see FZF). **\-\-fzf=false** with **-i** opens the terminal UI.

# TASKS

Errors and criticals become **high** tasks, warnings **medium**, notices **low**, and suggestions **suggestion**. Info findings of one check share a single **low** task. Lint and parse errors (**shell.shellcheck**, **shell.syntax**, **script.shellcheck**, **script.syntax**, **config.syntax**) are rolled up into one task per check and priority, such as "Fix shellcheck errors in 20 shell files", whose details list every **FILE:LINE: message**. A rescan adds tasks for new findings and marks tasks **resolved** when their finding is gone; **won't do** tasks stay closed. A scan narrowed with **\-\-only** or **\-\-manager** only resolves tasks of the parts it scanned. Tasks from **analyze -t** (source **ai**) and manual tasks are never resolved by a scan.

# KEYS

The dashboard and the task editor bind each action to a list of keys under **tui.keys**; any action takes several keys, **[]** unbinds it, and setting one action keeps the defaults of the others. A key may be bound to two actions only when they never share a screen. **ctrl+c** always quits. The help line at the bottom shows the first key of each action. The actions, their default keys and screens:

    quit                q                     all screens
    back                esc backspace h left  all screens
    tasks               t                     dashboard, report, task, explain
    up, down            k up, j down          all screens
    page_up, page_down  pgup b, pgdown f space   report, tasks, task, explain
    half_page_up        ctrl+u u              same
    half_page_down      ctrl+d                same
    top, bottom         home g, end G         same
    open                enter l right         dashboard (report), tasks (details)
    rescan              r                     dashboard, report
    reask               r                     explain (ask the AI again)
    explain             e                     tasks, task
    editor              v                     tasks, task (locations in $EDITOR)
    status_open         o                     tasks
    status_in_progress  i                     tasks
    status_done         d                     tasks
    status_wont_do      w                     tasks
    note                n                     tasks
    search              /                     tasks
    toggle_closed       a                     tasks
    cycle_command       c                     tasks

The note and find fields always use **enter** and **esc**. An unknown action, a blank key, **ctrl+c** or two actions sharing a key on one screen is a config error.

# FZF

With **tui.interface: fzf**, or **-F**, the dashboard and the task editor are fzf lists (fzf 0.51 or later on PATH). The command list previews each command's saved report; the task list previews the task, and typing filters it as in any fzf list. Keys call back into **audit**, then reload the list, so changes show at once. Your **FZF_DEFAULT_OPTS** still apply; audit's own options come after them, so its keys and preview window win.

Typing goes to fzf's query, so actions are bound to alt- keys under **tui.fzf_keys**, in fzf's key names (**alt-d**, **ctrl-x**, **enter**). Only these actions exist in fzf, with the same multi-key and conflict rules as **tui.keys**; a plain printable character, **esc**, **ctrl-c**, **ctrl-g** and **ctrl-q** cannot be bound. Scrolling, searching and leaving are fzf's own keys; **esc** in the task list returns to the command list.

    open                enter    command list: report in $PAGER; tasks: details in $PAGER
    rescan              alt-r    command list
    tasks               alt-t    command list: open the task list
    explain             alt-e    tasks: AI explanation in $PAGER
    editor              alt-v    tasks: file locations in $EDITOR
    status_open         alt-o    tasks
    status_in_progress  alt-i    tasks
    status_done         alt-d    tasks
    status_wont_do      alt-w    tasks
    note                alt-n    tasks: prompts for the note (empty keeps it, - clears it)
    toggle_closed       alt-a    tasks
    cycle_command       alt-c    tasks

The prompt shows the task list's command filter and **+closed**. Without **$PAGER**, pages open in **less -R -+F -+X**, so a short page does not flash past when **$LESS** has **-F**. The terminal UI's report screen, explanation retries and search field have no fzf counterpart.

# AI

AI features run a local CLI: **claude -p** with tools disabled and no session persistence, or **codex exec** in its read-only sandbox, ephemeral, from an empty temporary directory and told to answer from the prompt only (codex is an agent with a shell; the sandbox keeps it from writing, not from reading). Prompts carry findings, statistics, task titles and, with **-e**, failed command output; never raw logs, shell traces, timestamps or the export files. Answers are cached in the database by a hash of the provider, model and prompt, so asking again about unchanged results is free. Claude reports a cost per answer; codex does not. The features: **-a** on scans (one review per run), **packages registry -a** (tags), **analyze** (cross-command review or suggested tasks), **todo explain** and the task editor's **e** key, and **-e** on updates and migrations.

# EXPORT FILES

The export directory (**export.dir**, by default **~/.local/share/audit/export/**) holds JSON snapshots for other programs, such as a desktop dashboard, to read without opening the database. Each file is written to a temporary file and renamed into place, so a reader never sees a partial file. Every file starts with **schema_version** (currently 1), **generated_at** (UTC) and **host**. Within one schema version fields are only added; a renamed or removed field bumps it.

**summary.json**
:   One row per scanning command under **commands**: **command**, **file** (its own export file, absent when it never ran), **freshness** (**fresh**, **stale**, **old** or **none**, graded at **generated_at**), **stale_after_seconds** and **old_after_seconds** to regrade it later, **last_run** (**id**, **scope**, **started_at**, **finished_at**, **findings** counted by severity, **ignored**, **errors**) and **open_tasks** by priority. Then **open_tasks** totals and **last_update** (**id**, **finished_at**, **updated**, **failed**, **skipped**) once a package update has run.

_command_**.json**
:   The command's latest full run under **run**, with its findings and errors but without the scanner's raw data, which can hold environment values. Each summary stat has **group**, **name** and **value**, plus **note** (what qualifies the value) and **extra** (shown only in the expanded view) when set. **repos.json** adds the annotated repo list as **repos**; **files.json** adds the sizes and cleanup candidates as **files**. **packages.json** adds the annotated inventory as **packages**, as **audit packages \-\-json** prints it, and the runtimes as **runtimes**, as **audit packages runtimes \-\-json** prints them.

**tasks.json**
:   Every task under **tasks**, closed ones included.

**updates.json**
:   The saved package updates, runtime updates and migrations under **updates**, newest first, each item with its **kind** (**package**, **runtime** or **migration**), command, status and reason but not the command's output.

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
    tui:
      interface: tui           # tui or fzf; -F/--fzf per run
      keys: {quit: [q], status_done: [d], ...}   # every action; see KEYS
      fzf_keys: {open: [enter], status_done: [alt-d], ...}   # see FZF
    ai:
      provider: claude         # claude or codex; -I overrides it per run
      claude: {command: claude, model: claude-sonnet-5-5}
      codex: {command: codex, model: ""}   # empty model: codex's default
      analysis_level: standard
      timeout: 5m
      max_details: 10          # detail lines per finding in the prompt
      instruction_limit_kb: 40 # audit ai: CLAUDE.md/AGENTS.md size reported as large
    system:
      journal: "-p 4 -b -n 500 --no-pager"
      logs: [boot, dmesg, journal]
      log_max_lines: 5000
      log_patterns: 10
      programs: [sshd, nginx, postgres, apache, docker, cron]
      procs: {top: 10, high_cpu: 80, high_mem: 25, high_threads: 1000}
      services: {user_units: true, high_restarts: 5, unit_file_perms: true}
      storage: {warn_pct: 90, error_pct: 97, smart: false}
      keep_kernels: 3
    packages:
      env: login               # login (fresh login shell) or process
      managers: [uv, pnpm, cargo, go, gem, gh, apt, snap, flatpak, bins]
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
    export:
      enabled: true            # rewrite the export files after commands that save
      dir: ""                  # empty: <data_dir>/export; ~ is expanded
    scripts:
      roots: [~/bin, ~/.local/bin, "~/.config/*/scripts"]
      max_depth: 2
      exclude: [.git, node_modules, __pycache__, venv, .venv]
      max_kb: 512
      stale_after: 17520h
    configs:
      roots: [~/.config]
      max_depth: 4
      exclude: [.git, node_modules, plugins, plugged, pack, site-packages, __pycache__]
      max_kb: 1024
    files:
      roots: ["~"]
      exclude: []
      downloads: ~/Downloads
      large_mb: 1024
      dup_min_mb: 50
      cache_min_mb: 200
      build_min_mb: 50
      orphan_min_mb: 50
      downloads_min_mb: 100
      stale_after: 2160h
      old_downloads: 4320h
      hash_limit_gb: 10
      top: 20
    repos:
      roots: [~/ghq, "~"]
      max_depth: 4
      exclude: [~/.zinit, ~/.cache, ~/.local/share, ~/.local/state, ~/.cargo, ~/.rustup,
                ~/go/pkg, ~/.npm, ~/snap, ~/.vscode, '**/node_modules', '**/vendor']
      link_dirs: [~/git]
      ghq_root: ""             # empty: git config ghq.root, else ~/ghq
      concurrency: 8
      fetch_timeout: 2m
      stale_fetch: 720h
      meta_max_age: 168h

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
:   Runs, findings, tasks, the package registry and runtime caches, tags, saved updates and migrations, and the AI response cache. A database from an older audit is upgraded in place; one from a newer audit is refused.

**~/.local/share/audit/reports/**
:   HTML reports and **index.html**.

**~/.local/share/audit/bins/**
:   The previous file of each binary **packages bins install** replaced.

**~/.local/share/audit/export/**
:   JSON snapshots for other programs; see **EXPORT FILES**.

# ENVIRONMENT

**XDG_CONFIG_HOME**, **XDG_DATA_HOME**
:   Base directories for the config file and the data directory.

**NO_COLOR**
:   Disables colors.

**AUDIT_***
:   Overrides config keys.

# SEE ALSO

**claude**(1), **codex**(1), **journalctl**(1), **shellcheck**(1)
