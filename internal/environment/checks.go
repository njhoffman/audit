package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

// Command is the audit command name environment findings are filed under.
const Command = "environment"

// State is what the environment checks inspect. Env holds the variables
// being audited (a fresh login shell's when one could be captured) with
// commands run through its PATH.
type State struct {
	Ctx         context.Context
	Env         *exec.Env
	Captures    []Capture
	Scripts     []Script
	Syntax      []SyntaxResult
	Shellcheck  *ShellcheckResult // nil when shellcheck was not run
	Traced      map[string]bool   // shells whose sourced files are known
	SlowStartup time.Duration

	defs map[string][]definition // see definitions
}

// SyntaxResult is one `<shell> -n` parse of a script.
type SyntaxResult struct {
	Path   string   `json:"path"`
	Shell  string   `json:"shell"`
	Errors []string `json:"errors,omitempty"`
	// Loaded is false for files no shell sources at startup.
	Loaded bool `json:"loaded"`
	// Skipped is set when the shell could not be started.
	Skipped bool `json:"skipped,omitempty"`
}

// ShellcheckResult holds shellcheck's comments per file.
type ShellcheckResult struct {
	Installed bool                `json:"installed"`
	Comments  map[string][]string `json:"comments,omitempty"`
	Levels    map[string]string   `json:"levels,omitempty"` // worst level per file
}

// Checks lists the environment checks in run order.
var Checks = []finding.Check[*State]{
	{ID: "path.duplicate", Fn: pathDuplicate},
	{ID: "path.relative", Fn: pathRelative},
	{ID: "path.missing", Fn: pathMissing},
	{ID: "env.vars", Fn: envVars},
	{ID: "env.missing_path", Fn: envMissingPath},
	{ID: "python.break_system_packages", Fn: breakSystemPackages},
	{ID: "python.user_site", Fn: userSite},
	{ID: "shell.startup_exit", Fn: startupExit},
	{ID: "shell.startup_output", Fn: startupOutput},
	{ID: "shell.startup_time", Fn: startupTime},
	{ID: "shell.syntax", Fn: syntax},
	{ID: "shell.shellcheck", Fn: shellcheck},
	{ID: "shell.missing_source", Fn: missingSource},
	{ID: "shell.redefined", Fn: redefined},
	{ID: "shell.unloaded", Fn: unloaded},
	{ID: "shell.alias_broken", Fn: aliasBroken},
	{ID: "shell.alias_shadows", Fn: aliasShadows},
	{ID: "shell.fpath_missing", Fn: fpathMissing},
	{ID: "shell.fpath_duplicate", Fn: fpathDuplicate},
	{ID: "shell.notty_definitions", Fn: nottyDefinitions},
}

// Analyze runs every environment check.
func Analyze(s *State) []finding.Finding {
	return finding.RunChecks(Command, s, Checks)
}

func pathEntries(env *exec.Env) []string {
	var out []string
	for _, p := range env.Path() {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pathDuplicate(s *State) []finding.Finding {
	positions := map[string][]string{}
	var order []string
	for i, e := range pathEntries(s.Env) {
		n := filepath.Clean(e)
		if _, ok := positions[n]; !ok {
			order = append(order, n)
		}
		positions[n] = append(positions[n], fmt.Sprint(i))
	}
	var out []finding.Finding
	for _, e := range order {
		idx := positions[e]
		if len(idx) < 2 {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: e,
			Message: fmt.Sprintf("%s appears %d times in PATH (positions %s)", e, len(idx), strings.Join(idx, ", ")),
			Hint: "Something prepends it without a duplicate guard; find it with " +
				"`grep -rn` over shell rc files for the directory name.",
		})
	}
	return out
}

func pathRelative(s *State) []finding.Finding {
	var out []finding.Finding
	const hint = "Relative entries resolve against the current directory, so any " +
		"directory you cd into can inject commands."
	for _, e := range s.Env.Path() {
		switch {
		case e == "":
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: "(empty)",
				Message: "empty PATH entry (an extra ':'), which means the current directory", Hint: hint,
			})
		case !filepath.IsAbs(e):
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: e, Message: fmt.Sprintf("relative PATH entry %q", e), Hint: hint,
			})
		}
	}
	return dedupeSubjects(out)
}

func pathMissing(s *State) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	for _, e := range pathEntries(s.Env) {
		if seen[e] || !filepath.IsAbs(e) {
			continue
		}
		seen[e] = true
		if !isDir(e) {
			out = append(out, finding.Finding{Severity: finding.Info, Subject: e, Message: "PATH entry does not exist: " + e})
		}
	}
	return out
}

func dedupeSubjects(fs []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		if !seen[f.Subject] {
			seen[f.Subject] = true
			out = append(out, f)
		}
	}
	return out
}

func envVars(s *State) []finding.Finding {
	var out []finding.Finding
	if v := s.Env.Get("NODE_PATH"); v != "" {
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: "NODE_PATH", Message: "NODE_PATH is set",
			Details: strings.Split(v, ":"),
			Hint:    "It makes global modules importable from every project, hiding missing dependencies. Unset it.",
		})
	}
	if v := s.Env.Get("PYTHONPATH"); v != "" {
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: "PYTHONPATH", Message: "PYTHONPATH is set globally",
			Details: strings.Split(v, ":"),
			Hint:    "It leaks into every interpreter, including uv tool envs.",
		})
	}
	if s.Env.Which("pnpm") != "" && s.Env.Get("PNPM_HOME") == "" {
		out = append(out, finding.Finding{
			Severity: finding.Error, Subject: "PNPM_HOME", Message: "pnpm is installed but PNPM_HOME is unset",
			Hint: "pnpm add -g refuses to run without it.",
		})
	}
	return out
}

var (
	pathVarSingle = regexp.MustCompile(`(HOME|DIR|ROOT|CONFIG|PREFIX)$`)
	pathVarLazy   = regexp.MustCompile(`(FILE|CACHE)$`)
	pathVarList   = regexp.MustCompile(`(PATH|DIRS)$`)
	skipVars      = map[string]bool{"PATH": true, "PWD": true, "OLDPWD": true, "_": true}
)

// envMissingPath reports variables that name a directory or file by
// convention (*HOME, *DIR, *PATH, ...) but point at nothing.
func envMissingPath(s *State) []finding.Finding {
	names := make([]string, 0, len(s.Env.Vars))
	for k := range s.Env.Vars {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []finding.Finding
	for _, k := range names {
		v := s.Env.Vars[k]
		if skipVars[k] || strings.HasPrefix(k, "AUDIT_") || v == "" {
			continue
		}
		switch {
		case pathVarList.MatchString(k):
			var missing []string
			for _, e := range strings.Split(v, ":") {
				if filepath.IsAbs(e) && !exists(e) {
					missing = append(missing, e)
				}
			}
			if len(missing) > 0 {
				out = append(out, finding.Finding{
					Severity: finding.Info, Subject: k, Details: missing,
					Message: fmt.Sprintf("%s has %d %s", k, len(missing), plural(len(missing), "entry that does not exist", "entries that do not exist")),
					Hint:    "Drop stale entries where the variable is set.",
				})
			}
		case strings.Contains(v, ":") || !filepath.IsAbs(v):
		case exists(v):
		case pathVarSingle.MatchString(k):
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: k,
				Message: fmt.Sprintf("%s points at %s, which does not exist", k, v),
				Hint:    "Tools reading it fail or recreate it; fix or remove the export.",
			})
		case pathVarLazy.MatchString(k):
			out = append(out, finding.Finding{
				Severity: finding.Notice, Subject: k,
				Message: fmt.Sprintf("%s points at %s, which does not exist yet", k, v),
				Hint:    "Usually created on first use; check the path if the tool never runs.",
			})
		}
	}
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// PipConfigFiles are where pip reads configuration, in increasing priority
// order of user concern.
func pipConfigFiles(env *exec.Env) []string {
	return []string{
		filepath.Join(env.XDG("XDG_CONFIG_HOME"), "pip", "pip.conf"),
		filepath.Join(env.Home, ".pip", "pip.conf"),
		"/etc/pip.conf",
	}
}

func breakSystemPackages(s *State) []finding.Finding {
	const hint = "It disables PEP 668 for every pip call, so `pip install` can overwrite " +
		"apt-owned packages. Use uv tool / a venv instead."
	var out []finding.Finding
	if truthy(s.Env.Get("PIP_BREAK_SYSTEM_PACKAGES")) {
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: "env", Message: "PIP_BREAK_SYSTEM_PACKAGES is set", Hint: hint,
		})
	}
	for _, path := range pipConfigFiles(s.Env) {
		for _, section := range iniSectionsWith(path, "break-system-packages") {
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: path, Hint: hint,
				Message: fmt.Sprintf("break-system-packages enabled in %s [%s]", path, section),
			})
		}
	}
	return out
}

// iniSectionsWith returns the sections of an ini file where key is truthy.
func iniSectionsWith(path, key string) []string {
	f, err := os.Open(path) // #nosec G304 -- fixed pip config locations
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				k, v, ok = strings.Cut(line, ":")
			}
			if ok && section != "" && strings.EqualFold(strings.TrimSpace(k), key) && truthy(v) {
				out = append(out, section)
			}
		}
	}
	return out
}

func userSite(s *State) []finding.Finding {
	r := s.Env.Run(s.Ctx, "python3", []string{"-c", "import site; print(site.getusersitepackages())"},
		exec.Options{Timeout: 10 * time.Second})
	site := strings.TrimSpace(r.Stdout)
	if !r.OK() || !isDir(site) {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(site, "*.dist-info"))
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		name, _, _ := strings.Cut(filepath.Base(m), "-")
		names = append(names, name)
	}
	sort.Strings(names)
	var out []finding.Finding
	for _, name := range names {
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: name,
			Message: fmt.Sprintf("%s is pip --user installed in %s", name, site),
			Hint: "Fine if intended (e.g. it needs system libraries); otherwise move it to " +
				"`uv tool install` or apt. Silence with ignore: [\"" + Command + ":python.user_site:" + name + "\"].",
		})
	}
	return out
}

func startupExit(s *State) []finding.Finding {
	var out []finding.Finding
	for _, c := range s.Captures {
		subject := c.Shell + "/" + c.Mode
		switch {
		case c.Code == exec.ExitNotFound && c.Path == "":
		case c.TimedOut:
			out = append(out, finding.Finding{
				Severity: finding.Error, Subject: subject,
				Message: fmt.Sprintf("%s login startup (%s) did not finish within %s", c.Shell, c.Mode, c.Duration.Round(time.Second)),
				Hint:    "Something in the startup files waits for input or the network; run `" + c.Shell + " -lixc exit` to trace it.",
				Details: c.Output,
			})
		case c.Err != "":
			out = append(out, finding.Finding{
				Severity: finding.Error, Subject: subject,
				Message: fmt.Sprintf("could not start %s (%s): %s", c.Shell, c.Mode, c.Err),
			})
		case c.Code != 0:
			out = append(out, finding.Finding{
				Severity: finding.Error, Subject: subject, Details: c.Output,
				Message: fmt.Sprintf("%s login startup (%s) exited with status %d", c.Shell, c.Mode, c.Code),
				Hint:    "The last command of a startup file failed or called exit; run `" + c.Shell + " -lixc exit` to trace it.",
			})
		}
	}
	return out
}

var errorish = regexp.MustCompile(`(?i)\berror\b|not found|no such file|permission denied|parse error|bad substitution|unknown|invalid|failed`)

// startupOutput reports what a login shell prints before the first prompt.
// Under a terminal that breaks instant prompts and garbles the screen; without
// one it is how tools such as IDEs see the shell.
func startupOutput(s *State) []finding.Finding {
	var out []finding.Finding
	for _, c := range s.Captures {
		if len(c.Output) == 0 || c.TimedOut {
			continue
		}
		sev := finding.Warning
		for _, l := range c.Output {
			if errorish.MatchString(l) {
				sev = finding.Error
				break
			}
		}
		f := finding.Finding{
			Severity: sev, Subject: c.Shell, Details: c.Output,
			Message: fmt.Sprintf("%s login startup prints %d unexpected line%s: %s",
				c.Shell, len(c.Output), plural(len(c.Output), "", "s"), c.Output[0]),
		}
		if c.Mode == ModeTTY {
			f.Hint = "Move output into a first-prompt hook (in ~/.shell: _shell_first_prompt in zsh/zshrc.zsh), " +
				"or add a pattern to environment.known_output if it is intended."
		} else {
			f.Check = "shell.startup_notty"
			f.Message = fmt.Sprintf("%s login startup without a terminal prints %d unexpected line%s: %s",
				c.Shell, len(c.Output), plural(len(c.Output), "", "s"), c.Output[0])
			f.Hint = "IDEs and other tools start `" + c.Shell + " -lic` with no terminal; guard " +
				"terminal-only code with `[[ -t 1 ]]` (or check $TTY is non-empty before redirecting to it)."
		}
		out = append(out, f)
	}
	return out
}

func startupTime(s *State) []finding.Finding {
	if s.SlowStartup <= 0 {
		return nil
	}
	var out []finding.Finding
	for _, c := range s.Captures {
		if c.Mode != ModeTTY || c.TimedOut || c.Path == "" || c.Duration <= s.SlowStartup {
			continue
		}
		sev := finding.Notice
		if c.Duration > 3*s.SlowStartup {
			sev = finding.Warning
		}
		out = append(out, finding.Finding{
			Severity: sev, Subject: c.Shell,
			Message: fmt.Sprintf("%s login startup took %.2fs (threshold %.2fs)",
				c.Shell, c.Duration.Seconds(), s.SlowStartup.Seconds()),
			Hint: "Profile it with `zmodload zsh/zprof` (zsh) or `PS4='+$EPOCHREALTIME ' bash -lixc exit` (bash); " +
				"defer slow init behind lazy shims.",
		})
	}
	return out
}

func syntax(s *State) []finding.Finding {
	var out []finding.Finding
	for _, r := range s.Syntax {
		if len(r.Errors) == 0 {
			continue
		}
		f := finding.Finding{
			Severity: finding.Error, Subject: r.Path + " (" + r.Shell + ")", Details: r.Errors,
			Message: fmt.Sprintf("%s does not parse under %s: %s", r.Path, r.Shell, r.Errors[0]),
			Hint:    "Cross-shell files must parse under both bash and zsh; move shell-specific syntax to that shell's tree.",
		}
		if !r.Loaded {
			f.Severity = finding.Warning
			f.Message = fmt.Sprintf("%s (not sourced at startup) does not parse under %s: %s", r.Path, r.Shell, r.Errors[0])
			f.Hint = "Nothing sources it during startup. If something loads it later (zinit turbo, a plugin) fix it; " +
				"otherwise delete it or give it a non-shell extension."
			f.Group = &finding.Group{ID: "syntax_unsourced", Rollup: true, Title: "Fix or delete {n} unsourced shell file{s} with parse errors",
				Hint: f.Hint}
		} else {
			f.Group = &finding.Group{ID: "syntax", Rollup: true, Title: "Fix parse errors in {n} startup file{s} (bash or zsh)",
				Hint: f.Hint}
		}
		out = append(out, f)
	}
	return out
}

func shellcheck(s *State) []finding.Finding {
	if s.Shellcheck == nil {
		return nil
	}
	if !s.Shellcheck.Installed {
		return []finding.Finding{{
			Severity: finding.Info, Kind: finding.Suggestion, Subject: "shellcheck",
			Message: "shellcheck is not installed, so sh/bash startup files are only syntax-checked",
			Hint:    "Install it (apt install shellcheck) to lint for quoting and portability bugs.",
		}}
	}
	files := make([]string, 0, len(s.Shellcheck.Comments))
	for f := range s.Shellcheck.Comments {
		files = append(files, f)
	}
	sort.Strings(files)
	var out []finding.Finding
	for _, f := range files {
		comments := s.Shellcheck.Comments[f]
		sev := finding.Warning
		if s.Shellcheck.Levels[f] == "error" {
			sev = finding.Error
		}
		out = append(out, finding.Finding{
			Severity: sev, Subject: f, Details: comments,
			Message: fmt.Sprintf("shellcheck reports %d problem%s in %s", len(comments), plural(len(comments), "", "s"), f),
			Hint:    "Run `shellcheck " + f + "` for context and fixes.",
			Group: &finding.Group{ID: "shellcheck", Rollup: true, Title: "Fix shellcheck {level} in {n} shell file{s}",
				Hint: "Run shellcheck FILE for context and fixes."},
		})
	}
	return out
}

var (
	sourceLine = regexp.MustCompile(`^\s*(?:source|\.)\s+("[^"]+"|'[^']+'|[^\s;&|]+)(.*)$`)
	varRef     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	fileTest   = regexp.MustCompile(`-[efrs]\s`)
)

// missingSource reports unguarded `source FILE` / `. FILE` lines whose file
// does not exist. Paths that cannot be resolved statically are skipped.
func missingSource(s *State) []finding.Finding {
	var out []finding.Finding
	for _, sc := range s.Scripts {
		lines := readLines(sc.Path)
		for i, line := range lines {
			m := sourceLine.FindStringSubmatch(line)
			if m == nil || strings.Contains(m[2], "2>/dev/null") || strings.Contains(m[2], "||") {
				continue
			}
			raw := strings.Trim(m[1], `"'`)
			target, ok := resolveStatic(raw, s.Env)
			if !ok || exists(target) || guarded(lines, i, raw) {
				continue
			}
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: fmt.Sprintf("%s:%d", sc.Path, i+1),
				Message: fmt.Sprintf("%s:%d sources %s, which does not exist", sc.Path, i+1, target),
				Hint:    "Guard it with `[ -f FILE ] && . FILE` or remove the line.",
			})
		}
	}
	return out
}

// resolveStatic expands ~ and $VAR / ${VAR} / ${VAR:-default} in a source
// argument. It fails for anything needing the shell (command substitution,
// globs, zsh modifiers, unset variables) or that stays relative.
func resolveStatic(raw string, env *exec.Env) (string, bool) {
	if strings.ContainsAny(raw, "`*?[(") {
		return "", false
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		raw = env.Home + raw[1:]
	}
	expanded, ok := expandVars(raw, env, 0)
	if !ok || strings.ContainsAny(expanded, "${}") || !filepath.IsAbs(expanded) {
		return "", false
	}
	return expanded, true
}

// expandVars substitutes variable references, expanding ${VAR:-default}
// defaults in turn. Unset or empty variables without a default fail: the
// resulting path would not be the one the shell sources.
func expandVars(s string, env *exec.Env, depth int) (string, bool) {
	if depth > 3 {
		return "", false
	}
	ok := true
	out := varRef.ReplaceAllStringFunc(s, func(ref string) string {
		m := varRef.FindStringSubmatch(ref)
		name := m[1] + m[3]
		v, set := env.Lookup(name)
		if name == "HOME" && !set {
			v, set = env.Home, true
		}
		if set && v != "" {
			return v
		}
		if m[1] != "" && strings.Contains(ref, "-") {
			d, dok := expandVars(m[2], env, depth+1)
			ok = ok && dok
			return d
		}
		ok = false
		return ""
	})
	return out, ok
}

// guarded reports whether a file test on raw appears in the few lines before
// line i (an `if [ -f X ]; then` block).
func guarded(lines []string, i int, raw string) bool {
	for j := i - 1; j >= 0 && j >= i-3; j-- {
		if strings.Contains(lines[j], raw) && fileTest.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

func readLines(path string) []string {
	data, err := os.ReadFile(path) // #nosec G304 -- configured startup files
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

var (
	aliasDef = regexp.MustCompile(`^\s*alias\s+(?:-[gs]\s+)*([^=\s'"]+)=`)
	funcDef1 = regexp.MustCompile(`^\s*function\s+([^\s(){}]+)`)
	funcDef2 = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_:.+-]*)\s*\(\)`)
)

type definition struct {
	path   string
	line   int
	shells []string
}

// definitions finds the alias and function definitions in the startup
// scripts, keyed by alias:NAME and function:NAME. Checks run one at a time,
// so it is computed once on first use.
func (s *State) definitions() map[string][]definition {
	if s.defs != nil {
		return s.defs
	}
	defs := map[string][]definition{}
	add := func(key string, d definition) { defs[key] = append(defs[key], d) }
	for _, sc := range s.Scripts {
		if sc.Executable {
			continue // its definitions stay in its own process
		}
		shells := sc.LoadShells(s.Traced)
		if sc.Function != "" {
			add("function:"+sc.Function, definition{sc.Path, 1, shells})
		}
		for i, line := range readLines(sc.Path) {
			d := definition{sc.Path, i + 1, shells}
			if m := aliasDef.FindStringSubmatch(line); m != nil {
				add("alias:"+m[1], d)
			} else if m := funcDef1.FindStringSubmatch(line); m != nil {
				add("function:"+m[1], d)
			} else if m := funcDef2.FindStringSubmatch(line); m != nil {
				add("function:"+m[1], d)
			}
		}
	}
	s.defs = defs
	return defs
}

// redefined reports aliases and functions defined in more than one file
// loaded by the same shell; only the last one loaded takes effect.
func redefined(s *State) []finding.Finding {
	defs := s.definitions()
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []finding.Finding
	for _, k := range keys {
		ds := defs[k]
		if !conflicting(ds) {
			continue
		}
		details := make([]string, 0, len(ds))
		for _, d := range ds {
			details = append(details, fmt.Sprintf("%s:%d", d.path, d.line))
		}
		kind, name, _ := strings.Cut(k, ":")
		out = append(out, finding.Finding{
			Severity: finding.Info, Kind: finding.Suggestion, Subject: k, Details: details,
			Message: fmt.Sprintf("%s `%s` is defined in %d files; the last one loaded wins", kind, name, distinctFiles(ds)),
			Hint:    "Keep one definition so later edits are not silently overridden.",
		})
	}
	return out
}

// conflicting reports whether definitions in two different files are loaded
// by a common shell. Repeats within one file are usually if/else branches.
func conflicting(ds []definition) bool {
	for i := range ds {
		for j := i + 1; j < len(ds); j++ {
			if ds[i].path != ds[j].path && shareShell(ds[i].shells, ds[j].shells) {
				return true
			}
		}
	}
	return false
}

func shareShell(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// unloaded reports startup files and startup-tree scripts that no traced
// shell sources. Startup files get one finding each (bash, for example,
// skips ~/.bash_login when ~/.bash_profile exists); tree scripts are grouped
// by directory.
func unloaded(s *State) []finding.Finding {
	if len(s.Traced) == 0 {
		return nil
	}
	byDir := map[string][]string{}
	var out []finding.Finding
	for _, sc := range s.Scripts {
		if len(sc.LoadShells(s.Traced)) > 0 {
			continue
		}
		if sc.Startup {
			out = append(out, finding.Finding{
				Severity: finding.Notice, Subject: sc.Path,
				Message: fmt.Sprintf("%s exists but no login shell reads it", sc.Path),
				Hint: "bash reads only the first of ~/.bash_profile, ~/.bash_login and ~/.profile; " +
					"zsh reads ~/.z* files only. Merge it into a file that is read, or delete it.",
			})
			continue
		}
		dir := filepath.Dir(sc.Path)
		byDir[dir] = append(byDir[dir], filepath.Base(sc.Path))
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		names := byDir[d]
		out = append(out, finding.Finding{
			Severity: finding.Info, Kind: finding.Suggestion, Subject: d, Details: names,
			Message: fmt.Sprintf("%d script%s in %s %s not sourced during startup", len(names),
				plural(len(names), "", "s"), d, plural(len(names), "is", "are")),
			Hint: "Deferred loaders (zinit turbo, plugin managers) run after the first prompt and are not traced; " +
				"anything else here is unused or a stray copy.",
		})
	}
	return out
}

func distinctFiles(ds []definition) int {
	seen := map[string]bool{}
	for _, d := range ds {
		seen[d.path] = true
	}
	return len(seen)
}
