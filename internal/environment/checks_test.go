package environment

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/todo"
)

func TestPathDuplicateRelativeMissing(t *testing.T) {
	env, _, home := testEnv(t)
	a := filepath.Join(home, "a")
	mkdir(t, a)
	setPath(env, a, "rel/bin", a+"/", filepath.Join(home, "gone"))
	fs := analyze(&State{Env: env})

	dup := byCheck(fs, "path.duplicate")
	if len(dup) != 1 || dup[0].Subject != a || !strings.Contains(dup[0].Message, "2 times") {
		t.Fatalf("path.duplicate = %+v", dup)
	}
	if got := subjects(byCheck(fs, "path.relative")); !reflect.DeepEqual(got, []string{"rel/bin"}) {
		t.Errorf("path.relative = %v", got)
	}
	if got := subjects(byCheck(fs, "path.missing")); !reflect.DeepEqual(got, []string{filepath.Join(home, "gone")}) {
		t.Errorf("path.missing = %v", got)
	}
}

func TestPathEmptyEntryIsRelative(t *testing.T) {
	env, _, home := testEnv(t)
	mkdir(t, filepath.Join(home, "bin"))
	env.Vars["PATH"] = filepath.Join(home, "bin") + "::" + filepath.Join(home, "bin") + ":"
	fs := analyze(&State{Env: env})
	rel := byCheck(fs, "path.relative")
	if len(rel) != 1 || rel[0].Subject != "(empty)" {
		t.Errorf("empty entries should collapse into one finding: %+v", rel)
	}
	if len(byCheck(fs, "path.duplicate")) != 1 {
		t.Error("empty entries must not hide the real duplicate")
	}
}

func TestEnvVars(t *testing.T) {
	env, _, home := testEnv(t)
	makeExe(t, filepath.Join(home, "bin", "pnpm"), "")
	env.Vars["NODE_PATH"] = "/a:/b"
	env.Vars["PYTHONPATH"] = "/p"
	got := map[string]finding.Severity{}
	for _, f := range byCheck(analyze(&State{Env: env}), "env.vars") {
		got[f.Subject] = f.Severity
	}
	want := map[string]finding.Severity{"NODE_PATH": finding.Warning, "PYTHONPATH": finding.Warning, "PNPM_HOME": finding.Error}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env.vars = %v", got)
	}
	env.Vars["PNPM_HOME"] = "/x"
	delete(env.Vars, "NODE_PATH")
	delete(env.Vars, "PYTHONPATH")
	if fs := byCheck(analyze(&State{Env: env}), "env.vars"); len(fs) != 0 {
		t.Errorf("expected clean env, got %+v", fs)
	}
}

func TestEnvVarsNoPnpm(t *testing.T) {
	env, _, _ := testEnv(t)
	if fs := byCheck(analyze(&State{Env: env}), "env.vars"); len(fs) != 0 {
		t.Errorf("PNPM_HOME should only matter when pnpm is installed: %+v", fs)
	}
}

func TestEnvMissingPath(t *testing.T) {
	env, _, home := testEnv(t)
	mkdir(t, filepath.Join(home, "real"))
	for k, v := range map[string]string{
		"GOOD_HOME":      filepath.Join(home, "real"),
		"BAD_HOME":       filepath.Join(home, "nope"),
		"HISTFILE":       filepath.Join(home, "hist"),
		"XDG_DATA_DIRS":  filepath.Join(home, "real") + ":" + filepath.Join(home, "gone1") + ":" + filepath.Join(home, "gone2"),
		"RELATIVE_DIR":   "some/dir",
		"EDITOR":         "/no/such/editor",
		"PWD":            "/nowhere",
		"MANPATH":        "",
		"AUDIT_ENV_HOME": "/nope",
	} {
		env.Vars[k] = v
	}
	fs := byCheck(analyze(&State{Env: env}), "env.missing_path")
	got := map[string]finding.Severity{}
	for _, f := range fs {
		got[f.Subject] = f.Severity
	}
	want := map[string]finding.Severity{"BAD_HOME": finding.Warning, "HISTFILE": finding.Notice, "XDG_DATA_DIRS": finding.Info}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env.missing_path = %v", got)
	}
	for _, f := range fs {
		if f.Subject == "XDG_DATA_DIRS" && len(f.Details) != 2 {
			t.Errorf("list variable details = %v", f.Details)
		}
		if f.Subject == "XDG_DATA_DIRS" && !strings.Contains(f.Message, "2 entries that do not exist") {
			t.Errorf("message = %s", f.Message)
		}
	}
}

func TestBreakSystemPackages(t *testing.T) {
	env, _, home := testEnv(t)
	conf := writeFile(t, filepath.Join(home, ".config/pip/pip.conf"),
		"[global]\nbreak-system-packages = true\n[install]\nbreak-system-packages = false\n")
	env.Vars["PIP_BREAK_SYSTEM_PACKAGES"] = "1"
	got := subjects(byCheck(analyze(&State{Env: env}), "python.break_system_packages"))
	if !reflect.DeepEqual(got, []string{conf, "env"}) && !reflect.DeepEqual(got, []string{"env", conf}) {
		t.Errorf("subjects = %v", got)
	}
	env.Vars["PIP_BREAK_SYSTEM_PACKAGES"] = "0"
	writeFile(t, conf, "; break-system-packages = true\n")
	if fs := byCheck(analyze(&State{Env: env}), "python.break_system_packages"); len(fs) != 0 {
		t.Errorf("disabled settings should not be reported: %+v", fs)
	}
}

func TestUserSite(t *testing.T) {
	env, fake, home := testEnv(t)
	site := filepath.Join(home, ".local/lib/python3.14/site-packages")
	mkdir(t, filepath.Join(site, "autokey-0.96.1.dist-info"))
	fake.AddOutput(site+"\n", "python3", "-c")
	fs := byCheck(analyze(&State{Env: env}), "python.user_site")
	if len(fs) != 1 || fs[0].Subject != "autokey" || fs[0].Severity != finding.Info {
		t.Fatalf("python.user_site = %+v", fs)
	}
	if !strings.Contains(fs[0].Hint, "environment:python.user_site:autokey") {
		t.Errorf("hint should name the ignore key: %s", fs[0].Hint)
	}
}

func TestUserSiteNoPython(t *testing.T) {
	env, _, _ := testEnv(t)
	if fs := byCheck(analyze(&State{Env: env}), "python.user_site"); len(fs) != 0 {
		t.Errorf("no python3 should mean no findings: %+v", fs)
	}
}

func TestStartupExit(t *testing.T) {
	env, _, _ := testEnv(t)
	caps := []Capture{
		{Shell: "zsh", Mode: ModeTTY, Path: "/bin/zsh", Code: 0},
		{Shell: "zsh", Mode: ModeNoTTY, Path: "/bin/zsh", Code: 1},
		{Shell: "bash", Mode: ModeTTY, Path: "/bin/bash", TimedOut: true, Code: 124, Duration: 15 * time.Second},
		{Shell: "fish", Mode: ModeTTY, Code: 127, Err: "fish is not installed"},
		{Shell: "ksh", Mode: ModeTTY, Path: "/bin/ksh", Code: 127, Err: "exec format error"},
	}
	fs := byCheck(analyze(&State{Env: env, Captures: caps}), "shell.startup_exit")
	if got := subjects(fs); !reflect.DeepEqual(got, []string{"bash/tty", "ksh/tty", "zsh/notty"}) {
		t.Fatalf("subjects = %v", got)
	}
	for _, f := range fs {
		if f.Severity != finding.Error {
			t.Errorf("%s severity = %v", f.Subject, f.Severity)
		}
	}
}

func TestStartupOutput(t *testing.T) {
	env, _, _ := testEnv(t)
	caps := []Capture{
		{Shell: "zsh", Mode: ModeTTY, Path: "/bin/zsh", Output: []string{"hello there"}},
		{Shell: "zsh", Mode: ModeNoTTY, Path: "/bin/zsh", Output: []string{"zshrc.zsh:144: no such file or directory:"}},
		{Shell: "bash", Mode: ModeTTY, Path: "/bin/bash"},
		{Shell: "bash", Mode: ModeNoTTY, Path: "/bin/bash", TimedOut: true, Output: []string{"partial"}},
	}
	fs := analyze(&State{Env: env, Captures: caps})
	tty := byCheck(fs, "shell.startup_output")
	if len(tty) != 1 || tty[0].Subject != "zsh" || tty[0].Severity != finding.Warning {
		t.Fatalf("startup_output = %+v", tty)
	}
	notty := byCheck(fs, "shell.startup_notty")
	if len(notty) != 1 || notty[0].Severity != finding.Error || !strings.Contains(notty[0].Hint, "-t 1") {
		t.Fatalf("startup_notty = %+v", notty)
	}
}

func TestStartupTime(t *testing.T) {
	env, _, _ := testEnv(t)
	caps := []Capture{
		{Shell: "zsh", Mode: ModeTTY, Path: "/bin/zsh", Duration: 700 * time.Millisecond},
		{Shell: "bash", Mode: ModeTTY, Path: "/bin/bash", Duration: 2 * time.Second},
		{Shell: "dash", Mode: ModeTTY, Path: "/bin/dash", Duration: 100 * time.Millisecond},
		{Shell: "zsh", Mode: ModeNoTTY, Path: "/bin/zsh", Duration: 5 * time.Second},
	}
	fs := byCheck(analyze(&State{Env: env, Captures: caps, SlowStartup: 500 * time.Millisecond}), "shell.startup_time")
	got := map[string]finding.Severity{}
	for _, f := range fs {
		got[f.Subject] = f.Severity
	}
	if !reflect.DeepEqual(got, map[string]finding.Severity{"zsh": finding.Notice, "bash": finding.Warning}) {
		t.Fatalf("startup_time = %v", got)
	}
	if fs := byCheck(analyze(&State{Env: env, Captures: caps}), "shell.startup_time"); len(fs) != 0 {
		t.Error("a zero threshold disables the check")
	}
}

func TestSyntaxAndShellcheck(t *testing.T) {
	env, _, _ := testEnv(t)
	s := &State{
		Env: env,
		Syntax: []SyntaxResult{
			{Path: "/a.sh", Shell: "bash", Loaded: true},
			{Path: "/a.sh", Shell: "zsh", Loaded: true, Errors: []string{"/a.sh:3: parse error near `}'"}},
			{Path: "/notes.sh", Shell: "bash", Errors: []string{"line 1: syntax error"}},
		},
		Shellcheck: &ShellcheckResult{Installed: true,
			Comments: map[string][]string{"/b.sh": {"line 1: SC1000", "line 2: SC1001"}, "/c.sh": {"x"}},
			Levels:   map[string]string{"/b.sh": "error", "/c.sh": "warning"}},
	}
	fs := analyze(s)
	syn := map[string]finding.Severity{}
	for _, f := range byCheck(fs, "shell.syntax") {
		syn[f.Subject] = f.Severity
	}
	if !reflect.DeepEqual(syn, map[string]finding.Severity{"/a.sh (zsh)": finding.Error, "/notes.sh (bash)": finding.Warning}) {
		t.Fatalf("syntax = %v (unloaded files are warnings)", syn)
	}
	sc := byCheck(fs, "shell.shellcheck")
	got := map[string]finding.Severity{}
	for _, f := range sc {
		got[f.Subject] = f.Severity
	}
	if !reflect.DeepEqual(got, map[string]finding.Severity{"/b.sh": finding.Error, "/c.sh": finding.Warning}) {
		t.Fatalf("shellcheck = %v", got)
	}
	// Lint and parse errors roll up into one task per priority, listing
	// every file:line.
	var titles []string
	for _, x := range todo.Derive(append(byCheck(fs, "shell.shellcheck"), byCheck(fs, "shell.syntax")...)) {
		titles = append(titles, string(x.Priority)+" "+x.Title)
		if x.Title == "Fix shellcheck errors in 1 shell file" && strings.Join(x.Details, "|") != "/b.sh:1: SC1000|/b.sh:2: SC1001" {
			t.Errorf("rollup details %v", x.Details)
		}
	}
	if strings.Join(titles, "|") != "high Fix shellcheck errors in 1 shell file|medium Fix shellcheck warnings in 1 shell file|"+
		"high Fix parse errors in 1 startup file (bash or zsh)|medium Fix or delete 1 unsourced shell file with parse errors" {
		t.Errorf("rollup tasks %q", titles)
	}

	s.Shellcheck = &ShellcheckResult{}
	sc = byCheck(analyze(s), "shell.shellcheck")
	if len(sc) != 1 || sc[0].Kind != finding.Suggestion || sc[0].Severity != finding.Info {
		t.Fatalf("missing shellcheck should be a suggestion: %+v", sc)
	}
	s.Shellcheck = nil
	if len(byCheck(analyze(s), "shell.shellcheck")) != 0 {
		t.Error("nil result means not run")
	}
}

func TestMissingSource(t *testing.T) {
	env, _, home := testEnv(t)
	env.Vars["XDG_CONFIG_HOME"] = filepath.Join(home, ".config")
	writeFile(t, filepath.Join(home, "exists.sh"), "")
	rc := writeFile(t, filepath.Join(home, ".zshrc"), strings.Join([]string{
		"source ~/exists.sh",                              // 1 present
		"source $HOME/.config/television/integration.zsh", // 2 missing
		`. "${XDG_CONFIG_HOME}/missing.sh"`,               // 3 missing, quoted
		"[ -f ~/guarded.sh ] && source ~/guarded.sh",      // 4 guarded inline
		"if [[ -r ~/block.sh ]]; then",                    // 5
		"  source ~/block.sh",                             // 6 guarded by block
		"fi",                                              // 7
		"source ~/quiet.sh 2>/dev/null",                   // 8 silenced
		"source $UNSET_VAR/x.sh",                          // 9 unresolvable
		"source $(brew --prefix)/x.sh",                    // 10 command substitution
		"source ~/plugins/*.zsh",                          // 11 glob
		"source relative.sh",                              // 12 relative
		"source ${MISSING_ROOT:-$HOME/default}/init.sh",   // 13 default used, missing
		"source ~/also.sh || true",                        // 14 handled
		"# source ~/commented.sh",                         // 15 comment
	}, "\n"))
	fs := byCheck(analyze(&State{Env: env, Scripts: []Script{{Path: rc, Dialect: DialectZsh}}}), "shell.missing_source")
	want := []string{rc + ":13", rc + ":2", rc + ":3"}
	if got := subjects(fs); !reflect.DeepEqual(got, want) {
		t.Fatalf("missing_source = %v, want %v", got, want)
	}
	for _, f := range fs {
		if f.Subject == rc+":13" && !strings.Contains(f.Message, filepath.Join(home, "default", "init.sh")) {
			t.Errorf("default expansion: %s", f.Message)
		}
	}
}

func TestResolveStatic(t *testing.T) {
	env, _, home := testEnv(t)
	env.Vars["EMPTY"] = ""
	for raw, want := range map[string]string{
		"~":                     home,
		"~/x":                   home + "/x",
		"$HOME/x":               home + "/x",
		"${HOME}/x":             home + "/x",
		"${EMPTY:-/fallback}/x": "/fallback/x",
		"/abs/path":             "/abs/path",
	} {
		if got, ok := resolveStatic(raw, env); !ok || got != want {
			t.Errorf("resolveStatic(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"$NOPE/x", "x.sh", "${HOME:h}/x", "`pwd`/x", "/a/*.sh", "$EMPTY/x"} {
		if got, ok := resolveStatic(raw, env); ok {
			t.Errorf("resolveStatic(%q) = %q, want unresolved", raw, got)
		}
	}
}

func TestRedefinedUsesTrace(t *testing.T) {
	env, _, home := testEnv(t)
	a := writeFile(t, filepath.Join(home, "a.sh"), "alias x=1\n")
	b := writeFile(t, filepath.Join(home, "b.sh"), "alias x=2\n")
	c := writeFile(t, filepath.Join(home, "c.sh"), "alias x=3\n")
	traced := map[string]bool{"zsh": true, "bash": true}
	scripts := []Script{
		{Path: a, Dialect: DialectSh, LoadedBy: []string{"zsh"}},
		{Path: b, Dialect: DialectSh, LoadedBy: []string{"bash"}},
		{Path: c, Dialect: DialectSh},
	}
	if fs := byCheck(analyze(&State{Env: env, Scripts: scripts, Traced: traced}), "shell.redefined"); len(fs) != 0 {
		t.Fatalf("files loaded by different shells (or none) do not conflict: %+v", fs)
	}
	scripts[1].LoadedBy = []string{"bash", "zsh"}
	if fs := byCheck(analyze(&State{Env: env, Scripts: scripts, Traced: traced}), "shell.redefined"); len(fs) != 1 {
		t.Fatalf("both loaded by zsh: %+v", fs)
	}
}

func TestUnloaded(t *testing.T) {
	env, _, _ := testEnv(t)
	traced := map[string]bool{"zsh": true, "bash": true}
	scripts := []Script{
		{Path: "/h/.bash_login", Dialect: DialectBash, Startup: true},
		{Path: "/h/.profile", Dialect: DialectSh, Startup: true, LoadedBy: []string{"bash", "zsh"}},
		{Path: "/h/.shell/aliases/images/colors.sh", Dialect: DialectSh},
		{Path: "/h/.shell/aliases/images/transform.sh", Dialect: DialectSh},
		{Path: "/h/.shell/aliases/git.sh", Dialect: DialectSh, LoadedBy: []string{"zsh", "bash"}},
		{Path: "/h/.shell/zsh/plugin-configs/fzf.zsh", Dialect: DialectZsh},
		{Path: "/h/.shell/functions/mkcd", Dialect: DialectSh, Function: "mkcd"},
		{Path: "/h/.shell/bin/compile", Dialect: DialectZsh, Executable: true},
	}
	fs := byCheck(analyze(&State{Env: env, Scripts: scripts, Traced: traced}), "shell.unloaded")
	want := []string{"/h/.bash_login", "/h/.shell/aliases/images", "/h/.shell/zsh/plugin-configs"}
	if got := subjects(fs); !reflect.DeepEqual(got, want) {
		t.Fatalf("unloaded = %v, want %v", got, want)
	}
	for _, f := range fs {
		switch f.Subject {
		case "/h/.bash_login":
			if f.Severity != finding.Notice {
				t.Errorf("startup file severity = %v", f.Severity)
			}
		case "/h/.shell/aliases/images":
			if !reflect.DeepEqual(f.Details, []string{"colors.sh", "transform.sh"}) || f.Kind != finding.Suggestion {
				t.Errorf("grouped finding = %+v", f)
			}
		}
	}
	if fs := byCheck(analyze(&State{Env: env, Scripts: scripts}), "shell.unloaded"); len(fs) != 0 {
		t.Error("without a trace nothing is known to be unloaded")
	}
}

func TestRedefined(t *testing.T) {
	env, _, home := testEnv(t)
	a := writeFile(t, filepath.Join(home, "aliases/a.sh"), "alias ll='ls -l'\nalias gs=\"git status\"\nfoo() { :; }\n")
	b := writeFile(t, filepath.Join(home, "zsh/b.zsh"), "alias ll='ls -la'\nfunction foo {\n}\n")
	c := writeFile(t, filepath.Join(home, "bash/c.bash"), "alias -g zz=1\nalias gs='git st'\n")
	d := writeFile(t, filepath.Join(home, "zsh/d.zsh"), "alias zz=2\nif x; then alias q=1; else alias q=2; fi\nalias q=3\n")
	fn := writeFile(t, filepath.Join(home, "functions/foo"), "echo foo\n")
	exe := writeFile(t, filepath.Join(home, "bin/tool"), "#!/bin/sh\nalias ll=x\nfoo() { :; }\n")
	scripts := []Script{
		{Path: a, Dialect: DialectSh}, {Path: b, Dialect: DialectZsh}, {Path: c, Dialect: DialectBash},
		{Path: d, Dialect: DialectZsh}, {Path: fn, Dialect: DialectSh, Function: "foo"},
		{Path: exe, Dialect: DialectSh, Executable: true},
	}
	fs := byCheck(analyze(&State{Env: env, Scripts: scripts}), "shell.redefined")
	want := []string{"alias:gs", "alias:ll", "function:foo"}
	if got := subjects(fs); !reflect.DeepEqual(got, want) {
		t.Fatalf("redefined = %v, want %v (zz is bash vs zsh; q repeats within one file)", got, want)
	}
	for _, f := range fs {
		if f.Kind != finding.Suggestion || f.Severity != finding.Info {
			t.Errorf("%s: %v/%v", f.Subject, f.Kind, f.Severity)
		}
		if f.Subject == "function:foo" && (len(f.Details) != 3 || !strings.Contains(f.Message, "3 files")) {
			t.Errorf("foo: %s %v", f.Message, f.Details)
		}
	}
}
