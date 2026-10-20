package environment

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

type recorder struct {
	mu     sync.Mutex
	phases []string
	steps  int
}

func (r *recorder) Phase(label string, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phases = append(r.phases, label)
}

func (r *recorder) Step(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps++
}

func (r *recorder) Done() {}

var _ progress.Reporter = (*recorder)(nil)

func TestScan(t *testing.T) {
	env, fake, home := testEnv(t)
	bin := filepath.Join(home, "bin")
	for _, b := range []string{"zsh", "bash", "shellcheck"} {
		makeExe(t, filepath.Join(bin, b), "")
	}
	profile := writeFile(t, filepath.Join(home, ".profile"), "export A=1\n")
	zshrc := writeFile(t, filepath.Join(home, ".zshrc"), "setopt x\n")
	shebang := makeExe(t, filepath.Join(home, ".shell/bin/tool"), "#!/bin/bash\necho $1\n")

	fake.AddOutput("", "zsh", "-n")
	fake.AddOutput("", "bash", "-n")
	fake.Add([]string{"zsh", "-n", zshrc}, exec.Result{Code: 1, Stderr: zshrc + ":1: parse error\n"})
	fake.AddOutput(`{"comments":[{"file":"`+profile+`","line":1,"level":"warning","code":2155,"message":"Declare and assign separately"}]}`,
		"shellcheck", "-f", "json1", "-S", "warning", "-e", shellcheckExcludes, "-s", "bash")
	fake.AddOutput(`{"comments":[{"file":"`+shebang+`","line":2,"level":"info","code":2086,"message":"Quote"},`+
		`{"file":"`+shebang+`","line":2,"level":"error","code":1000,"message":"Bad"}]}`,
		"shellcheck", "-f", "json1", "-S", "warning", "-e", shellcheckExcludes, shebang)

	captured := map[string]string{"HOME": home, "PATH": bin, "FROM": "zsh-tty"}
	capt := &fakeCapturer{captures: map[string]Capture{
		"zsh/tty":    {Path: filepath.Join(bin, "zsh"), Env: captured, Duration: 200 * time.Millisecond},
		"zsh/notty":  {Path: filepath.Join(bin, "zsh"), Env: map[string]string{"FROM": "zsh-notty"}},
		"bash/tty":   {Path: filepath.Join(bin, "bash"), Env: map[string]string{"FROM": "bash-tty"}},
		"bash/notty": {Path: filepath.Join(bin, "bash"), TimedOut: true},
	}, traces: map[string][]string{"zsh": {profile, zshrc}}}
	rec := &recorder{}
	var runnerFor *exec.Env
	s := &Scanner{
		Env: env, Capturer: capt, Shells: []string{"zsh", "bash"},
		StartupFiles: []string{"~/.profile", "~/.zshrc", "~/.bashrc"}, StartupDirs: []string{"~/.shell"},
		SlowStartup: time.Second, Workers: 2, Progress: rec,
		RunnerFor: func(e *exec.Env) exec.Runner { runnerFor = e; return fake },
	}
	res := s.Scan(ctx)

	if !reflect.DeepEqual(capt.calls, []string{"zsh/tty", "zsh/notty", "bash/tty", "bash/notty", "zsh/trace", "bash/trace"}) {
		t.Errorf("captures = %v", capt.calls)
	}
	if res.State.Env.Get("FROM") != "zsh-tty" || runnerFor != res.State.Env || res.State.Env.Home != home {
		t.Errorf("analyzed env should be the zsh tty capture: %v", res.State.Env.Vars)
	}
	if res.Data.EnvSource != "zsh login shell (tty)" {
		t.Errorf("env source = %q", res.Data.EnvSource)
	}
	var paths []string
	for _, sc := range res.State.Scripts {
		paths = append(paths, sc.Path)
	}
	if !reflect.DeepEqual(paths, []string{profile, shebang, zshrc}) {
		t.Errorf("scripts = %v", paths)
	}

	var parsed []string
	for _, r := range res.State.Syntax {
		parsed = append(parsed, filepath.Base(r.Path)+"/"+r.Shell)
	}
	sort.Strings(parsed)
	// zsh was traced and sourced .profile; bash was not traced, so .profile
	// is still assumed to load under it by dialect.
	if !reflect.DeepEqual(parsed, []string{".profile/bash", ".profile/zsh", ".zshrc/zsh", "tool/bash"}) {
		t.Errorf("syntax jobs = %v", parsed)
	}
	if len(res.Data.Syntax) != 1 || res.Data.Syntax[0].Path != zshrc || res.Data.Syntax[0].Errors[0] != zshrc+":1: parse error" {
		t.Errorf("persisted syntax failures = %+v", res.Data.Syntax)
	}

	sc := res.State.Shellcheck
	if !sc.Installed || len(sc.Comments[profile]) != 1 || len(sc.Comments[shebang]) != 2 || sc.Levels[shebang] != "error" {
		t.Errorf("shellcheck = %+v", sc)
	}
	if _, ok := sc.Comments[zshrc]; ok {
		t.Error("zsh files must not go through shellcheck")
	}

	if !reflect.DeepEqual(res.Data.Traced, []string{"zsh"}) || !reflect.DeepEqual(res.State.Scripts[0].LoadedBy, []string{"zsh"}) {
		t.Errorf("trace not applied: %v %+v", res.Data.Traced, res.State.Scripts[0])
	}
	if len(rec.phases) != 4 || rec.steps != 4+2+4 {
		t.Errorf("progress phases=%v steps=%d", rec.phases, rec.steps)
	}

	var d Data
	if err := json.Unmarshal(res.RawData(), &d); err != nil || len(d.Captures) != 4 {
		t.Fatalf("raw data: %v %+v", err, d)
	}
	if strings.Contains(string(res.RawData()), "zsh-tty") {
		t.Error("captured environments must not be persisted")
	}

	stats := map[string]string{}
	for _, st := range res.Stats {
		stats[st.Name] = st.Value
	}
	if stats["startup scripts"] != "3 (bash 1, sh 1, zsh 1)" || stats["bash notty"] != "timed out" ||
		stats["syntax failures"] != "1" || stats["analyzed env"] != "zsh login shell (tty)" {
		t.Errorf("stats = %v", stats)
	}

	fs := Analyze(res.State)
	for _, check := range []string{"shell.syntax", "shell.shellcheck", "shell.startup_exit"} {
		if len(byCheck(fs, check)) == 0 {
			t.Errorf("expected a %s finding", check)
		}
	}

	// Files audit scripts lints are skipped here unless a shell sources
	// them at startup: tool is skipped, .profile (sourced by zsh) is not.
	real := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	var asked []string
	s.LintedElsewhere = func(p string) bool {
		asked = append(asked, p)
		return p == real(shebang) || p == real(profile)
	}
	res = s.Scan(ctx)
	if len(res.State.Scripts) != 3 {
		t.Errorf("skipped files stay in the inventory: %d", len(res.State.Scripts))
	}
	for _, r := range res.State.Syntax {
		if r.Path == shebang {
			t.Errorf("tool should not be parsed here: %+v", r)
		}
	}
	if _, ok := res.State.Shellcheck.Comments[shebang]; ok {
		t.Error("tool should not be shellchecked here")
	}
	if len(res.State.Shellcheck.Comments[profile]) != 1 {
		t.Errorf("a sourced startup file is always linted: %+v", res.State.Shellcheck.Comments)
	}
	if slices.Contains(asked, real(profile)) {
		t.Error("sourced files need no ownership lookup")
	}
}

func TestScanSkipsUnstartableShell(t *testing.T) {
	env, _, home := testEnv(t)
	makeExe(t, filepath.Join(home, "bin", "zsh"), "")
	writeFile(t, filepath.Join(home, ".zshrc"), "")
	s := &Scanner{Env: env, Capturer: &fakeCapturer{}, StartupFiles: []string{"~/.zshrc"}}
	res := s.Scan(ctx)
	if len(res.State.Syntax) != 1 || !res.State.Syntax[0].Skipped || len(res.Data.Syntax) != 0 {
		t.Errorf("a shell that cannot run is not a syntax error: %+v", res.State.Syntax)
	}
}

func TestScanFallsBackToProcessEnv(t *testing.T) {
	env, _, _ := testEnv(t)
	s := &Scanner{Env: env, Capturer: &fakeCapturer{}, Shells: []string{"zsh"}}
	res := s.Scan(ctx)
	if res.State.Env != env || res.Data.EnvSource != "audit process" {
		t.Errorf("fallback env: %q", res.Data.EnvSource)
	}
	if res.State.Shellcheck.Installed {
		t.Error("shellcheck is not on PATH")
	}
}

func TestNewScannerRejectsBadPattern(t *testing.T) {
	env, _, _ := testEnv(t)
	if _, err := NewScanner(env, nil, nil, nil, []string{"("}, 0, 0); err == nil ||
		!strings.Contains(err.Error(), "known_output") {
		t.Errorf("err = %v", err)
	}
	if _, err := NewScanner(env, nil, nil, nil, []string{"^ok$"}, 0, 0); err != nil {
		t.Error(err)
	}
}

func TestShellcheckUsesConfiguredSeverityAndExcludes(t *testing.T) {
	env, fake, home := testEnv(t)
	makeExe(t, filepath.Join(home, "bin", "shellcheck"), "")
	tool := makeExe(t, filepath.Join(home, ".shell/bin/tool"), "#!/bin/bash\necho $1\n")
	fake.AddOutput(`{"comments":[{"file":"`+tool+`","line":2,"level":"style","code":2250,"message":"Prefer braces"}]}`,
		"shellcheck", "-f", "json1", "-S", "style", "-e", "SC2034,SC1090", tool)
	s := &Scanner{Env: env, ShellcheckSeverity: "style", ShellcheckExclude: []string{"SC2034", "SC1090"}}
	s.Env.Runner = fake
	got := s.shellcheck(ctx, []Script{{Path: tool, Dialect: "bash"}})
	if !got.Installed || len(got.Comments[tool]) != 1 {
		t.Errorf("configured flags not passed: %+v", got)
	}
}
