package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

type fakeScanner struct {
	command, scope string
	findings       []finding.Finding
	err            error
	scans          int
	owns           []string
}

func (f *fakeScanner) Command() string { return f.command }
func (f *fakeScanner) Scope() string   { return f.scope }
func (f *fakeScanner) Scan(context.Context, progress.Reporter) (*Outcome, error) {
	f.scans++
	if f.err != nil {
		return nil, f.err
	}
	return &Outcome{Findings: append([]finding.Finding{}, f.findings...), Errors: []string{"part: x"}}, nil
}

type ownerScanner struct{ *fakeScanner }

func (o ownerScanner) Owns(check string) bool { return prefixOwner(o.owns).Owns(check) }

func fnd(check, subject string, sev finding.Severity) finding.Finding {
	return finding.Finding{Command: "system", Check: check, Severity: sev, Kind: finding.Issue, Subject: subject, Message: "m"}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func engine(t *testing.T) (*Engine, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	cfg := &config.Config{History: 2, Stale: config.StaleConfig{Thresholds: config.Thresholds{Warn: time.Hour, Old: 24 * time.Hour}}}
	return &Engine{Store: st, Config: cfg, Host: "box", Now: c.now}, c
}

func TestExecuteSavesIgnoresAndCreatesTasks(t *testing.T) {
	e, _ := engine(t)
	e.Config.Ignore = []string{"procs.zombies"}
	ctx := context.Background()
	s := &fakeScanner{command: "system", findings: []finding.Finding{
		fnd("logs.oom", "journal", finding.Error),
		fnd("procs.zombies", "zombie processes", finding.Warning),
		fnd("users.info", "a", finding.Info),
		fnd("users.info", "b", finding.Info),
	}}
	res, err := e.Execute(ctx, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Run
	if r.ID == 0 || r.Host != "box" || r.Ignored != 1 || len(r.Findings) != 3 {
		t.Errorf("run %+v", r)
	}
	if res.Saved || res.TaskChanges != 2 {
		t.Errorf("result %+v", res)
	}
	ts, _ := e.Store.Todos(ctx, "system")
	keys := map[string]todo.Priority{}
	for _, tk := range ts {
		keys[tk.Key] = tk.Priority
	}
	if keys["system:logs.oom:journal"] != todo.High || keys[todo.AggregateKey("system", "users.info")] != todo.Low || len(keys) != 2 {
		t.Errorf("tasks %v", keys)
	}
}

func TestResolveModes(t *testing.T) {
	e, c := engine(t)
	ctx := context.Background()
	s := &fakeScanner{command: "system", findings: []finding.Finding{fnd("logs.oom", "journal", finding.Error)}}

	if _, err := e.Resolve(ctx, s, SavedOnly, nil); !errors.Is(err, ErrNoSavedRun) {
		t.Fatalf("saved-only without a run: %v", err)
	}
	res, err := e.Resolve(ctx, s, Auto, nil)
	if err != nil || res.Saved || s.scans != 1 {
		t.Fatalf("auto with nothing saved should scan: %+v %v", res, err)
	}

	c.t = c.t.Add(30 * time.Minute)
	if res, _ = e.Resolve(ctx, s, Auto, nil); !res.Saved || s.scans != 1 {
		t.Error("fresh saved run should be reused")
	}
	if res, _ = e.Resolve(ctx, s, Rescan, nil); res.Saved || s.scans != 2 {
		t.Error("rescan should always scan")
	}

	c.t = c.t.Add(2 * time.Hour)
	if res, _ = e.Resolve(ctx, s, SavedOnly, nil); !res.Saved || s.scans != 2 {
		t.Error("saved-only should never scan, even when stale")
	}
	if res, _ = e.Resolve(ctx, s, Auto, nil); res.Saved || s.scans != 3 {
		t.Error("stale saved run should trigger a scan in auto mode")
	}
}

func TestResolveMatchesScope(t *testing.T) {
	e, _ := engine(t)
	ctx := context.Background()
	full := &fakeScanner{command: "system"}
	if _, err := e.Execute(ctx, full, nil); err != nil {
		t.Fatal(err)
	}
	scoped := &fakeScanner{command: "system", scope: "procs"}
	_, err := e.Resolve(ctx, scoped, SavedOnly, nil)
	if !errors.Is(err, ErrNoSavedRun) || !strings.Contains(err.Error(), "scope procs") {
		t.Errorf("a full run should not satisfy a scoped request: %v", err)
	}
}

func TestSavedAppliesCurrentIgnoreRules(t *testing.T) {
	e, _ := engine(t)
	ctx := context.Background()
	s := &fakeScanner{command: "system", findings: []finding.Finding{
		fnd("logs.oom", "journal", finding.Error), fnd("procs.cpu", "x", finding.Notice)}}
	if _, err := e.Execute(ctx, s, nil); err != nil {
		t.Fatal(err)
	}
	e.Config.Ignore = []string{"system:procs.cpu"}
	r, err := e.Saved(ctx, "system", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Ignored != 1 {
		t.Errorf("findings %v ignored %d", r.Findings, r.Ignored)
	}
}

func TestExecuteResolvesGoneTasks(t *testing.T) {
	e, c := engine(t)
	ctx := context.Background()
	s := &fakeScanner{command: "system", findings: []finding.Finding{
		fnd("logs.oom", "journal", finding.Error), fnd("procs.cpu", "x", finding.Warning)}}
	if _, err := e.Execute(ctx, s, nil); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	s.findings = s.findings[:1]
	if _, err := e.Execute(ctx, s, nil); err != nil {
		t.Fatal(err)
	}
	status := statuses(t, e)
	if status["system:procs.cpu:x"] != todo.Resolved || status["system:logs.oom:journal"] != todo.Open {
		t.Errorf("statuses %v", status)
	}
}

func statuses(t *testing.T, e *Engine) map[string]todo.Status {
	t.Helper()
	ts, err := e.Store.Todos(context.Background(), "system")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]todo.Status{}
	for _, tk := range ts {
		m[tk.Key] = tk.Status
	}
	return m
}

func TestScopedRunOnlyResolvesOwnedTasks(t *testing.T) {
	e, c := engine(t)
	ctx := context.Background()
	full := &fakeScanner{command: "system", findings: []finding.Finding{
		fnd("logs.oom", "journal", finding.Error), fnd("procs.cpu", "x", finding.Warning)}}
	if _, err := e.Execute(ctx, full, nil); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)

	// A scoped run that does not declare ownership resolves nothing.
	if _, err := e.Execute(ctx, &fakeScanner{command: "system", scope: "procs"}, nil); err != nil {
		t.Fatal(err)
	}
	if st := statuses(t, e); st["system:procs.cpu:x"] != todo.Open || st["system:logs.oom:journal"] != todo.Open {
		t.Errorf("non-owner scoped run touched tasks: %v", st)
	}

	// An owner resolves tasks of its own checks only.
	procs := ownerScanner{&fakeScanner{command: "system", scope: "procs", owns: []string{"procs."}}}
	if _, err := e.Execute(ctx, procs, nil); err != nil {
		t.Fatal(err)
	}
	if st := statuses(t, e); st["system:procs.cpu:x"] != todo.Resolved || st["system:logs.oom:journal"] != todo.Open {
		t.Errorf("owner scoped run: %v", st)
	}
}

func TestExecutePrunesHistory(t *testing.T) {
	e, c := engine(t)
	ctx := context.Background()
	s := &fakeScanner{command: "system"}
	for i := 0; i < 4; i++ {
		c.t = c.t.Add(time.Minute)
		if _, err := e.Execute(ctx, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := e.Store.History(ctx, "system", 0)
	if len(h) != e.Config.History {
		t.Errorf("history %d, want %d", len(h), e.Config.History)
	}
}

func TestExecuteScanError(t *testing.T) {
	e, _ := engine(t)
	if _, err := e.Execute(context.Background(), &fakeScanner{command: "system", err: errors.New("boom")}, nil); err == nil {
		t.Fatal("want error")
	}
	if h, _ := e.Store.History(context.Background(), "system", 0); len(h) != 0 {
		t.Error("failed scan should not be saved")
	}
}

func TestAnalyze(t *testing.T) {
	e, _ := engine(t)
	ctx := context.Background()
	res, err := e.Execute(ctx, &fakeScanner{command: "system", findings: []finding.Finding{fnd("logs.oom", "journal", finding.Error)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Analyze(ctx, res.Run, false); err == nil {
		t.Error("analyze without a client should fail")
	}
	f := &exec.Fake{}
	f.AddOutput(`{"subtype":"success","result":"looks bad","total_cost_usd":0.5}`, "claude")
	e.Config.AI.AnalysisLevel = "thorough"
	e.AI = &llm.Client{Runner: f, Model: "m", Cache: e.Store, Now: e.Now}
	if err := e.Analyze(ctx, res.Run, false); err != nil {
		t.Fatal(err)
	}
	a := res.Run.Analysis
	if a == nil || a.Text != "looks bad" || a.Level != "deep" || a.Cached {
		t.Fatalf("analysis %+v", a)
	}
	saved, _ := e.Store.GetRun(ctx, res.Run.ID)
	if saved.Analysis == nil || saved.Analysis.Text != "looks bad" {
		t.Error("analysis not persisted")
	}
	if err := e.Analyze(ctx, saved, false); err != nil || !saved.Analysis.Cached || len(f.Calls) != 1 {
		t.Errorf("second analyze should be cached: %+v calls=%d err=%v", saved.Analysis, len(f.Calls), err)
	}
}

func TestRescanHint(t *testing.T) {
	if got := RescanHint("system", ""); got != "audit system --rescan" {
		t.Error(got)
	}
	if got := RescanHint("system", "procs,logs"); got != "audit system --rescan --only procs,logs" {
		t.Error(got)
	}
	if got := RescanHint("packages", "uv"); got != "audit packages --rescan --manager uv" {
		t.Error(got)
	}
	if got := RescanHint("environment", "x"); got != "audit environment --rescan" {
		t.Error(got)
	}
}

func TestNewSystemUsesConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg, _, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSystem(cfg, nil); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	cfg.System.Programs = []string{"bogus"}
	if _, err := NewSystem(cfg, nil); err == nil {
		t.Error("system.programs must reach the scanner")
	}
}

type fakeCapturer struct {
	capture environment.Capture
	shells  []string
}

func (f *fakeCapturer) Capture(_ context.Context, shell, mode string) environment.Capture {
	f.shells = append(f.shells, shell+"/"+mode)
	return f.capture
}

// envManager is installed when its binary is on PATH and reports the value
// of MARK it was collected with as its one package.
type envManager struct{}

func (envManager) Name() string   { return "fakepm" }
func (envManager) Binary() string { return "fakepm" }
func (envManager) Runtime(context.Context, *exec.Env) *packages.Runtime {
	return nil
}
func (envManager) ManagerVersion(context.Context, *exec.Env) string { return "" }
func (envManager) BinDirs(context.Context, *exec.Env) []string      { return nil }
func (envManager) Collect(_ context.Context, env *exec.Env) ([]packages.Package, error) {
	return []packages.Package{{Name: env.Get("MARK")}}, nil
}

func scanPackages(t *testing.T, s *PackagesScanner) (*Outcome, packages.Data) {
	t.Helper()
	out, err := s.Scan(context.Background(), progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	var data packages.Data
	if err := json.Unmarshal(out.Data, &data); err != nil {
		t.Fatal(err)
	}
	return out, data
}

func stat(out *Outcome, name string) string {
	for _, s := range out.Stats {
		if s.Name == name {
			return s.Value
		}
	}
	return ""
}

func TestPackagesScanUsesLoginEnvironment(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "fakepm"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	process := &exec.Env{Vars: map[string]string{"PATH": "/nonexistent", "MARK": "process"}, Home: t.TempDir(), Runner: &exec.Fake{}}
	c := &fakeCapturer{capture: environment.Capture{Env: map[string]string{
		"PATH": bin, "MARK": "login", "AUDIT_ENV_OUT": "/tmp/x",
	}}}
	s := &PackagesScanner{Env: process, Managers: []packages.Manager{envManager{}}, LoginShell: "zsh", Capturer: c}

	out, data := scanPackages(t, s)
	if len(c.shells) != 1 || c.shells[0] != "zsh/"+environment.ModeNoTTY {
		t.Errorf("captures %v, want one zsh without a tty", c.shells)
	}
	inv := data.Inventories[0]
	if !inv.Available || len(inv.Packages) != 1 || inv.Packages[0].Name != "login" {
		t.Errorf("manager should be found on the login PATH and see login vars: %+v", inv)
	}
	if got := stat(out, "environment"); got != "login zsh" {
		t.Errorf("environment stat %q", got)
	}
	for _, f := range out.Findings {
		if f.Check == CheckLoginEnv {
			t.Errorf("unexpected %s finding: %s", CheckLoginEnv, f.Message)
		}
	}
	if process.Get("MARK") != "process" {
		t.Error("the process environment must not be modified")
	}
}

func TestPackagesScanFallsBackWhenLoginFails(t *testing.T) {
	for name, cp := range map[string]environment.Capture{
		"missing": {Code: exec.ExitNotFound, Err: "zsh is not installed"},
		"timeout": {TimedOut: true, Code: exec.ExitTimeout},
		"no env":  {Code: 1},
		"no PATH": {Code: 0, Env: map[string]string{"HOME": "/h"}},
	} {
		t.Run(name, func(t *testing.T) {
			process := &exec.Env{Vars: map[string]string{"PATH": "/nonexistent", "MARK": "process"}, Home: t.TempDir(), Runner: &exec.Fake{}}
			s := &PackagesScanner{Env: process, LoginShell: "zsh", Capturer: &fakeCapturer{capture: cp}}
			out, _ := scanPackages(t, s)
			if got := stat(out, "environment"); got != "process (login zsh failed)" {
				t.Errorf("environment stat %q", got)
			}
			var hit *finding.Finding
			for i := range out.Findings {
				if out.Findings[i].Check == CheckLoginEnv {
					hit = &out.Findings[i]
				}
			}
			if hit == nil || hit.Severity != finding.Warning || hit.Command != packages.Command || hit.Subject != "zsh" {
				t.Fatalf("want a %s warning, got %+v", CheckLoginEnv, out.Findings)
			}
		})
	}
}

func TestPackagesScanStillUsesLoginEnvWhenStartupFails(t *testing.T) {
	// A startup file erroring out is reported by audit environment; the
	// variables the shell did set are still the ones a terminal gets.
	process := &exec.Env{Vars: map[string]string{"PATH": "/nonexistent"}, Home: t.TempDir(), Runner: &exec.Fake{}}
	cp := environment.Capture{Code: 1, Env: map[string]string{"PATH": "/usr/bin"}}
	out, _ := scanPackages(t, &PackagesScanner{Env: process, LoginShell: "bash", Capturer: &fakeCapturer{capture: cp}})
	if got := stat(out, "environment"); got != "login bash" {
		t.Errorf("environment stat %q", got)
	}
}

func TestNewPackagesEnvSource(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg, _, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	env := &exec.Env{Vars: map[string]string{}, Home: t.TempDir()}
	cfg.Environment.Shells = []string{"bash", "zsh"}
	s, err := NewPackages(cfg, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.LoginShell != "bash" || s.Capturer == nil {
		t.Errorf("default should start the first configured shell, got %q", s.LoginShell)
	}
	cfg.Packages.Env = config.EnvProcess
	if s, _ = NewPackages(cfg, env, nil); s.LoginShell != "" {
		t.Errorf("env: process should not start a shell, got %q", s.LoginShell)
	}
	cfg.Packages.Env, cfg.Environment.Shells = config.EnvLogin, nil
	if s, _ = NewPackages(cfg, env, nil); s.LoginShell != "" {
		t.Errorf("no shells configured should fall back to the process, got %q", s.LoginShell)
	}
}
