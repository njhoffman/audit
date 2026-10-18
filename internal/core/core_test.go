package core

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/llm"
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
