package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// failingStore is the engine's SQLite store with the named methods
// failing.
type failingStore struct {
	RunStore
	fail  map[string]bool
	spent float64
}

var errStore = errors.New("disk I/O error")

func (s *failingStore) err(name string) error {
	if s.fail[name] {
		return errStore
	}
	return nil
}

func (s *failingStore) Prune(ctx context.Context, command string, keep int) error {
	if err := s.err("Prune"); err != nil {
		return err
	}
	return s.RunStore.Prune(ctx, command, keep)
}

func (s *failingStore) Todos(ctx context.Context, command string) ([]todo.Todo, error) {
	if err := s.err("Todos"); err != nil {
		return nil, err
	}
	return s.RunStore.Todos(ctx, command)
}

func (s *failingStore) SaveTodos(ctx context.Context, ts []todo.Todo) error {
	if err := s.err("SaveTodos"); err != nil {
		return err
	}
	return s.RunStore.SaveTodos(ctx, ts)
}

func (s *failingStore) UpdateAnalysis(ctx context.Context, id int64, a *run.Analysis) error {
	if err := s.err("UpdateAnalysis"); err != nil {
		return err
	}
	return s.RunStore.UpdateAnalysis(ctx, id, a)
}

func (s *failingStore) AICostSince(context.Context, time.Time) (float64, error) {
	return s.spent, s.err("AICostSince")
}

func failing(e *Engine, names ...string) *failingStore {
	fs := &failingStore{RunStore: e.Store, fail: map[string]bool{}}
	for _, n := range names {
		fs.fail[n] = true
	}
	e.Store = fs
	return fs
}

func TestExecuteStoreFailures(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ method, want string }{
		{"Prune", "prune history: disk I/O error"},
		{"Todos", "load tasks: disk I/O error"},
		{"SaveTodos", "save tasks: disk I/O error"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			e, _ := engine(t)
			failing(e, tc.method)
			s := &fakeScanner{command: "system", findings: []finding.Finding{fnd("procs.zombie", "a", finding.Warning)}}
			if _, err := e.Execute(ctx, s, nil); err == nil || err.Error() != tc.want {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
	// A run that derives no tasks never writes them.
	e, _ := engine(t)
	failing(e, "SaveTodos")
	if _, err := e.Execute(ctx, &fakeScanner{command: "system"}, nil); err != nil {
		t.Errorf("no tasks to save: %v", err)
	}
}

func TestAnalyzeSaveFailure(t *testing.T) {
	ctx := context.Background()
	e, _ := engine(t)
	res, err := e.Execute(ctx, &fakeScanner{command: "system"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &exec.Fake{}
	f.AddOutput(`{"subtype":"success","result":"fine"}`, "claude")
	e.AI = &llm.Client{Runner: f, Model: "m", Now: e.Now}
	failing(e, "UpdateAnalysis")
	if err := e.Analyze(ctx, res.Run, false); err == nil || !strings.Contains(err.Error(), "save ai review") || res.Run.Analysis == nil {
		t.Errorf("the review is kept and the failed save reported: %v %+v", err, res.Run.Analysis)
	}
	bad := &exec.Fake{}
	bad.Add([]string{"claude"}, exec.Result{Code: 1, Stderr: "boom"})
	e.AI = &llm.Client{Runner: bad, Model: "m", Now: e.Now}
	if err := e.Analyze(ctx, &run.Run{}, true); err == nil {
		t.Error("a failed AI call is an error")
	}
}

const reviewAnswer = `{"subtype":"success","result":"","total_cost_usd":0.1,"structured_output":{"points":[` +
	`{"title":"Swap is off","subject":"swap","severity":"notice","details":["no swap"],"fix":"add swap"}]}}`

func TestReviewOnScan(t *testing.T) {
	ctx := context.Background()
	e, _ := engine(t)
	e.Config.AI = config.AIConfig{ReviewOnScan: []string{"system"}, ReviewDailyUSD: 1}
	f := &exec.Fake{}
	f.AddOutput(reviewAnswer, "claude")
	e.Reviewer = &llm.Client{Runner: f, Model: "m", Cache: sqlite(e), Now: e.Now}
	fs := failing(e)

	res, err := e.Execute(ctx, &fakeScanner{command: "system"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCheck(res.Run.Findings, "swap") || len(f.Calls) != 1 {
		t.Fatalf("the review's point becomes a finding: %+v, %d call(s)", res.Run.Findings, len(f.Calls))
	}
	if _, err := e.Execute(ctx, &fakeScanner{command: "system", scope: "procs"}, nil); err != nil || len(f.Calls) != 1 {
		t.Errorf("a scoped scan is not reviewed: %v, %d call(s)", err, len(f.Calls))
	}

	// A new prompt over today's budget is skipped; a failed spend lookup
	// and a failed call are notes, never a failed scan.
	other := &fakeScanner{command: "system", findings: []finding.Finding{fnd("procs.zombie", "z", finding.Warning)}}
	fs.spent = 2
	if res, err = e.Execute(ctx, other, nil); err != nil || !hasError(res.Run, "ai review skipped: today's AI spend $2.00") {
		t.Errorf("over budget: %v %v", err, res.Run.Errors)
	}
	fs.fail["AICostSince"] = true
	if res, _ = e.Execute(ctx, other, nil); !hasError(res.Run, "ai review: disk I/O error") {
		t.Errorf("spend lookup failed: %v", res.Run.Errors)
	}
	e.Config.AI.ReviewDailyUSD = 0
	bad := &exec.Fake{}
	bad.Add([]string{"claude"}, exec.Result{Code: 1, Stderr: "rate limited"})
	e.Reviewer = &llm.Client{Runner: bad, Model: "m", Now: e.Now}
	if res, _ = e.Execute(ctx, other, nil); !hasError(res.Run, "ai review: ") {
		t.Errorf("failed call: %v", res.Run.Errors)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if add, note := e.review(cctx, "system", &Outcome{}); add != nil || note != "" {
		t.Errorf("a canceled review adds nothing and says nothing: %v %q", add, note)
	}
}

func hasCheck(fs []finding.Finding, subject string) bool {
	for _, f := range fs {
		if f.Subject == subject {
			return true
		}
	}
	return false
}

func hasError(r *run.Run, prefix string) bool {
	for _, e := range r.Errors {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func TestEngineNowFallback(t *testing.T) {
	before := time.Now()
	if got := (&Engine{}).now(); got.Before(before) {
		t.Errorf("now %v before %v", got, before)
	}
}

func TestBackupsAndContainersAdapters(t *testing.T) {
	ctx := context.Background()
	env := &exec.Env{Vars: map[string]string{"PATH": t.TempDir()}, Home: t.TempDir(), Runner: &exec.Fake{}}
	cfg := &config.Config{Backups: config.BackupsConfig{Paths: []string{"~/work"}, MaxAge: time.Hour,
		Sources: []config.BackupSource{{Name: "restic", Command: "restic-last", Covers: []string{"~"}}}},
		Containers: config.ContainersConfig{Engines: []string{"docker"}, StoppedAfter: time.Hour}}
	b := NewBackups(cfg, env)
	if b.Command() != "backups" || b.Scope() != "" || len(b.Options.Sources) != 1 || b.Options.Sources[0].Name != "restic" {
		t.Errorf("backups scanner %+v", b.Options)
	}
	out, err := b.Scan(ctx, progress.Nop)
	if err != nil || !json.Valid(out.Data) {
		t.Errorf("backups scan: %v %s", err, out.Data)
	}
	c := NewContainers(cfg, env)
	if c.Command() != "containers" || c.Scope() != "" || c.Options.StoppedAfter != time.Hour {
		t.Errorf("containers scanner %+v", c.Options)
	}
	out, err = c.Scan(ctx, progress.Nop)
	if err != nil || string(out.Data) != `{"engines":null}` {
		t.Errorf("no engine installed: %v %s", err, out.Data)
	}
}
