// Package core runs an audit command end to end: scan, drop ignored findings,
// save the run, reconcile tasks, and optionally attach an AI review. It also
// decides when saved results can stand in for a new scan.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// Outcome is what a scanner produced, before ignore rules apply.
type Outcome struct {
	Findings []finding.Finding
	Stats    []run.Stat
	Errors   []string
	Data     json.RawMessage
}

// Scanner is one command's scan.
type Scanner interface {
	Command() string
	// Scope names the subset scanned; "" means everything. Saved results are
	// only reused for a matching scope.
	Scope() string
	Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error)
}

// Owner is implemented by scanners whose scoped runs cover a known set of
// checks. A scoped run of a scanner that is not an Owner never resolves
// tasks, because a missing finding may just be out of scope.
type Owner interface {
	Owns(check string) bool
}

// Mode says whether saved results may be used.
type Mode int

const (
	// Auto reuses saved results younger than the warn threshold and scans
	// otherwise.
	Auto Mode = iota
	// Rescan always scans.
	Rescan
	// SavedOnly never scans.
	SavedOnly
)

// ErrNoSavedRun is returned in SavedOnly mode when nothing was saved yet.
var ErrNoSavedRun = errors.New("no saved results")

// Engine ties the scanners to the store.
type Engine struct {
	Store  *store.Store
	Config *config.Config
	Host   string
	Now    func() time.Time
	// AI is nil unless --ai was given.
	AI *llm.Client
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Result is a run plus how it was obtained.
type Result struct {
	Run *run.Run
	// Saved is true when the run was read back rather than just scanned.
	Saved bool
	// TaskChanges counts tasks created, updated or resolved by this scan.
	TaskChanges int
}

// Resolve returns results for s according to mode, scanning when needed.
func (e *Engine) Resolve(ctx context.Context, s Scanner, mode Mode, rep progress.Reporter) (*Result, error) {
	if mode != Rescan {
		r, err := e.Saved(ctx, s.Command(), s.Scope())
		if err != nil {
			return nil, err
		}
		if mode == SavedOnly {
			if r == nil {
				return nil, fmt.Errorf("%w for audit %s%s", ErrNoSavedRun, s.Command(), scopeSuffix(s.Scope()))
			}
			return &Result{Run: r, Saved: true}, nil
		}
		th := e.Config.Stale.For(s.Command())
		if r != nil && run.FreshnessOf(r.Age(e.now()), th.Warn, th.Old) == run.Fresh {
			return &Result{Run: r, Saved: true}, nil
		}
	}
	return e.Execute(ctx, s, rep)
}

func scopeSuffix(scope string) string {
	if scope == "" {
		return ""
	}
	return " (scope " + scope + ")"
}

// Saved loads the newest saved run of command and scope with the current
// ignore rules applied, or nil when there is none.
func (e *Engine) Saved(ctx context.Context, command, scope string) (*run.Run, error) {
	r, err := e.Store.LatestRun(ctx, command, scope)
	if err != nil || r == nil {
		return nil, err
	}
	kept, ignored := finding.NewIgnorer(e.Config.Ignore).Split(r.Findings)
	r.Findings = kept
	r.Ignored += len(ignored)
	return r, nil
}

// Execute scans, saves the run, prunes history and reconciles tasks.
func (e *Engine) Execute(ctx context.Context, s Scanner, rep progress.Reporter) (*Result, error) {
	if rep == nil {
		rep = progress.Nop
	}
	start := e.now()
	out, err := s.Scan(ctx, rep)
	if err != nil {
		return nil, err
	}
	kept, ignored := finding.NewIgnorer(e.Config.Ignore).Split(out.Findings)
	if kept == nil {
		kept = []finding.Finding{}
	}
	finding.Sort(kept)
	r := &run.Run{
		Command: s.Command(), Scope: s.Scope(), Host: e.Host, StartedAt: start, FinishedAt: e.now(),
		Findings: kept, Ignored: len(ignored), Stats: out.Stats, Errors: out.Errors, Data: out.Data,
	}
	if err := e.Store.SaveRun(ctx, r); err != nil {
		return nil, fmt.Errorf("save run: %w", err)
	}
	if err := e.Store.Prune(ctx, r.Command, e.Config.History); err != nil {
		return nil, fmt.Errorf("prune history: %w", err)
	}
	n, err := e.reconcile(ctx, s, r)
	if err != nil {
		return nil, err
	}
	return &Result{Run: r, TaskChanges: n}, nil
}

func (e *Engine) reconcile(ctx context.Context, s Scanner, r *run.Run) (int, error) {
	existing, err := e.Store.Todos(ctx, r.Command)
	if err != nil {
		return 0, fmt.Errorf("load tasks: %w", err)
	}
	derived := todo.Derive(r.Findings)
	if r.Scope != "" {
		existing = inScope(s, existing, derived)
	}
	changed := todo.Reconcile(r.Command, existing, derived, r.FinishedAt)
	if len(changed) == 0 {
		return 0, nil
	}
	if err := e.Store.SaveTodos(ctx, changed); err != nil {
		return 0, fmt.Errorf("save tasks: %w", err)
	}
	return len(changed), nil
}

// inScope keeps the stored tasks a scoped run may touch: those of checks the
// scanner owns, or, for scanners that do not say, only those the run saw.
func inScope(s Scanner, existing, derived []todo.Todo) []todo.Todo {
	owner, _ := s.(Owner)
	seen := map[string]bool{}
	for _, d := range derived {
		seen[d.Key] = true
	}
	var out []todo.Todo
	for _, t := range existing {
		if seen[t.Key] || (owner != nil && owner.Owns(t.Check)) {
			out = append(out, t)
		}
	}
	return out
}

// Analyze attaches an AI review to r and saves it. refresh skips the cache.
func (e *Engine) Analyze(ctx context.Context, r *run.Run, refresh bool) error {
	if e.AI == nil {
		return errors.New("ai review is not enabled")
	}
	level := llm.NormalizeLevel(e.Config.AI.AnalysisLevel)
	resp, err := e.AI.Ask(ctx, llm.AnalysisRequest(r, level, e.Config.AI.MaxDetails), refresh)
	if resp == nil {
		return err
	}
	r.Analysis = &run.Analysis{Text: resp.Text, Model: resp.Model, Level: level, CostUSD: resp.CostUSD,
		Cached: resp.Cached, CreatedAt: resp.CreatedAt}
	if r.ID != 0 {
		if uerr := e.Store.UpdateAnalysis(ctx, r.ID, r.Analysis); uerr != nil && err == nil {
			err = fmt.Errorf("save ai review: %w", uerr)
		}
	}
	return err
}
