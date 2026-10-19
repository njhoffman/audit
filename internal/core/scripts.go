package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/scripts"
)

// DescStore holds cached script descriptions (implemented by *store.Store).
type DescStore interface {
	ScriptDescriptions(ctx context.Context) (map[string]string, error)
}

// ScriptsScanner inventories and checks scripts.
type ScriptsScanner struct {
	Options scripts.ScanOptions
	Descs   DescStore
}

// NewScripts builds the scripts scanner; root globs are expanded.
func NewScripts(cfg *config.Config, env *exec.Env) *ScriptsScanner {
	sc := cfg.Scripts
	var roots []string
	for _, r := range sc.Roots {
		p := env.Expand(r)
		if m, err := filepath.Glob(p); err == nil && len(m) > 0 {
			roots = append(roots, m...)
		} else {
			roots = append(roots, p)
		}
	}
	return &ScriptsScanner{Options: scripts.ScanOptions{Env: env, Options: scripts.Options{Roots: roots, MaxDepth: sc.MaxDepth,
		Exclude: sc.Exclude, MaxBytes: sc.MaxKB << 10}, StaleAfter: sc.StaleAfter,
		ShellcheckSeverity: cfg.Environment.Shellcheck.Severity, ShellcheckExclude: cfg.Environment.Shellcheck.Exclude}}
}

// Command implements Scanner.
func (*ScriptsScanner) Command() string { return scripts.Command }

// Scope implements Scanner.
func (*ScriptsScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *ScriptsScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	o := s.Options
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if s.Descs != nil {
		var err error
		if o.Descriptions, err = s.Descs.ScriptDescriptions(ctx); err != nil {
			return nil, err
		}
	}
	d, fs, stats, errs, err := scripts.Scan(ctx, o, rep)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Stats: stats, Data: data, Errors: errs}, nil
}
