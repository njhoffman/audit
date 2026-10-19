package core

import (
	"context"
	"encoding/json"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/progress"
)

// FilesScanner measures disk use and finds reclaimable space.
type FilesScanner struct {
	Options files.Options
}

// NewFiles builds the files scanner from the config.
func NewFiles(cfg *config.Config, env *exec.Env) *FilesScanner {
	fc := cfg.Files
	expand := func(ps []string) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = env.Expand(p)
		}
		return out
	}
	return &FilesScanner{Options: files.Options{Env: env, Roots: expand(fc.Roots), Exclude: expand(fc.Exclude),
		Downloads: env.Expand(fc.Downloads), LargeMB: fc.LargeMB, DupMinMB: fc.DupMinMB, CacheMinMB: fc.CacheMinMB,
		BuildMinMB: fc.BuildMinMB, OrphanMinMB: fc.OrphanMinMB, DownloadsMinMB: fc.DownloadsMinMB, StaleAfter: fc.StaleAfter, OldDownloads: fc.OldDownloads,
		HashLimit: fc.HashLimitGB << 30, Top: fc.Top}}
}

// Command implements Scanner.
func (*FilesScanner) Command() string { return files.Command }

// Scope implements Scanner.
func (*FilesScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *FilesScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	o := s.Options
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	d, fs, stats, errs, err := files.Scan(ctx, o, rep)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Stats: stats, Data: data, Errors: errs}, nil
}
