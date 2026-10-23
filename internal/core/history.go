package core

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/history"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// HistoryScanner checks shell histories without saving command text.
type HistoryScanner struct{ Options history.Options }

// NewHistory expands configured paths using the scan environment.
func NewHistory(cfg *config.Config, env *exec.Env) *HistoryScanner {
	h := cfg.ShellHistory
	paths := make([]string, 0, len(h.Files))
	for _, path := range h.Files {
		path = strings.ReplaceAll(path, "$XDG_DATA_HOME", env.XDG("XDG_DATA_HOME"))
		paths = append(paths, filepath.Clean(env.Expand(path)))
	}
	return &HistoryScanner{Options: history.Options{Files: paths, Patterns: h.Patterns, MaxLines: h.MaxLines, MaxBytes: h.MaxMB << 20}}
}

func (*HistoryScanner) Command() string { return "history" }
func (*HistoryScanner) Scope() string   { return "" }

func (s *HistoryScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	rep.Phase("checking shell history", 0)
	fs, files, entries, errs, err := history.Scan(ctx, s.Options)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Errors: errs, Stats: []run.Stat{
		{Group: "history", Name: "files", Value: fmt.Sprint(files)},
		{Group: "history", Name: "entries", Value: fmt.Sprint(entries)},
	}}, nil
}
