package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
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
		paths = append(paths, historyPath(env, path))
	}
	return &HistoryScanner{Options: history.Options{Files: paths, HistDB: historyPath(env, h.HistDB), Session: sessionID(env), Patterns: h.Patterns, MaxLines: h.MaxLines, MaxBytes: h.MaxMB << 20}}
}

// historyPath makes a configured history path absolute: ~ and $VAR or
// ${VAR} are expanded, an unset XDG_* variable takes its default under the
// home directory, and a relative path is taken from the home directory
// (where audit runs commands), so it matches prune's absolute arguments.
func historyPath(env *exec.Env, p string) string {
	if p == "" {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = env.Expand(p[:1]) + p[1:]
	}
	p = os.Expand(p, func(k string) string {
		if strings.HasPrefix(k, "XDG_") && strings.HasSuffix(k, "_HOME") {
			return env.XDG(k)
		}
		if k == "HOME" {
			return env.Home
		}
		return env.Get(k)
	})
	if !filepath.IsAbs(p) {
		p = filepath.Join(env.Home, p)
	}
	return filepath.Clean(p)
}

func sessionID(env *exec.Env) int { n, _ := strconv.Atoi(env.Get("SESSION")); return n }

func (*HistoryScanner) Command() string { return "history" }
func (*HistoryScanner) Scope() string   { return "" }

func (s *HistoryScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	rep.Phase("checking shell history", 0)
	fs, files, entries, errs, err := history.Scan(ctx, s.Options)
	if err != nil {
		return nil, err
	}
	stats := []run.Stat{
		{Group: "history", Name: "files", Value: fmt.Sprint(files)},
		{Group: "history", Name: "entries", Value: fmt.Sprint(entries)},
	}
	host := s.Options.Host
	if host == "" {
		host, _ = os.Hostname()
	}
	if total, onHost, onSession, e := history.HistDBCounts(ctx, s.Options.HistDB, host, s.Options.Session); e == nil {
		stats = append(stats, run.Stat{Group: "history", Name: "histdb total entries", Value: fmt.Sprint(total)}, run.Stat{Group: "history", Name: "histdb this host", Value: fmt.Sprint(onHost)})
		if s.Options.Session != 0 {
			stats = append(stats, run.Stat{Group: "history", Name: "histdb this session", Value: fmt.Sprint(onSession)})
		} else {
			stats = append(stats, run.Stat{Group: "history", Name: "histdb this session", Value: "unavailable (SESSION is not set)"})
		}
		if total > entries {
			fs = append(fs, finding.Finding{Command: "history", Check: "history.histdb_behind", Subject: "histdb", Kind: finding.Issue, Severity: finding.Warning, Message: fmt.Sprintf("histdb has %d more entries than configured history files", total-entries), Hint: "Run audit history sync to rebuild the zsh history file from histdb."})
		}
	} else if !os.IsNotExist(e) {
		errs = append(errs, fmt.Sprintf("histdb: %v", e))
	}
	return &Outcome{Findings: fs, Errors: errs, Stats: stats}, nil
}
