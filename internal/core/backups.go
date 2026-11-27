package core

import (
	"context"
	"encoding/json"

	"github.com/njhoffman/audit/internal/backups"
	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

// BackupsScanner checks the workstation's backups.
type BackupsScanner struct {
	Options backups.Options
}

// NewBackups builds the backups scanner from the config.
func NewBackups(cfg *config.Config, env *exec.Env) *BackupsScanner {
	bc := cfg.Backups
	o := backups.Options{Env: env, Paths: bc.Paths, MaxAge: bc.MaxAge, DejaDup: bc.DejaDup}
	for _, s := range bc.Sources {
		o.Sources = append(o.Sources, backups.Source{Name: s.Name, Command: s.Command, Covers: s.Covers})
	}
	return &BackupsScanner{Options: o}
}

// Command implements Scanner.
func (*BackupsScanner) Command() string { return backups.Command }

// Scope implements Scanner.
func (*BackupsScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *BackupsScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	rep.Phase("checking backups", 0)
	res, err := backups.Scan(ctx, s.Options)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(res.Data)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: res.Findings, Stats: res.Stats, Data: data}, nil
}
