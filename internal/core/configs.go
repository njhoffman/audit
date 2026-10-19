package core

import (
	"context"
	"encoding/json"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/configs"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
)

// ConfigsScanner checks user configuration.
type ConfigsScanner struct {
	Options configs.Options
}

// NewConfigs builds the configs scanner; invs are the saved package
// inventories used to name config owners.
func NewConfigs(cfg *config.Config, env *exec.Env, invs []packages.Inventory) *ConfigsScanner {
	cc := cfg.Configs
	roots := make([]string, len(cc.Roots))
	for i, r := range cc.Roots {
		roots[i] = env.Expand(r)
	}
	return &ConfigsScanner{Options: configs.Options{Env: env, Roots: roots, MaxDepth: cc.MaxDepth, Exclude: cc.Exclude,
		MaxBytes: cc.MaxKB << 10, Inventories: invs}}
}

// Command implements Scanner.
func (*ConfigsScanner) Command() string { return configs.Command }

// Scope implements Scanner.
func (*ConfigsScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *ConfigsScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	d, fs, stats, errs, err := configs.Scan(ctx, s.Options, rep)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Stats: stats, Data: data, Errors: errs}, nil
}
