package core

import (
	"context"
	"encoding/json"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/containers"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

// ContainersScanner checks docker and podman.
type ContainersScanner struct {
	Options containers.Options
}

// NewContainers builds the containers scanner from the config.
func NewContainers(cfg *config.Config, env *exec.Env) *ContainersScanner {
	cc := cfg.Containers
	return &ContainersScanner{Options: containers.Options{Env: env, Engines: cc.Engines, StoppedAfter: cc.StoppedAfter}}
}

// Command implements Scanner.
func (*ContainersScanner) Command() string { return containers.Command }

// Scope implements Scanner.
func (*ContainersScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *ContainersScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	rep.Phase("asking the container engines", 0)
	res, err := containers.Scan(ctx, s.Options)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(res.Data)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: res.Findings, Stats: res.Stats, Data: data}, nil
}
