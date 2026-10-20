package core

import (
	"context"
	"encoding/json"

	"github.com/njhoffman/audit/internal/ai"
	"github.com/njhoffman/audit/internal/progress"
)

// AIScanner reports on AI tooling and projects.
type AIScanner struct {
	Options ai.Options
}

// Command implements Scanner.
func (*AIScanner) Command() string { return ai.Command }

// Scope implements Scanner.
func (*AIScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *AIScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	d, fs, stats, errs, err := ai.Scan(ctx, s.Options, rep)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Stats: stats, Data: data, Errors: errs}, nil
}
