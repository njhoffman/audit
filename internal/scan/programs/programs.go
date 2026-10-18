// Package programs analyzes per-program configuration files (sshd, nginx,
// ...) and surfaces common misconfigurations as findings.
package programs

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

// Program identifies one analyzed program.
type Program string

const (
	ProgramSSHD     Program = "sshd"
	ProgramNginx    Program = "nginx"
	ProgramPostgres Program = "postgres"
	ProgramApache   Program = "apache"
	ProgramDocker   Program = "docker"
	ProgramCron     Program = "cron"
)

// AllPrograms is the stable enumeration of supported programs.
var AllPrograms = []Program{
	ProgramSSHD, ProgramNginx, ProgramPostgres,
	ProgramApache, ProgramDocker, ProgramCron,
}

// ProgramResult is the per-program contribution to a programs scan.
type ProgramResult struct {
	Program  Program        `json:"program"`
	Skipped  bool           `json:"skipped,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	Notes    []string       `json:"notes,omitempty"`
	Findings []scan.Finding `json:"findings,omitempty"`
	Source   string         `json:"source,omitempty"`
}

// Options selects which programs to analyze.
type Options struct {
	Programs []Program
}

func DefaultOptions() Options {
	return Options{Programs: AllPrograms}
}

// analyzer is the per-program contract.
type analyzer func(ctx context.Context) ProgramResult

// analyzers maps each Program to its implementation.
var analyzers = map[Program]analyzer{
	ProgramSSHD:     analyzeSSHD,
	ProgramNginx:    analyzeNginx,
	ProgramPostgres: analyzePostgres,
	ProgramApache:   analyzeApache,
	ProgramDocker:   analyzeDocker,
	ProgramCron:     analyzeCron,
}

// Scan runs every requested analyzer and returns a single scan.Result. A
// program that isn't installed/configured produces a Skipped result with a
// reason rather than an error.
func Scan(ctx context.Context, opts Options) (*scan.Result, error) {
	if len(opts.Programs) == 0 {
		opts = DefaultOptions()
	}
	started := time.Now()

	per := []ProgramResult{}
	allFindings := []scan.Finding{}
	skipped := []string{}

	for _, p := range opts.Programs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fn, ok := analyzers[p]
		if !ok {
			per = append(per, ProgramResult{
				Program: p, Skipped: true, Reason: "no analyzer registered",
			})
			skipped = append(skipped, string(p))
			continue
		}
		r := fn(ctx)
		per = append(per, r)
		allFindings = append(allFindings, r.Findings...)
		if r.Skipped {
			skipped = append(skipped, string(p))
		}
	}

	sort.SliceStable(allFindings, func(i, j int) bool {
		return severityRank(allFindings[i].Severity) > severityRank(allFindings[j].Severity)
	})

	res := &scan.Result{
		Kind:       "programs",
		StartedAt:  started,
		FinishedAt: time.Now(),
		Summary: map[string]any{
			"programs":    programNames(opts.Programs),
			"per_program": per,
			"skipped":     skipped,
		},
		Findings: allFindings,
	}
	return res, nil
}

func programNames(p []Program) []string {
	out := make([]string, len(p))
	for i, x := range p {
		out[i] = string(x)
	}
	return out
}

func severityRank(s scan.Severity) int {
	switch s {
	case scan.SeverityCritical:
		return 5
	case scan.SeverityError:
		return 4
	case scan.SeverityWarning:
		return 3
	case scan.SeverityNotice:
		return 2
	case scan.SeverityInfo:
		return 1
	}
	return 0
}

// ParsePrograms validates a comma-separated user input. Unknown names
// produce an error so a typo doesn't get silently dropped.
func ParsePrograms(in []string) ([]Program, error) {
	if len(in) == 0 {
		return nil, nil
	}
	known := map[string]Program{}
	for _, p := range AllPrograms {
		known[string(p)] = p
	}
	out := make([]Program, 0, len(in))
	seen := map[Program]bool{}
	for _, name := range in {
		p, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown program %q (valid: %v)", name, programNames(AllPrograms))
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}
