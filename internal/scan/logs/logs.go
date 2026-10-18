// Package logs scans system logs (journal, dmesg, boot, auth, kern, misc),
// buckets entries by normalized pattern, and applies high-priority rules.
package logs

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

// Source identifies one log surface.
type Source string

const (
	SourceAuth    Source = "auth"
	SourceBoot    Source = "boot"
	SourceJournal Source = "journal"
	SourceDmesg   Source = "dmesg"
	SourceKern    Source = "kern"
	SourceMisc    Source = "misc"
)

// AllSources lists every source the spec mentions, in a stable order.
var AllSources = []Source{
	SourceAuth, SourceBoot, SourceJournal, SourceDmesg, SourceKern, SourceMisc,
}

// Entry is one parsed log line.
type Entry struct {
	Source    Source    `json:"source"`
	Timestamp time.Time `json:"timestamp,omitempty"`
	Host      string    `json:"host,omitempty"`
	Unit      string    `json:"unit,omitempty"`
	PID       string    `json:"pid,omitempty"`
	Message   string    `json:"message"`
	Raw       string    `json:"-"`
}

// SourceResult is the per-source contribution to a logs scan.
type SourceResult struct {
	Source       Source         `json:"source"`
	LinesRead    int            `json:"lines_read"`
	Buckets      []Bucket       `json:"top_buckets"`
	Findings     []scan.Finding `json:"findings"`
	Err          string         `json:"error,omitempty"`
	NotRunYet    bool           `json:"not_implemented_yet,omitempty"`
	UsedFallback string         `json:"used_fallback,omitempty"`
}

// Bucket aggregates entries that normalize to the same pattern.
type Bucket struct {
	Normalized string `json:"normalized"`
	Count      int    `json:"count"`
	Sample     string `json:"sample"`
}

// Options configures a logs scan.
type Options struct {
	Sources []Source

	// JournalArgs is the user-supplied passthrough string for journalctl,
	// e.g. "-p 4 -b -n 500 --no-pager". It is split on whitespace.
	JournalArgs string

	// TopBuckets is how many normalized patterns to report per source.
	TopBuckets int

	// MaxLines per source caps memory/log volume.
	MaxLines int
}

func DefaultOptions() Options {
	return Options{
		Sources:     []Source{SourceBoot, SourceDmesg, SourceJournal},
		JournalArgs: "-p 4 -b -n 500 --no-pager",
		TopBuckets:  10,
		MaxLines:    5000,
	}
}

// scanner is the per-source contract.
type scanner func(ctx context.Context, opts Options) (SourceResult, error)

// scanners maps each Source to its implementation. Sources without a
// scanner produce a NotRunYet=true SourceResult so the user sees them
// listed as skipped rather than silently dropped.
var scanners = map[Source]scanner{
	SourceJournal: scanJournal,
	SourceDmesg:   scanDmesg,
	SourceBoot:    scanBoot,
	SourceAuth:    scanAuth,
	SourceKern:    scanKern,
	SourceMisc:    scanMisc,
}

// Scan runs every requested source and produces a single scan.Result that
// bundles all of them. Per-source errors are surfaced in the SourceResult,
// not propagated to the caller, so partial reads still return a useful
// digest.
func Scan(ctx context.Context, opts Options) (*scan.Result, error) {
	if len(opts.Sources) == 0 {
		opts = DefaultOptions()
	}
	if opts.TopBuckets <= 0 {
		opts.TopBuckets = 10
	}
	if opts.MaxLines <= 0 {
		opts.MaxLines = 5000
	}

	started := time.Now()
	per := []SourceResult{}
	allFindings := []scan.Finding{}
	totalLines := 0

	for _, src := range opts.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fn, ok := scanners[src]
		if !ok {
			per = append(per, SourceResult{Source: src, NotRunYet: true})
			continue
		}
		sr, err := fn(ctx, opts)
		if err != nil {
			sr.Err = err.Error()
		}
		per = append(per, sr)
		allFindings = append(allFindings, sr.Findings...)
		totalLines += sr.LinesRead
	}

	sort.SliceStable(allFindings, func(i, j int) bool {
		return severityRank(allFindings[i].Severity) > severityRank(allFindings[j].Severity)
	})

	notRunYet := []string{}
	errored := map[string]string{}
	for _, sr := range per {
		if sr.NotRunYet {
			notRunYet = append(notRunYet, string(sr.Source))
		}
		if sr.Err != "" {
			errored[string(sr.Source)] = sr.Err
		}
	}

	res := &scan.Result{
		Kind:       "logs",
		StartedAt:  started,
		FinishedAt: time.Now(),
		Summary: map[string]any{
			"sources":             sourceNames(opts.Sources),
			"per_source":          per,
			"total_lines_read":    totalLines,
			"sources_not_run_yet": notRunYet,
			"errors":              errored,
		},
		Findings: allFindings,
	}
	return res, nil
}

func sourceNames(s []Source) []string {
	out := make([]string, len(s))
	for i, src := range s {
		out[i] = string(src)
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

// ParseSources turns a comma-separated user input into a validated slice.
// Unknown names produce an error so we don't silently drop a typo.
func ParseSources(in []string) ([]Source, error) {
	if len(in) == 0 {
		return nil, nil
	}
	known := map[string]Source{}
	for _, s := range AllSources {
		known[string(s)] = s
	}
	out := make([]Source, 0, len(in))
	seen := map[Source]bool{}
	for _, name := range in {
		s, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown log source %q (valid: %v)", name, sourceNames(AllSources))
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}
