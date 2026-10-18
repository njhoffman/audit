// Package system runs the host scanners (processes, services, accounts, logs
// and program configs) and converts their results into audit findings.
package system

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scan"
	"github.com/njhoffman/audit/internal/scan/logs"
	"github.com/njhoffman/audit/internal/scan/procs"
	"github.com/njhoffman/audit/internal/scan/programs"
	"github.com/njhoffman/audit/internal/scan/services"
	"github.com/njhoffman/audit/internal/scan/users"
)

// Command is the audit command name used in finding keys.
const Command = "system"

// Part is one scanner of the system audit.
type Part struct {
	Kind string
	Scan func(ctx context.Context) (*scan.Result, error)
}

// Kinds lists every part in scan order.
var Kinds = []string{"procs", "services", "users", "logs", "programs"}

// Options configures the parts built by NewScanner.
type Options struct {
	Only        []string // part kinds to run; empty runs all
	LogSources  []string // logs sources; empty uses the scanner default
	JournalArgs string   // journalctl passthrough flags
	Programs    []string // program analyzers; empty runs all
	LogMaxLines int      // lines read per log source; 0 uses the scanner default
	LogPatterns int      // normalized patterns reported per source; 0 uses the default
	Procs       procs.Options
	Services    services.Options
}

// Scanner runs the configured parts in order.
type Scanner struct {
	Parts    []Part
	Progress progress.Reporter
}

// NewScanner builds a Scanner over the real host scanners.
func NewScanner(o Options) (*Scanner, error) {
	only := map[string]bool{}
	for _, k := range o.Only {
		k = strings.TrimSpace(k)
		if !contains(Kinds, k) {
			return nil, fmt.Errorf("unknown system part %q (want %s)", k, strings.Join(Kinds, ", "))
		}
		only[k] = true
	}
	sources, err := logs.ParseSources(o.LogSources)
	if err != nil {
		return nil, fmt.Errorf("system.logs: %w", err)
	}
	progs, err := programs.ParsePrograms(o.Programs)
	if err != nil {
		return nil, fmt.Errorf("system programs: %w", err)
	}
	logOpts := logs.DefaultOptions()
	if len(sources) > 0 {
		logOpts.Sources = sources
	}
	if o.JournalArgs != "" {
		logOpts.JournalArgs = o.JournalArgs
	}
	if o.LogMaxLines > 0 {
		logOpts.MaxLines = o.LogMaxLines
	}
	if o.LogPatterns > 0 {
		logOpts.TopBuckets = o.LogPatterns
	}
	procOpts := procs.DefaultOptions()
	if o.Procs != (procs.Options{}) {
		procOpts = o.Procs
	}
	svcOpts := services.DefaultOptions()
	if o.Services != (services.Options{}) {
		svcOpts = o.Services
	}
	progOpts := programs.DefaultOptions()
	if len(progs) > 0 {
		progOpts.Programs = progs
	}

	all := []Part{
		{"procs", func(ctx context.Context) (*scan.Result, error) { return procs.Scan(ctx, procOpts) }},
		{"services", func(ctx context.Context) (*scan.Result, error) {
			return services.Scan(ctx, svcOpts)
		}},
		{"users", func(ctx context.Context) (*scan.Result, error) { return users.Scan(ctx, users.DefaultOptions()) }},
		{"logs", func(ctx context.Context) (*scan.Result, error) { return logs.Scan(ctx, logOpts) }},
		{"programs", func(ctx context.Context) (*scan.Result, error) { return programs.Scan(ctx, progOpts) }},
	}
	s := &Scanner{}
	for _, p := range all {
		if len(only) == 0 || only[p.Kind] {
			s.Parts = append(s.Parts, p)
		}
	}
	return s, nil
}

// Scope describes which parts ran, so saved results are only reused for a
// matching selection. It is empty when every part ran.
func (s *Scanner) Scope() string {
	if len(s.Parts) == len(Kinds) {
		return ""
	}
	kinds := make([]string, len(s.Parts))
	for i, p := range s.Parts {
		kinds[i] = p.Kind
	}
	return strings.Join(kinds, ",")
}

// Data is the persisted payload of a system run: each part's raw summary.
type Data struct {
	Parts map[string]map[string]any `json:"parts"`
}

// Result is a finished system scan.
type Result struct {
	Findings []finding.Finding
	Stats    []run.Stat
	Errors   []string
	Data     Data
}

// RawData encodes the payload for run.Run.Data.
func (r *Result) RawData() json.RawMessage {
	b, _ := json.Marshal(r.Data)
	return b
}

// Scan runs every part. A part that fails is recorded in Errors and the
// remaining parts still run; a cancelled context stops the scan.
func (s *Scanner) Scan(ctx context.Context) (*Result, error) {
	rep := s.Progress
	if rep == nil {
		rep = progress.Nop
	}
	defer rep.Done()

	res := &Result{Data: Data{Parts: map[string]map[string]any{}}}
	rep.Phase("scanning system", len(s.Parts))
	for _, p := range s.Parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sr, err := safeScan(ctx, p)
		rep.Step(p.Kind)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", p.Kind, err))
			continue
		}
		res.Findings = append(res.Findings, Convert(p.Kind, sr.Findings)...)
		res.Stats = append(res.Stats, Stats(p.Kind, sr.Summary)...)
		res.Errors = append(res.Errors, summaryErrors(p.Kind, sr.Summary)...)
		res.Data.Parts[p.Kind] = sr.Summary
	}
	finding.Sort(res.Findings)
	return res, nil
}

func safeScan(ctx context.Context, p Part) (r *scan.Result, err error) {
	defer func() {
		if v := recover(); v != nil {
			r, err = nil, fmt.Errorf("scanner crashed: %v", v)
		}
	}()
	r, err = p.Scan(ctx)
	if err == nil && r == nil {
		err = fmt.Errorf("scanner returned no result")
	}
	return r, err
}

// Convert maps scanner findings to audit findings. The check id is
// "<kind>.<check>"; program findings, whose subjects read "prog: what", get
// "programs.<prog>" with the remainder as subject.
func Convert(kind string, in []scan.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(in))
	for _, f := range in {
		check, subject := f.Check, f.Subject
		if check == "" && kind == "programs" {
			if prog, rest, ok := strings.Cut(subject, ": "); ok {
				check, subject = prog, rest
			}
		}
		id := kind
		if check != "" {
			id += "." + strings.ReplaceAll(check, "-", "_")
		}
		out = append(out, finding.Finding{
			Command:  Command,
			Check:    id,
			Severity: severity(f.Severity),
			Kind:     finding.Issue,
			Subject:  subject,
			Message:  f.Detail,
		})
	}
	return out
}

func severity(s scan.Severity) finding.Severity {
	switch s {
	case scan.SeverityCritical:
		return finding.Critical
	case scan.SeverityError:
		return finding.Error
	case scan.SeverityWarning:
		return finding.Warning
	case scan.SeverityNotice:
		return finding.Notice
	}
	return finding.Info
}

// Stats flattens the scalar parts of a scanner summary into report stats.
// Lists of records and nested objects stay in Data only; flat maps of
// scalars render as "k=v" pairs.
func Stats(kind string, summary map[string]any) []run.Stat {
	generic := normalize(summary)
	keys := make([]string, 0, len(generic))
	for k := range generic {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []run.Stat
	for _, k := range keys {
		if k == "errors" {
			continue
		}
		if v, ok := statValue(generic[k]); ok {
			out = append(out, run.Stat{Group: kind, Name: strings.ReplaceAll(k, "_", " "), Value: v})
		}
	}
	return out
}

// normalize round-trips through JSON so typed summaries become plain maps,
// slices and scalars.
func normalize(summary map[string]any) map[string]any {
	b, err := json.Marshal(summary)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

const maxListed = 8

func statValue(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, x != ""
	case bool:
		if x {
			return "yes", true
		}
		return "no", true
	case float64:
		return scalar(x), true
	case []any:
		if len(x) == 0 {
			return "none", true
		}
		strs := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return fmt.Sprintf("%d", len(x)), true
			}
			strs = append(strs, s)
		}
		if len(strs) > maxListed {
			return fmt.Sprintf("%s (+%d more)", strings.Join(strs[:maxListed], ", "), len(strs)-maxListed), true
		}
		return strings.Join(strs, ", "), true
	case map[string]any:
		if len(x) == 0 {
			return "none", true
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			switch e := x[k].(type) {
			case float64:
				pairs = append(pairs, k+"="+scalar(e))
			case string:
				pairs = append(pairs, k+"="+e)
			case bool:
				pairs = append(pairs, fmt.Sprintf("%s=%t", k, e))
			default:
				return "", false
			}
		}
		return strings.Join(pairs, ", "), true
	}
	return "", false
}

func scalar(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.1f", f)
}

// summaryErrors lifts per-source read failures (the logs summary's "errors"
// map) into run errors so they are not lost in Data.
func summaryErrors(kind string, summary map[string]any) []string {
	raw, ok := normalize(summary)["errors"].(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s %s: %v", kind, k, raw[k]))
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
