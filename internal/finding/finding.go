// Package finding defines the result model shared by every audit command.
package finding

import (
	"fmt"
	"sort"
	"strings"
)

// Severity ranks how serious a finding is.
type Severity string

const (
	Info     Severity = "info"
	Notice   Severity = "notice"
	Warning  Severity = "warning"
	Error    Severity = "error"
	Critical Severity = "critical"
)

// Severities lists every severity from most to least serious.
var Severities = []Severity{Critical, Error, Warning, Notice, Info}

// Rank orders severities: higher is more serious. Unknown severities rank 0.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case Error:
		return 4
	case Warning:
		return 3
	case Notice:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// ParseSeverity accepts a severity name or a common abbreviation.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "i":
		return Info, nil
	case "notice", "n":
		return Notice, nil
	case "warning", "warn", "w":
		return Warning, nil
	case "error", "err", "e":
		return Error, nil
	case "critical", "crit", "c":
		return Critical, nil
	}
	return "", fmt.Errorf("unknown severity %q (want critical, error, warning, notice or info)", s)
}

// Kind separates problems from improvement ideas.
type Kind string

const (
	Issue      Kind = "issue"
	Suggestion Kind = "suggestion"
)

// Finding is one result of a check.
type Finding struct {
	Command  string   `json:"command"`
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Kind     Kind     `json:"kind"`
	Subject  string   `json:"subject"`
	Message  string   `json:"message"`
	Hint     string   `json:"hint,omitempty"`
	Details  []string `json:"details,omitempty"`
}

// Key identifies a finding across scans: command:check:subject.
func (f Finding) Key() string {
	return f.Command + ":" + f.Check + ":" + f.Subject
}

// IsSuggestion reports whether the finding is an improvement idea.
func (f Finding) IsSuggestion() bool { return f.Kind == Suggestion }

// Sort orders findings by severity (most serious first), then check, then subject.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Subject < b.Subject
	})
}

// Counts tallies findings by severity.
type Counts map[Severity]int

// Count tallies fs by severity.
func Count(fs []Finding) Counts {
	c := Counts{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

// Total returns the number of findings counted.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Worst returns the most serious severity present, or "" when empty.
func (c Counts) Worst() Severity {
	for _, s := range Severities {
		if c[s] > 0 {
			return s
		}
	}
	return ""
}

// Filter selects findings for display.
type Filter struct {
	MinSeverity Severity // "" keeps everything
	Check       string   // check id prefix, "" keeps everything
}

// Apply returns the findings that pass the filter, preserving order.
func (flt Filter) Apply(fs []Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if flt.MinSeverity != "" && f.Severity.Rank() < flt.MinSeverity.Rank() {
			continue
		}
		if flt.Check != "" && !strings.HasPrefix(f.Check, flt.Check) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Ignorer drops findings the user chose to silence. Each rule matches a full
// key (command:check:subject), a command-qualified check (command:check), or a
// bare check id.
type Ignorer struct {
	rules map[string]bool
}

// NewIgnorer builds an Ignorer from config rules.
func NewIgnorer(rules []string) Ignorer {
	m := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r = strings.TrimSpace(r); r != "" {
			m[r] = true
		}
	}
	return Ignorer{rules: m}
}

// Ignored reports whether f matches a rule.
func (ig Ignorer) Ignored(f Finding) bool {
	return ig.rules[f.Key()] || ig.rules[f.Command+":"+f.Check] || ig.rules[f.Check]
}

// Split partitions fs into kept and ignored findings.
func (ig Ignorer) Split(fs []Finding) (kept, ignored []Finding) {
	for _, f := range fs {
		if ig.Ignored(f) {
			ignored = append(ignored, f)
		} else {
			kept = append(kept, f)
		}
	}
	return kept, ignored
}
