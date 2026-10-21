// Package run defines the persisted result of one audit command invocation.
package run

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

// Run is everything one scan produced. Data carries a command-specific payload
// (the package inventory, for example) that the command's list view decodes.
type Run struct {
	ID         int64             `json:"id"`
	Command    string            `json:"command"`
	Scope      string            `json:"scope,omitempty"`
	Host       string            `json:"host"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Findings   []finding.Finding `json:"findings"`
	Ignored    int               `json:"ignored"`
	Stats      []Stat            `json:"stats,omitempty"`
	Errors     []string          `json:"errors,omitempty"`
	Data       json.RawMessage   `json:"data,omitempty"`
	Analysis   *Analysis         `json:"analysis,omitempty"`
}

// Stat is one labelled number or fact shown in a report's summary section.
// Value is the headline, a number where there is one; Note qualifies it.
// Extra marks a line only the expanded view shows, such as the counts of a
// shell other than the user's.
type Stat struct {
	Group string `json:"group,omitempty"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
	Extra bool   `json:"extra,omitempty"`
}

// Analysis is an LLM review attached to a run.
type Analysis struct {
	Text      string    `json:"text"`
	Model     string    `json:"model"`
	Level     string    `json:"level"`
	CostUSD   float64   `json:"cost_usd"`
	Cached    bool      `json:"cached"`
	CreatedAt time.Time `json:"created_at"`
}

// Duration is how long the scan took.
func (r *Run) Duration() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// Counts tallies the run's findings by severity.
func (r *Run) Counts() finding.Counts { return finding.Count(r.Findings) }

// Age is how long ago the scan finished, relative to now.
func (r *Run) Age(now time.Time) time.Duration { return now.Sub(r.FinishedAt) }

// Freshness grades saved results by age.
type Freshness int

const (
	Fresh Freshness = iota
	Stale           // older than the warn threshold: still shown, flagged
	Old             // older than the old threshold: flagged loudly
)

// FreshnessOf grades age against the warn and old thresholds. A threshold of
// zero or less never trips.
func FreshnessOf(age, warn, old time.Duration) Freshness {
	switch {
	case old > 0 && age >= old:
		return Old
	case warn > 0 && age >= warn:
		return Stale
	}
	return Fresh
}

// Ago is HumanAge as a phrase: "just now" or "3h ago".
func Ago(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return HumanAge(d) + " ago"
}

// HumanAge renders a duration as a short age: "just now", "5m", "3h", "2d",
// "6w".
func HumanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return fmt.Sprintf("%dw", int(d/(7*24*time.Hour)))
}
