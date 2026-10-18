// Package todo turns findings into a prioritized task list and reconciles it
// with the user's status changes across rescans.
package todo

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

// Priority orders tasks.
type Priority string

const (
	High       Priority = "high"
	Medium     Priority = "medium"
	Low        Priority = "low"
	Suggestion Priority = "suggestion"
)

// Priorities lists priorities from most to least urgent.
var Priorities = []Priority{High, Medium, Low, Suggestion}

// Rank orders priorities: higher is more urgent.
func (p Priority) Rank() int {
	switch p {
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Suggestion:
		return 1
	}
	return 0
}

// ParsePriority accepts a priority name or its first letter.
func ParsePriority(s string) (Priority, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "h":
		return High, nil
	case "medium", "med", "m":
		return Medium, nil
	case "low", "l":
		return Low, nil
	case "suggestion", "suggest", "s":
		return Suggestion, nil
	}
	return "", fmt.Errorf("unknown priority %q (want high, medium, low or suggestion)", s)
}

// Status is where a task stands.
type Status string

const (
	Open       Status = "open"
	InProgress Status = "in_progress"
	Done       Status = "done"
	WontDo     Status = "wont_do"
	// Resolved is set by the scanner when the finding behind a task is gone.
	Resolved Status = "resolved"
)

// Statuses lists every status in workflow order.
var Statuses = []Status{Open, InProgress, Done, WontDo, Resolved}

// Closed reports whether the task needs no further attention.
func (s Status) Closed() bool { return s == Done || s == WontDo || s == Resolved }

// Label is the human form of a status.
func (s Status) Label() string {
	switch s {
	case InProgress:
		return "in progress"
	case WontDo:
		return "won't do"
	}
	return string(s)
}

// ParseStatus accepts status names in several spellings.
func ParseStatus(s string) (Status, error) {
	switch strings.NewReplacer("-", "", "_", "", " ", "", "'", "").Replace(strings.ToLower(strings.TrimSpace(s))) {
	case "open", "o", "reopen", "todo":
		return Open, nil
	case "inprogress", "progress", "wip", "p", "started":
		return InProgress, nil
	case "done", "d", "complete", "completed", "fixed":
		return Done, nil
	case "wontdo", "wont", "w", "skip", "ignore":
		return WontDo, nil
	case "resolved", "r":
		return Resolved, nil
	}
	return "", fmt.Errorf("unknown status %q (want open, in-progress, done, wont-do or resolved)", s)
}

// Source says where a task came from.
type Source string

const (
	FromFinding   Source = "finding"
	FromAggregate Source = "aggregate"
	Manual        Source = "manual"
)

// Todo is one task.
type Todo struct {
	ID         int64     `json:"id"`
	Key        string    `json:"key"`
	Command    string    `json:"command"`
	Check      string    `json:"check,omitempty"`
	Title      string    `json:"title"`
	Hint       string    `json:"hint,omitempty"`
	Details    []string  `json:"details,omitempty"`
	Priority   Priority  `json:"priority"`
	Status     Status    `json:"status"`
	Source     Source    `json:"source"`
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
}

// PriorityFor maps a finding to a task priority. Info issues return "" because
// they are rolled up per check by Derive.
func PriorityFor(f finding.Finding) Priority {
	if f.IsSuggestion() {
		return Suggestion
	}
	switch f.Severity {
	case finding.Critical, finding.Error:
		return High
	case finding.Warning:
		return Medium
	case finding.Notice:
		return Low
	}
	return ""
}

// AggregateKey is the task key for a check's rolled-up info findings.
func AggregateKey(command, check string) string { return command + ":" + check + ":*" }

// GroupKey is the task key for the info findings of one finding.Group.
func GroupKey(command, check, group string) string { return command + ":" + check + ":" + group + ":*" }

// Derive builds the task list a set of findings calls for. Each issue or
// suggestion gets its own task; info issues get one low-priority task per check
// asking whether the items can be deleted or ignored, or one per group when
// the finding names one.
func Derive(fs []finding.Finding) []Todo {
	var out []Todo
	seen := map[string]int{}
	type agg struct {
		command, check string
		group          *finding.Group
		items          []string
	}
	aggs := map[string]*agg{}
	var aggOrder []string

	for _, f := range fs {
		p := PriorityFor(f)
		if p == "" {
			k := AggregateKey(f.Command, f.Check)
			if f.Group != nil {
				k = GroupKey(f.Command, f.Check, f.Group.ID)
			}
			a, ok := aggs[k]
			if !ok {
				a = &agg{command: f.Command, check: f.Check, group: f.Group}
				aggs[k] = a
				aggOrder = append(aggOrder, k)
			}
			item := f.Subject
			if f.Message != "" && f.Message != f.Subject {
				item += ": " + f.Message
			}
			a.items = append(a.items, item)
			continue
		}
		t := Todo{
			Key: f.Key(), Command: f.Command, Check: f.Check, Title: titleFor(f),
			Hint: f.Hint, Details: f.Details, Priority: p, Status: Open, Source: FromFinding,
		}
		if i, dup := seen[t.Key]; dup {
			// Two findings share a key: keep one task at the higher priority.
			if p.Rank() > out[i].Priority.Rank() {
				out[i].Priority = p
			}
			out[i].Details = append(out[i].Details, t.Title)
			continue
		}
		seen[t.Key] = len(out)
		out = append(out, t)
	}
	for _, k := range aggOrder {
		a := aggs[k]
		noun := "items"
		if len(a.items) == 1 {
			noun = "item"
		}
		t := Todo{
			Key: k, Command: a.command, Check: a.check, Priority: Low, Status: Open, Source: FromAggregate,
			Title:   fmt.Sprintf("Review %d %s from %s: resolve them, or add the check to ignore", len(a.items), noun, a.check),
			Hint:    fmt.Sprintf("ignore with %q or %q in the audit config", a.command+":"+a.check, a.check),
			Details: a.items,
		}
		if a.group != nil {
			t.Title = a.group.Title
			if a.group.Hint != "" {
				t.Hint = a.group.Hint
			}
		}
		out = append(out, t)
	}
	return out
}

func titleFor(f finding.Finding) string {
	switch {
	case f.Subject == "":
		return f.Message
	case f.Message == "":
		return f.Subject
	case strings.HasPrefix(f.Message, f.Subject):
		// Only a leading subject is dropped; one mentioned mid-sentence
		// ("membership in adm ...") does not name the task on its own.
		return f.Message
	default:
		return f.Subject + ": " + f.Message
	}
}

// Reconcile merges freshly derived tasks for one command into the stored ones
// and returns every task that must be written (new or changed).
//
//   - A new key becomes an open task.
//   - A known key refreshes its title, hint, details and priority. A resolved
//     or done task whose finding is still present reopens; won't-do stays.
//   - A stored, scanner-made task whose key is gone becomes resolved, unless
//     the user marked it won't do.
//
// Manual tasks and tasks of other commands are never touched.
func Reconcile(command string, existing, derived []Todo, now time.Time) []Todo {
	byKey := map[string]Todo{}
	for _, t := range existing {
		if t.Command == command && t.Source != Manual {
			byKey[t.Key] = t
		}
	}
	var changed []Todo
	present := map[string]bool{}
	for _, d := range derived {
		present[d.Key] = true
		old, ok := byKey[d.Key]
		if !ok {
			d.CreatedAt, d.UpdatedAt, d.LastSeenAt = now, now, now
			changed = append(changed, d)
			continue
		}
		t := old
		t.Title, t.Hint, t.Details, t.Priority, t.Check, t.Source = d.Title, d.Hint, d.Details, d.Priority, d.Check, d.Source
		t.LastSeenAt = now
		if t.Status == Resolved || t.Status == Done {
			t.Status = Open
			t.ResolvedAt = time.Time{}
			t.UpdatedAt = now
		}
		changed = append(changed, t)
	}
	for _, old := range existing {
		if old.Command != command || old.Source == Manual || present[old.Key] {
			continue
		}
		if old.Status == WontDo || old.Status == Resolved {
			continue
		}
		old.Status = Resolved
		old.ResolvedAt, old.UpdatedAt = now, now
		changed = append(changed, old)
	}
	return changed
}

// Sort orders tasks: open work first, then by priority, command and title.
func Sort(ts []Todo) {
	sort.SliceStable(ts, func(i, j int) bool {
		a, b := ts[i], ts[j]
		if a.Status.Closed() != b.Status.Closed() {
			return !a.Status.Closed()
		}
		if (a.Status == InProgress) != (b.Status == InProgress) {
			return a.Status == InProgress
		}
		if a.Priority.Rank() != b.Priority.Rank() {
			return a.Priority.Rank() > b.Priority.Rank()
		}
		if a.Command != b.Command {
			return a.Command < b.Command
		}
		return a.ID < b.ID
	})
}

// Filter selects tasks for display.
type Filter struct {
	Command    string
	Priorities []Priority
	Statuses   []Status
	ShowClosed bool
	Search     string
}

// Apply returns the tasks that pass the filter.
func (f Filter) Apply(ts []Todo) []Todo {
	var out []Todo
	q := strings.ToLower(f.Search)
	for _, t := range ts {
		if f.Command != "" && t.Command != f.Command {
			continue
		}
		if len(f.Priorities) > 0 && !contains(f.Priorities, t.Priority) {
			continue
		}
		if len(f.Statuses) > 0 {
			if !contains(f.Statuses, t.Status) {
				continue
			}
		} else if !f.ShowClosed && t.Status.Closed() {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(t.Title+" "+t.Key+" "+t.Note), q) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func contains[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
