package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// FixesEmpty is what the fixes log says before anything was recorded.
const FixesEmpty = "Nothing recorded yet: tasks closing and successful updates, syncs and cleanups are logged as they happen."

// Fixes prints the fixes log: its totals, then the newest limit entries
// (all when limit is 0) with how many older ones were left out.
func (p *Printer) Fixes(as []store.Activity, limit int) {
	if len(as) == 0 {
		p.println(FixesEmpty)
		return
	}
	p.fixTotals(as)
	shown := as
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	now := p.Now()
	rows := make([][]string, len(shown))
	for i, x := range shown {
		what := x.Title
		if x.From != "" || x.To != "" {
			what += " " + x.From + " -> " + x.To
		}
		where := x.Command
		if where == "" {
			where = x.Kind
		}
		rows[i] = []string{x.At.Local().Format("2006-01-02 15:04"), run.HumanAge(now.Sub(x.At)), where, x.Action, string(x.Priority), what}
	}
	p.println("")
	p.Table([]string{"WHEN", "AGE", "COMMAND", "WHAT", "PRIORITY", "ITEM"}, rows)
	if len(shown) < len(as) {
		p.printf("%d older entries; audit history runs fixes -l 0 lists them all.\n", len(as)-len(shown))
	}
}

// FixTotals counts the log: tasks closed per command (won't do left out)
// by priority, tasks reopened, and action steps per kind.
type FixTotals struct {
	Closed   map[string]map[todo.Priority]int
	Reopened int
	Steps    map[string]int
}

// SumFixes totals as.
func SumFixes(as []store.Activity) FixTotals {
	t := FixTotals{Closed: map[string]map[todo.Priority]int{}, Steps: map[string]int{}}
	for _, x := range as {
		switch {
		case x.Kind == "task" && x.Action == "reopened":
			t.Reopened++
		case x.Kind == "task" && x.Action != string(todo.WontDo):
			if t.Closed[x.Command] == nil {
				t.Closed[x.Command] = map[todo.Priority]int{}
			}
			t.Closed[x.Command][x.Priority]++
		case x.Kind != "task":
			t.Steps[x.Kind]++
		}
	}
	return t
}

// StepsText is "3 package, 1 sync", by kind.
func (t FixTotals) StepsText() string {
	kinds := make([]string, 0, len(t.Steps))
	for k := range t.Steps {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%d %s", t.Steps[k], k)
	}
	return strings.Join(parts, ", ")
}

func (p *Printer) fixTotals(as []store.Activity) {
	t := SumFixes(as)
	cmds := make([]string, 0, len(t.Closed))
	for c := range t.Closed {
		cmds = append(cmds, c)
	}
	sort.Strings(cmds)
	var rows [][]string
	for _, c := range cmds {
		total := 0
		var parts []string
		for _, pr := range todo.Priorities {
			if n := t.Closed[c][pr]; n > 0 {
				total += n
				parts = append(parts, fmt.Sprintf("%d %s", n, pr))
			}
		}
		rows = append(rows, []string{c, fmt.Sprint(total), strings.Join(parts, ", ")})
	}
	if len(rows) > 0 {
		p.println("Tasks fixed (resolved or done):")
		p.Table([]string{"COMMAND", "FIXED", "BY PRIORITY"}, rows)
	}
	if s := t.StepsText(); s != "" {
		p.printf("Steps done: %s.\n", s)
	}
	if t.Reopened > 0 {
		p.printf("Reopened: %d task(s) came back after being fixed.\n", t.Reopened)
	}
}
