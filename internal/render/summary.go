package render

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// CommandStatus is one row of the cross-command summary.
type CommandStatus struct {
	Command    string
	Latest     *store.RunInfo // nil when the command has never run
	Thresholds config.Thresholds
	// Open counts open and in-progress tasks by priority.
	Open map[todo.Priority]int
}

// Summary prints when each command last ran, how fresh that is, what it
// found and how many tasks are still open.
func (p *Printer) Summary(rows []CommandStatus) {
	now := p.Now()
	cols := []column{{title: "COMMAND"}, {title: "LAST RUN"}, {title: "AGE"}, {title: "FINDINGS"}, {title: "TASKS"}}
	cells := make([][]string, len(rows))
	styles := make([][]lipgloss.Style, len(rows))
	for i, r := range rows {
		st := []lipgloss.Style{p.fg("12").Bold(true), p.style(), p.style(), p.style(), p.style()}
		if r.Latest == nil {
			cells[i] = []string{r.Command, "never", "-", "-", taskCounts(r.Open)}
			st[1], st[2] = p.faint(), p.faint()
		} else {
			age := now.Sub(r.Latest.FinishedAt)
			cells[i] = []string{r.Command, r.Latest.FinishedAt.Local().Format("2006-01-02 15:04"),
				run.HumanAge(age), plainCounts(r.Latest.Counts), taskCounts(r.Open)}
			switch run.FreshnessOf(age, r.Thresholds.Warn, r.Thresholds.Old) {
			case run.Old:
				st[2] = p.fg("9").Bold(true)
			case run.Stale:
				st[2] = p.fg("11")
			default:
				st[2] = p.fg("10")
			}
			if w := r.Latest.Counts.Worst(); w != "" {
				st[3] = p.sevStyle(w)
			}
		}
		if total(r.Open) > 0 && r.Open[todo.High] > 0 {
			st[4] = p.prioStyle(todo.High)
		}
		styles[i] = st
	}
	p.table(cols, cells, func(row, col int) lipgloss.Style { return styles[row][col] })
}

// CountsText abbreviates finding counts, worst first ("2 err 5 warn"), or
// "none".
func CountsText(c finding.Counts) string { return plainCounts(c) }

// TasksText abbreviates open task counts by priority, or "-".
func TasksText(m map[todo.Priority]int) string { return taskCounts(m) }

func plainCounts(c finding.Counts) string {
	if c.Total() == 0 {
		return "none"
	}
	var parts []string
	for _, s := range finding.Severities {
		if n := c[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, abbrev(s)))
		}
	}
	return strings.Join(parts, " ")
}

func abbrev(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "crit"
	case finding.Error:
		return "err"
	case finding.Warning:
		return "warn"
	}
	return string(s)
}

func taskCounts(m map[todo.Priority]int) string {
	if total(m) == 0 {
		return "-"
	}
	var parts []string
	for _, pr := range todo.Priorities {
		if n := m[pr]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, pr))
		}
	}
	return strings.Join(parts, " ")
}

func total(m map[todo.Priority]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// OpenCounts tallies tasks that are not closed, by priority.
func OpenCounts(ts []todo.Todo) map[todo.Priority]int {
	m := map[todo.Priority]int{}
	for _, t := range ts {
		if !t.Status.Closed() {
			m[t.Priority]++
		}
	}
	return m
}

// Todos prints tasks as a table.
func (p *Printer) Todos(ts []todo.Todo) {
	if len(ts) == 0 {
		p.println(p.faint().Render("No tasks match."))
		return
	}
	rows := make([][]string, len(ts))
	for i, t := range ts {
		rows[i] = []string{fmt.Sprintf("%d", t.ID), string(t.Priority), t.Status.Label(), t.Command, t.Title}
	}
	p.table([]column{{title: "ID"}, {title: "PRIORITY"}, {title: "STATUS"}, {title: "COMMAND"}, {title: "TITLE", flex: true}},
		rows, func(row, col int) lipgloss.Style {
			switch col {
			case 0:
				return p.faint()
			case 1:
				return p.prioStyle(ts[row].Priority)
			case 2:
				return p.statusStyle(ts[row].Status)
			case 3:
				return p.fg("12")
			}
			if ts[row].Status.Closed() {
				return p.faint()
			}
			return p.style()
		})
}

// Todo prints one task with every field.
func (p *Printer) Todo(t todo.Todo) {
	p.printf("%s %s\n", p.faint().Render(fmt.Sprintf("#%d", t.ID)), p.bold().Render(t.Title))
	field := func(name, value string, st lipgloss.Style) {
		if value != "" {
			p.printf("  %s %s\n", p.faint().Render(padRight(name, 9)), st.Render(value))
		}
	}
	field("priority", string(t.Priority), p.prioStyle(t.Priority))
	field("status", t.Status.Label(), p.statusStyle(t.Status))
	field("command", t.Command, p.fg("12"))
	field("key", t.Key, p.style())
	field("source", string(t.Source), p.style())
	field("created", stamp(t.CreatedAt), p.style())
	field("updated", stamp(t.UpdatedAt), p.style())
	field("seen", stamp(t.LastSeenAt), p.style())
	field("resolved", stamp(t.ResolvedAt), p.style())
	field("hint", t.Hint, p.fg("10"))
	field("note", t.Note, p.style())
	for _, d := range t.Details {
		p.println(perLine(p.faint(), p.wrap("- "+d, 4)))
	}
	if len(todo.Locations(t)) > 0 && t.ID > 0 {
		p.printf("  %s %s\n", p.faint().Render(padRight("editor", 9)), fmt.Sprintf("vim -q <(audit todo show %d -l)", t.ID))
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// History prints saved runs, one per line.
func (p *Printer) History(runs []store.RunInfo) {
	if len(runs) == 0 {
		p.println(p.faint().Render("No saved runs."))
		return
	}
	now := p.Now()
	rows := make([][]string, len(runs))
	for i, r := range runs {
		scope := r.Scope
		if scope == "" {
			scope = "-"
		}
		rows[i] = []string{fmt.Sprintf("%d", r.ID), r.Command, scope, r.FinishedAt.Local().Format("2006-01-02 15:04"),
			run.HumanAge(now.Sub(r.FinishedAt)), r.Duration.Round(100 * time.Millisecond).String(), plainCounts(r.Counts)}
	}
	p.table([]column{{title: "ID"}, {title: "COMMAND"}, {title: "SCOPE"}, {title: "FINISHED"}, {title: "AGE"},
		{title: "TOOK"}, {title: "FINDINGS", flex: true}}, rows, func(row, col int) lipgloss.Style {
		switch col {
		case 0:
			return p.faint()
		case 1:
			return p.fg("12")
		case 6:
			if w := runs[row].Counts.Worst(); w != "" {
				return p.sevStyle(w)
			}
		}
		return p.style()
	})
}
