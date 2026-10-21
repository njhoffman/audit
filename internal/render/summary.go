package render

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

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
	cc := NewCountColumns(rows)
	cols := []column{{title: "COMMAND"}, {title: "LAST RUN"}, {title: "AGE"}, {title: "FINDINGS"}, {title: "TASKS"}}
	cells := make([][]string, len(rows))
	styles := make([][]lipgloss.Style, len(rows))
	for i, r := range rows {
		st := []lipgloss.Style{p.fg("12").Bold(true), p.style(), p.style(), p.style(), p.style()}
		name := p.glyphs().Icon(r.Command) + r.Command
		if r.Latest == nil {
			cells[i] = []string{name, "never", "-", p.RunCounts(cc, r), p.TaskCounts(cc, r.Open)}
			st[1], st[2] = p.faint(), p.faint()
		} else {
			age := now.Sub(r.Latest.FinishedAt)
			cells[i] = []string{name, r.Latest.FinishedAt.Local().Format("2006-01-02 15:04"),
				run.HumanAge(age), p.RunCounts(cc, r), p.TaskCounts(cc, r.Open)}
			st[2] = p.ageStyle(age, r.Thresholds)
		}
		styles[i] = st
	}
	p.table(cols, cells, func(row, col int) lipgloss.Style { return styles[row][col] })
}

// ageStyle colors an age by its freshness.
func (p *Printer) ageStyle(age time.Duration, th config.Thresholds) lipgloss.Style {
	switch run.FreshnessOf(age, th.Warn, th.Old) {
	case run.Old:
		return p.fg("9").Bold(true)
	case run.Stale:
		return p.fg("11")
	}
	return p.fg("10")
}

// CountColumns lines finding and task counts up across rows: one
// sub-column per severity and priority that some row has, each as wide as
// its largest count.
type CountColumns struct {
	sev  []finding.Severity
	sevW map[finding.Severity]int
	pri  []todo.Priority
	priW map[todo.Priority]int
}

// NewCountColumns sizes the count sub-columns for rows.
func NewCountColumns(rows []CommandStatus) CountColumns {
	cc := CountColumns{sevW: map[finding.Severity]int{}, priW: map[todo.Priority]int{}}
	for _, r := range rows {
		if r.Latest != nil {
			for s, n := range r.Latest.Counts {
				if n > 0 {
					cc.sevW[s] = max(cc.sevW[s], len(fmt.Sprint(n)))
				}
			}
		}
		for pr, n := range r.Open {
			if n > 0 {
				cc.priW[pr] = max(cc.priW[pr], len(fmt.Sprint(n)))
			}
		}
	}
	for _, s := range finding.Severities {
		if cc.sevW[s] > 0 {
			cc.sev = append(cc.sev, s)
		}
	}
	for _, pr := range todo.Priorities {
		if cc.priW[pr] > 0 {
			cc.pri = append(cc.pri, pr)
		}
	}
	return cc
}

// RunCounts is the finding counts of r's latest run: aligned cells, a
// check mark when it found nothing, blank when it never ran.
func (p *Printer) RunCounts(cc CountColumns, r CommandStatus) string {
	switch {
	case r.Latest == nil:
		return ""
	case r.Latest.Counts.Total() == 0:
		mark := "✓"
		if p.glyphs().Nerd {
			mark = "\uf00c" // fa-check
		}
		return p.fg("10").Render(mark + " none")
	}
	return p.FindingCounts(cc, r.Latest.Counts)
}

// FindingCounts is c as aligned cells: each severity's marker and count in
// a muted shade of its color, blank where c has none.
func (p *Printer) FindingCounts(cc CountColumns, c finding.Counts) string {
	cells := make([]string, len(cc.sev))
	for i, s := range cc.sev {
		cells[i] = p.countCell(c[s], cc.sevW[s], p.glyphs().Severity[s], p.mutedSev(s))
	}
	return strings.TrimRight(strings.Join(cells, "  "), " ")
}

// TaskCounts is open as aligned cells, like FindingCounts, by priority.
func (p *Printer) TaskCounts(cc CountColumns, open map[todo.Priority]int) string {
	cells := make([]string, len(cc.pri))
	for i, pr := range cc.pri {
		cells[i] = p.countCell(open[pr], cc.priW[pr], p.glyphs().Priority[pr], p.prioStyle(pr).UnsetBold())
	}
	return strings.TrimRight(strings.Join(cells, "  "), " ")
}

func (p *Printer) countCell(n, width int, mark string, st lipgloss.Style) string {
	if n == 0 {
		return strings.Repeat(" ", ansi.StringWidth(mark)+1+width)
	}
	return st.Render(mark + " " + padLeft(fmt.Sprint(n), width))
}

// mutedSev is s's color without bold or the critical badge background.
func (p *Printer) mutedSev(s finding.Severity) lipgloss.Style {
	if s == finding.Critical {
		return p.fg("9")
	}
	return p.sevStyle(s).UnsetBold()
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
		rows[i] = []string{fmt.Sprintf("%d", t.ID), string(t.Priority), t.Status.Label(), t.Command, p.tilde(t.Title)}
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
	p.printf("%s %s\n", p.faint().Render(fmt.Sprintf("#%d", t.ID)), p.bold().Render(p.tilde(t.Title)))
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
	field("hint", p.tilde(t.Hint), p.fg("10"))
	field("note", t.Note, p.style())
	for _, d := range t.Details {
		p.println(perLine(p.faint(), p.wrap("- "+p.tilde(d), 4)))
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
