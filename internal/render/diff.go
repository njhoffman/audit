package render

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// Diff prints what changed in findings from run from to run to: a heading
// naming both runs, the counts, then a table each of added, resolved and
// changed findings, most serious first.
func (p *Printer) Diff(from, to *run.Run, d finding.Delta) {
	now := p.Now()
	at := func(r *run.Run) string {
		return fmt.Sprintf("run %d, %s (%s ago)", r.ID, r.FinishedAt.Local().Format("2006-01-02 15:04"), run.HumanAge(now.Sub(r.FinishedAt)))
	}
	name := to.Command
	if to.Scope != "" {
		name += " (" + to.Scope + ")"
	}
	p.println(p.bold().Render(name+": findings since "+at(from)) + p.faint().Render(" -> "+at(to)))
	if d.Empty() {
		p.println(fmt.Sprintf("No change: the same %d finding(s).", d.Unchanged))
		return
	}
	p.println(fmt.Sprintf("%d added, %d resolved, %d changed severity, %d unchanged.", len(d.Added), len(d.Resolved), len(d.Changed), d.Unchanged))
	section := func(title string, fs []finding.Finding, from []finding.Severity) {
		if len(fs) == 0 {
			return
		}
		p.println("")
		p.println(p.bold().Render(fmt.Sprintf("%s (%d)", title, len(fs))))
		rows := make([][]string, len(fs))
		for i, f := range fs {
			sev := string(f.Severity)
			if from != nil {
				sev = string(from[i]) + " -> " + sev
			}
			rows[i] = []string{sev, f.Check, p.tilde(f.Subject), p.tilde(firstLine(f.Message))}
		}
		p.table([]column{{title: "SEVERITY"}, {title: "CHECK"}, {title: "SUBJECT"}, {title: "MESSAGE", flex: true}},
			rows, func(row, col int) lipgloss.Style {
				switch col {
				case 0:
					if title == "Resolved" {
						return p.faint()
					}
					return p.sevStyle(fs[row].Severity)
				case 1:
					return p.fg("12")
				}
				return p.style()
			})
	}
	section("Added", d.Added, nil)
	section("Resolved", d.Resolved, nil)
	changed := make([]finding.Finding, len(d.Changed))
	fromSev := make([]finding.Severity, len(d.Changed))
	for i, c := range d.Changed {
		changed[i], fromSev[i] = c.Finding, c.From
	}
	section("Changed severity", changed, fromSev)
}
