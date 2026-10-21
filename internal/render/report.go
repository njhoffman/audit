package render

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// ReportOptions controls a full report.
type ReportOptions struct {
	Thresholds config.Thresholds
	// Saved marks results read back from the store rather than just scanned;
	// only saved results get an age banner.
	Saved  bool
	Filter finding.Filter
	// RescanHint is the command line that refreshes these results.
	RescanHint string
}

const defaultDetails = 5

// Banner returns the age notice for saved results, or "" for results that
// were just produced. Fresh results get a quiet line; stale ones a yellow
// warning; old ones a red box.
func (p *Printer) Banner(r *run.Run, th config.Thresholds, saved bool, hint string) string {
	if !saved {
		return ""
	}
	age := r.Age(p.Now())
	when := r.FinishedAt.Local().Format("2006-01-02 15:04")
	rescan := ""
	if hint != "" {
		rescan = fmt.Sprintf(" Run `%s` to rescan.", hint)
	}
	switch run.FreshnessOf(age, th.Warn, th.Old) {
	case run.Old:
		msg := fmt.Sprintf("OUTDATED: these results are %s old (scanned %s).%s", run.HumanAge(age), when, rescan)
		box := p.style().Bold(true).Foreground(lipgloss.Color("9")).
			Border(lipgloss.ThickBorder()).BorderForeground(lipgloss.Color("9")).Padding(0, 1)
		if p.Width > 10 && ansi.StringWidth(msg)+4 > p.Width {
			box = box.Width(p.Width - 2)
		}
		return box.Render(msg)
	case run.Stale:
		return p.fg("11").Bold(true).Render(
			fmt.Sprintf("! Saved results are %s old (scanned %s).%s", run.HumanAge(age), when, rescan))
	}
	return p.faint().Render(fmt.Sprintf("Saved results from %s (%s).", run.Ago(age), when))
}

// Header prints the run's title line, age banner and severity counts.
func (p *Printer) Header(r *run.Run, o ReportOptions) {
	title := p.bold().Foreground(lipgloss.Color("12")).Render(p.glyphs().Icon(r.Command) + "audit " + r.Command)
	meta := []string{r.Host, r.FinishedAt.Local().Format("2006-01-02 15:04"),
		"took " + r.Duration().Round(100*time.Millisecond).String()}
	if r.Scope != "" {
		meta = append(meta, "scope "+r.Scope)
	}
	p.printf("%s  %s\n", title, p.faint().Render(strings.Join(meta, "  ")))
	if b := p.Banner(r, o.Thresholds, o.Saved, o.RescanHint); b != "" {
		p.println(b)
	}
	line := p.counts(r.Counts())
	if r.Ignored > 0 {
		line += p.faint().Render(fmt.Sprintf("  (%d ignored)", r.Ignored))
	}
	p.println(line)
}

// Brief prints the header and the summary statistics only.
func (p *Printer) Brief(r *run.Run, o ReportOptions) {
	p.Header(r, o)
	if len(r.Stats) > 0 {
		p.println("")
		p.stats(r.Stats)
	}
}

// Report prints everything about a run: header, stats, errors, issues,
// suggestions and the AI review.
func (p *Printer) Report(r *run.Run, o ReportOptions) {
	p.Header(r, o)

	if len(r.Stats) > 0 {
		p.printf("\n%s\n", p.heading("Summary"))
		p.stats(r.Stats)
	}
	if len(r.Errors) > 0 {
		p.printf("\n%s\n", p.heading("Scan errors"))
		for _, e := range r.Errors {
			p.println(perLine(p.fg("9"), p.wrap("- "+e, 2)))
		}
	}

	shown := o.Filter.Apply(r.Findings)
	var issues, suggestions []finding.Finding
	for _, f := range shown {
		if f.IsSuggestion() {
			suggestions = append(suggestions, f)
		} else {
			issues = append(issues, f)
		}
	}
	if hidden := len(r.Findings) - len(shown); hidden > 0 {
		p.println(p.faint().Render(fmt.Sprintf("\n%d finding(s) hidden by filters.", hidden)))
	}
	if len(issues) > 0 {
		p.printf("\n%s\n", p.heading("Issues"))
		p.findings(issues)
	}
	if len(suggestions) > 0 {
		p.printf("\n%s\n", p.heading("Suggestions"))
		p.findings(suggestions)
	}
	if r.Analysis != nil && r.Analysis.Text != "" {
		p.printf("\n%s  %s\n", p.heading("AI review"), p.faint().Render(analysisMeta(r.Analysis, p.Now())))
		p.println(p.markdown(r.Analysis.Text))
	}
}

// AI prints an AI answer under a heading with its model, cache age and cost.
func (p *Printer) AI(title, model string, cached bool, at time.Time, cost float64, md string) {
	meta := analysisMeta(&run.Analysis{Model: model, Cached: cached, CreatedAt: at, CostUSD: cost}, p.Now())
	p.printf("%s  %s\n", p.heading(title), p.faint().Render(meta))
	p.println(p.markdown(md))
}

func analysisMeta(a *run.Analysis, now time.Time) string {
	var parts []string
	for _, s := range []string{a.Model, a.Level} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if a.Cached {
		parts = append(parts, "cached "+run.Ago(now.Sub(a.CreatedAt)))
	}
	if a.CostUSD > 0 {
		parts = append(parts, fmt.Sprintf("$%.4f", a.CostUSD))
	}
	return strings.Join(parts, "  ")
}

func (p *Printer) markdown(md string) string {
	style := "dark"
	if p.r.ColorProfile() == termenv.Ascii {
		style = "notty"
	}
	wrap := 0
	if p.Width > 2 {
		wrap = p.Width - 2
	}
	tr, err := glamour.NewTermRenderer(glamour.WithStandardStyle(style), glamour.WithWordWrap(wrap))
	if err != nil {
		return md
	}
	out, err := tr.Render(md)
	if err != nil {
		return md
	}
	return trimPadding(strings.TrimRight(out, "\n"))
}

// trailingPad matches the spaces (and the SGR codes between them) glamour
// pads every line with up to the wrap width.
var trailingPad = regexp.MustCompile(`(?:\x1b\[[0-9;]*m| )+$`)

// trimPadding strips that padding from each line, ending a styled line with
// a reset so no attribute leaks into the next one.
func trimPadding(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		t := trailingPad.ReplaceAllString(l, "")
		if t != l && strings.Contains(l, "\x1b[") {
			t += "\x1b[0m"
		}
		lines[i] = t
	}
	return strings.Join(lines, "\n")
}

// numeric matches a count or a measure ("791", "0.42s", "21.9 GB", "30%"),
// which the summary right-aligns.
var numeric = regexp.MustCompile(`^-?[0-9][0-9.,]*( ?[KMGTP]?i?B|%|ms|s)?$`)

// stats prints the summary: group headings, then each line's dim label,
// its value (numbers bold and right-aligned) and a dimmer note. Collapsed
// skips the Extra lines and packs each group onto as few lines as fit.
func (p *Printer) stats(stats []run.Stat) {
	if p.Collapsed {
		p.compactStats(stats)
		return
	}
	shown := make([]run.Stat, 0, len(stats))
	nameW, numW := 0, 0
	for _, s := range stats {
		if s.Extra && p.Collapsed {
			continue
		}
		s.Name, s.Value, s.Note = p.tilde(s.Name), p.tilde(s.Value), p.tilde(s.Note)
		shown = append(shown, s)
		nameW = max(nameW, ansi.StringWidth(s.Name))
		if numeric.MatchString(s.Value) {
			numW = max(numW, ansi.StringWidth(s.Value))
		}
	}
	group := "\x00"
	for _, s := range shown {
		if s.Group != group {
			group = s.Group
			if group != "" {
				p.println("  " + p.bold().Render(p.glyphs().Icon(group)+group))
			}
		}
		indent := 4
		if group == "" {
			indent = 2
		}
		line := strings.Repeat(" ", indent) + p.label().Render(padRight(s.Name, nameW)) + "  "
		if numeric.MatchString(s.Value) {
			line += p.bold().Render(padLeft(s.Value, numW))
		} else {
			value := s.Value
			if s.Note != "" {
				value = padRight(value, numW)
			}
			line += value
		}
		if s.Note != "" {
			line += "  " + p.faint().Render(s.Note)
		}
		if p.Width > 0 {
			line = truncate(line, p.Width)
		}
		p.println(line)
	}
}

// compactStats prints each group's stats after its name, "540 aliases" for
// a number and "firewall ufw" for text, wrapping under the first stat when
// the line is full. Notes are left to the expanded view.
func (p *Printer) compactStats(stats []run.Stat) {
	type group struct {
		name  string
		items []string
	}
	var groups []group
	for _, s := range stats {
		if s.Extra {
			continue
		}
		if len(groups) == 0 || groups[len(groups)-1].name != s.Group {
			groups = append(groups, group{name: s.Group})
		}
		item := p.label().Render(p.tilde(s.Name)) + " " + p.tilde(s.Value)
		if numeric.MatchString(s.Value) {
			item = p.bold().Render(s.Value) + " " + p.label().Render(p.tilde(s.Name))
		}
		g := &groups[len(groups)-1]
		g.items = append(g.items, item)
	}
	groupW := 0
	for _, g := range groups {
		groupW = max(groupW, ansi.StringWidth(p.glyphs().Icon(g.name)+g.name))
	}
	indent := 2 + groupW + 2
	for _, g := range groups {
		line := "  " + p.bold().Render(padRight(p.glyphs().Icon(g.name)+g.name, groupW)) + "  "
		width, first := indent, true
		for _, it := range g.items {
			w := ansi.StringWidth(it)
			if !first && p.Width > 0 && width+2+w > p.Width {
				p.println(line)
				line, width, first = strings.Repeat(" ", indent), indent, true
			}
			if !first {
				line += "  "
				width += 2
			}
			if p.Width > 0 && width+w > p.Width {
				it = truncate(it, p.Width-width)
			}
			line += it
			width += ansi.StringWidth(it)
			first = false
		}
		p.println(line)
	}
}

func (p *Printer) findings(fs []finding.Finding) {
	if p.Collapsed {
		for _, f := range fs {
			p.println(p.findingLine(f))
		}
		return
	}
	for _, f := range fs {
		head := p.sevBadge(f.Severity) + " " + p.fg("12").Render(f.Check)
		if f.Subject != "" {
			head += "  " + p.bold().Render(p.tilde(f.Subject))
		}
		p.println(head)
		if f.Message != "" {
			p.println(p.wrap(p.tilde(f.Message), 9))
		}
		if f.Hint != "" {
			p.println(perLine(p.fg("10"), p.wrap("hint: "+p.tilde(f.Hint), 9)))
		}
		details := f.Details
		shown := p.Details
		if shown <= 0 {
			shown = defaultDetails
		}
		if !p.AllDetails && len(details) > shown {
			details = details[:shown]
		}
		for _, d := range details {
			p.println(perLine(p.faint(), p.wrap("- "+p.tilde(d), 11)))
		}
		if more := len(f.Details) - len(details); more > 0 {
			p.println(p.faint().Render(fmt.Sprintf("%s(+%d more; display.details sets how many show)", strings.Repeat(" ", 11), more)))
		}
		p.println(p.faint().Render(strings.Repeat(" ", 9) + "key " + f.Key()))
	}
}

// findingLine is a collapsed finding: its severity marker, check and the
// first line of its message (or its subject), cut to the width.
func (p *Printer) findingLine(f finding.Finding) string {
	text := firstLine(f.Message)
	if text == "" {
		text = f.Subject
	}
	line := "  " + p.sevMark(f.Severity) + " " + p.sevStyle(f.Severity).UnsetBackground().Render(f.Check) + "  " + p.tilde(text)
	if p.Width > 0 {
		line = truncate(line, p.Width)
	}
	return line
}

// List prints one line per finding: severity, check, subject and message.
func (p *Printer) List(r *run.Run, o ReportOptions) {
	p.Header(r, o)
	fs := o.Filter.Apply(r.Findings)
	if len(fs) == 0 {
		return
	}
	p.println("")
	rows := make([][]string, len(fs))
	for i, f := range fs {
		subject := f.Subject
		if f.IsSuggestion() {
			subject = "(suggestion) " + subject
		}
		rows[i] = []string{string(f.Severity), f.Check, p.tilde(subject), p.tilde(firstLine(f.Message))}
	}
	p.table([]column{{title: "SEVERITY"}, {title: "CHECK"}, {title: "SUBJECT"}, {title: "MESSAGE", flex: true}},
		rows, func(row, col int) lipgloss.Style {
			switch col {
			case 0:
				return p.sevStyle(fs[row].Severity)
			case 1:
				return p.fg("12")
			}
			return p.style()
		})
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
