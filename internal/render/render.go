// Package render writes audit results to a terminal: full reports, compact
// lists, the cross-command summary and task lists.
package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/todo"
)

// Printer renders to one writer with one color profile.
type Printer struct {
	w io.Writer
	r *lipgloss.Renderer
	// Width is the terminal width used for wrapping and truncation; 0 means
	// unlimited (output is not a terminal).
	Width int
	// Verbose shows the full tags column of the package list.
	Verbose bool
	// Details is how many detail lines a finding shows; 0 means the default.
	Details int
	// Home is shown as ~ in paths; "" leaves paths alone.
	Home string
	// Collapsed prints one line per finding and leaves out the Extra
	// summary lines.
	Collapsed bool
	// AllDetails shows every detail line instead of the first Details.
	AllDetails bool
	// Glyphs are the markers and icons; the zero value means UnicodeGlyphs.
	Glyphs Glyphs
	// Now is the clock used for ages.
	Now func() time.Time
}

// New returns a Printer on w. Colors follow the terminal unless noColor is
// set; output that is not a terminal is never colored.
func New(w io.Writer, noColor bool, width int) *Printer {
	r := lipgloss.NewRenderer(w)
	if noColor {
		r.SetColorProfile(termenv.Ascii)
	}
	return &Printer{w: w, r: r, Width: width, Now: time.Now}
}

// NewProfile returns a Printer on w that always uses the given color
// profile, for rendering into a buffer that ends up on a terminal.
func NewProfile(w io.Writer, profile termenv.Profile, width int) *Printer {
	r := lipgloss.NewRenderer(w)
	r.SetColorProfile(profile)
	return &Printer{w: w, r: r, Width: width, Now: time.Now}
}

func (p *Printer) printf(format string, a ...any) { _, _ = fmt.Fprintf(p.w, format, a...) }
func (p *Printer) println(s string)               { _, _ = fmt.Fprintln(p.w, s) }

func (p *Printer) style() lipgloss.Style { return p.r.NewStyle() }

func (p *Printer) fg(c string) lipgloss.Style { return p.style().Foreground(lipgloss.Color(c)) }

func (p *Printer) bold() lipgloss.Style  { return p.style().Bold(true) }
func (p *Printer) faint() lipgloss.Style { return p.fg("8") }

// label is the color of summary labels: dimmed, but less than faint.
func (p *Printer) label() lipgloss.Style { return p.fg("248") }

func (p *Printer) tilde(s string) string { return Tilde(s, p.Home) }

// Tilde replaces home with ~ wherever it starts a path in s: not inside a
// longer name (/home/nick2) or a deeper path (/mnt/home/nick).
func Tilde(s, home string) string {
	home = strings.TrimRight(home, "/")
	if home == "" || !strings.Contains(s, home) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, home)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := i + len(home)
		b.WriteString(s[:i])
		if (i == 0 || !pathByte(s[i-1])) && (j == len(s) || s[j] == '/' || !pathByte(s[j])) {
			b.WriteString("~")
		} else {
			b.WriteString(home)
		}
		s = s[j:]
	}
}

func pathByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.-/~", c) >= 0
}

// heading is a section title, after its icon when there is one.
func (p *Printer) heading(s string) string {
	return p.bold().Render(p.glyphs().Icon(s)) + p.bold().Underline(true).Render(s)
}

// Severity colors, shared with the HTML report's palette in spirit.
func (p *Printer) sevStyle(s finding.Severity) lipgloss.Style {
	switch s {
	case finding.Critical:
		return p.style().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("1"))
	case finding.Error:
		return p.fg("9").Bold(true)
	case finding.Warning:
		return p.fg("11")
	case finding.Notice:
		return p.fg("14")
	}
	return p.faint()
}

func (p *Printer) glyphs() Glyphs {
	if p.Glyphs.Severity == nil {
		return UnicodeGlyphs
	}
	return p.Glyphs
}

// sevMark is s's marker in its color; critical's badge background would be
// a block behind one character, so it gets the error red instead.
func (p *Printer) sevMark(s finding.Severity) string {
	st := p.sevStyle(s)
	if s == finding.Critical {
		st = p.fg("9").Bold(true)
	}
	return st.Render(p.glyphs().Severity[s])
}

func (p *Printer) sevBadge(s finding.Severity) string {
	label, width := strings.ToUpper(string(s)), 8
	if g := p.glyphs(); g.Nerd {
		label, width = g.Severity[s]+" "+label, 10
	}
	if s == finding.Critical {
		return p.sevStyle(s).Render(" " + label + " ")
	}
	return p.sevStyle(s).Render(padRight(label, width))
}

func (p *Printer) prioStyle(pr todo.Priority) lipgloss.Style {
	switch pr {
	case todo.High:
		return p.fg("9").Bold(true)
	case todo.Medium:
		return p.fg("11")
	case todo.Low:
		return p.fg("14")
	}
	return p.fg("12")
}

func (p *Printer) statusStyle(s todo.Status) lipgloss.Style {
	switch s {
	case todo.InProgress:
		return p.fg("13").Bold(true)
	case todo.Done, todo.Resolved:
		return p.fg("10")
	case todo.WontDo:
		return p.faint()
	}
	return p.style()
}

// counts renders "2 error  5 warning" with each part colored, skipping zeros.
func (p *Printer) counts(c finding.Counts) string {
	var parts []string
	for _, s := range finding.Severities {
		if n := c[s]; n > 0 {
			parts = append(parts, p.sevMark(s)+" "+p.sevStyle(s).Render(fmt.Sprintf("%d %s", n, s)))
		}
	}
	if len(parts) == 0 {
		return p.fg("10").Render("no findings")
	}
	return strings.Join(parts, "  ")
}

// wrap word-wraps s to the printer width minus indent and indents every line.
func (p *Printer) wrap(s string, indent int) string {
	pad := strings.Repeat(" ", indent)
	if p.Width <= indent+20 {
		return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
	}
	wrapped := ansi.Wrap(s, p.Width-indent, "")
	return pad + strings.ReplaceAll(wrapped, "\n", "\n"+pad)
}

// perLine styles each line of s on its own; Render on a multi-line string
// would pad every line to the widest one.
func perLine(st lipgloss.Style, s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = st.Render(l)
	}
	return strings.Join(lines, "\n")
}

// truncate shortens s to n cells with an ellipsis; n <= 0 leaves it alone.
func truncate(s string, n int) string {
	if n <= 0 || ansi.StringWidth(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return ansi.Truncate(s, n-1, "") + "…"
}

func padLeft(s string, n int) string {
	if w := ansi.StringWidth(s); w < n {
		return strings.Repeat(" ", n-w) + s
	}
	return s
}

func padRight(s string, n int) string {
	if w := ansi.StringWidth(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// column is one table column: a header and whether it absorbs leftover
// width by truncating (the last flexible column wins).
type column struct {
	title string
	flex  bool
}

// table prints rows aligned under headers. cell styles are applied after
// padding so color codes never disturb alignment. A flex column is truncated
// so the row fits the printer width.
func (p *Printer) table(cols []column, rows [][]string, style func(row, col int) lipgloss.Style) {
	const gap = 2
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = ansi.StringWidth(c.title)
	}
	for _, r := range rows {
		for i := range cols {
			if i < len(r) {
				if w := ansi.StringWidth(r[i]); w > widths[i] {
					widths[i] = w
				}
			}
		}
	}
	flex := -1
	for i, c := range cols {
		if c.flex {
			flex = i
		}
	}
	if flex >= 0 && p.Width > 0 {
		total := gap * (len(cols) - 1)
		for _, w := range widths {
			total += w
		}
		if over := total - p.Width; over > 0 {
			widths[flex] = max(widths[flex]-over, 8)
		}
	}
	line := func(cells []string, st func(col int) lipgloss.Style) string {
		var b strings.Builder
		for i := range cols {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			cell = truncate(cell, widths[i])
			if i < len(cols)-1 {
				cell = padRight(cell, widths[i]+gap)
			}
			b.WriteString(st(i).Render(cell))
		}
		return strings.TrimRight(b.String(), " ")
	}
	titles := make([]string, len(cols))
	for i, c := range cols {
		titles[i] = c.title
	}
	// A table with no titles is a key/value list and prints no header.
	if strings.Join(titles, "") != "" {
		p.println(line(titles, func(int) lipgloss.Style { return p.faint().Bold(true) }))
	}
	for ri, r := range rows {
		p.println(line(r, func(ci int) lipgloss.Style {
			if style == nil {
				return p.style()
			}
			return style(ri, ci)
		}))
	}
}
