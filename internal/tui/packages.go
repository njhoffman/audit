package tui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/njhoffman/audit/internal/keys"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
)

// pkgScreen is the package inventory: one row per package across managers,
// outdated ones only unless all is set. Marked packages (by Key) are what
// the update action hands to audit packages update; with none marked it
// takes the row under the cursor.
type pkgScreen struct {
	all     []packages.Item // every package, in manager then name order
	rows    []packages.Item // after the outdated filter
	showAll bool
	marked  map[string]bool
	cursor  int
	offset  int
	height  int
	loaded  bool
}

type packagesMsg struct {
	items []packages.Item
	err   error
}

type updateMsg struct{ err error }

func (m *Model) loadPackages() tea.Cmd {
	return func() tea.Msg {
		as, err := m.b.Packages(m.ctx)
		var items []packages.Item
		for _, a := range as {
			items = append(items, a.Items...)
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Manager != items[j].Manager {
				return items[i].Manager < items[j].Manager
			}
			return items[i].Name < items[j].Name
		})
		return packagesMsg{items, err}
	}
}

func (m *Model) openPackages() tea.Cmd {
	m.screen = screenPackages
	if m.pkg.marked == nil {
		m.pkg.marked = map[string]bool{}
	}
	m.layout()
	return m.loadPackages()
}

// filterPackages applies the outdated filter, keeping the cursor in range.
func (m *Model) filterPackages() {
	p := &m.pkg
	p.rows = p.rows[:0]
	for _, it := range p.all {
		if p.showAll || it.Gap.Behind() {
			p.rows = append(p.rows, it)
		}
	}
	p.cursor = min(p.cursor, max(0, len(p.rows)-1))
	p.follow()
}

func (p *pkgScreen) follow() {
	switch {
	case p.cursor < p.offset:
		p.offset = p.cursor
	case p.cursor >= p.offset+p.height:
		p.offset = p.cursor - p.height + 1
	}
	p.offset = max(0, min(p.offset, len(p.rows)-p.height))
}

func (p *pkgScreen) move(n int) {
	p.cursor = max(0, min(len(p.rows)-1, p.cursor+n))
	p.follow()
}

// targets are the refs the update action runs: the marked packages that
// are still listed, else the one under the cursor.
func (m *Model) updateTargets() []string {
	var out []string
	for _, it := range m.pkg.all {
		if m.pkg.marked[it.Key()] {
			out = append(out, it.Manager+":"+it.Name)
		}
	}
	if len(out) == 0 && m.pkg.cursor < len(m.pkg.rows) {
		it := m.pkg.rows[m.pkg.cursor]
		out = append(out, it.Manager+":"+it.Name)
	}
	return out
}

func (m *Model) packagesKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := &m.pkg
	switch {
	case m.is(k, keys.Down):
		p.move(1)
	case m.is(k, keys.Up):
		p.move(-1)
	case m.is(k, keys.PageDown):
		p.move(p.height)
	case m.is(k, keys.PageUp):
		p.move(-p.height)
	case m.is(k, keys.HalfPageDown):
		p.move(p.height / 2)
	case m.is(k, keys.HalfPageUp):
		p.move(-p.height / 2)
	case m.is(k, keys.Top):
		p.move(-len(p.rows))
	case m.is(k, keys.Bottom):
		p.move(len(p.rows))
	case m.is(k, keys.ToggleAll):
		p.showAll = !p.showAll
		m.filterPackages()
	case m.is(k, keys.Mark):
		if p.cursor < len(p.rows) {
			key := p.rows[p.cursor].Key()
			p.marked[key] = !p.marked[key]
			if !p.marked[key] {
				delete(p.marked, key)
			}
			p.move(1)
		}
	case m.is(k, keys.Update):
		return m, m.updatePackages()
	}
	return m, nil
}

// updatePackages hands the terminal to audit packages update for the
// targets, with its own plan, question and sudo prompt; when it exits the
// packages are rescanned and the screen reloaded.
func (m *Model) updatePackages() tea.Cmd {
	if m.busy != "" {
		m.setStatus("wait for "+m.busy+" to finish", true)
		return nil
	}
	refs := m.updateTargets()
	if len(refs) == 0 {
		return nil
	}
	c, err := m.b.UpdateSession(m.ctx, refs)
	if err != nil {
		m.setStatus(err.Error(), true)
		return nil
	}
	return tea.ExecProcess(c, func(err error) tea.Msg { return updateMsg{err} })
}

func (m *Model) packagesView() string {
	p := &m.pkg
	if !p.loaded {
		return faintStyle.Render("  loading...")
	}
	if len(p.all) == 0 {
		return "\n  No saved packages run." + m.press(keys.Back, "go back")
	}
	if len(p.rows) == 0 {
		return "\n  Every package is up to date." + m.press(keys.ToggleAll, "list them all")
	}
	pr := render.NewProfile(io.Discard, lipgloss.ColorProfile(), 0)
	now := m.now()
	type cells struct{ mark, manager, name, version, latest, gap, released string }
	lines := make([]cells, len(p.rows))
	w := cells{mark: " ", manager: "MANAGER", name: "NAME", version: "VERSION", latest: "LATEST", gap: "GAP", released: "RELEASED"}
	width := func(a, b string) string {
		if ansi.StringWidth(b) > ansi.StringWidth(a) {
			return b
		}
		return a
	}
	for i, it := range p.rows {
		latest, released := packages.LatestCells(it, now)
		c := cells{mark: " ", manager: it.Manager, name: truncCell(it.Name, 36), version: truncCell(it.Version, 20), latest: truncCell(latest, 24),
			gap: string(it.Gap), released: released}
		if p.marked[it.Key()] {
			c.mark = "*"
		}
		lines[i] = c
		w = cells{" ", width(w.manager, c.manager), width(w.name, c.name), width(w.version, c.version),
			width(w.latest, c.latest), width(w.gap, c.gap), width(w.released, c.released)}
	}
	pad := func(s, like string) string {
		return s + strings.Repeat(" ", max(0, ansi.StringWidth(like)-ansi.StringWidth(s)))
	}
	row := func(c cells) string {
		return c.mark + " " + pad(c.manager, w.manager) + "  " + pad(c.name, w.name) + "  " + pad(c.version, w.version) + "  " +
			pad(c.latest, w.latest) + "  " + pad(c.gap, w.gap) + "  " + c.released
	}
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(row(cells{" ", "MANAGER", "NAME", "VERSION", "LATEST", "GAP", "RELEASED"})) + "\n")
	end := min(len(p.rows), p.offset+p.height)
	for i := p.offset; i < end; i++ {
		line := clip(row(lines[i]), m.width)
		if i == p.cursor {
			line = cursorStyle.Render(line)
		} else if p.rows[i].Gap.Behind() {
			line = pr.GapStyle(p.rows[i]).Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// packagesLabel says what the screen lists.
func (m *Model) packagesLabel() string {
	p := &m.pkg
	what := fmt.Sprintf("%d outdated of %d", len(p.rows), len(p.all))
	if p.showAll {
		what = fmt.Sprintf("all %d", len(p.all))
	}
	if n := len(p.marked); n > 0 {
		what += fmt.Sprintf(", %d marked", n)
	}
	return what
}

// truncCell shortens s to at most n cells, ending in an ellipsis when cut, so one
// long version (apt's 1:2.3.4-5ubuntu6~22.04.1) does not push the columns
// after it off the screen.
func truncCell(s string, n int) string { return ansi.Truncate(s, n, "…") }
