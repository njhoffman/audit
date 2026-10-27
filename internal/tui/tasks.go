package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/todo"
)

// taskTable is the task list: one row per task with its priority, status
// and command colored and marked, a cursor and a scroll offset. When split
// is between 0 and the number of tasks, a divider follows the first split
// rows (a section's tasks above the rest).
type taskTable struct {
	tasks  []todo.Todo
	split  int
	cursor int
	offset int // first visible line
	height int // lines for rows, under the header
}

// Column widths; the title takes the rest of the line.
const (
	idW     = 5
	prioW   = 12 // marker, space, "suggestion"
	statusW = 11
	cmdW    = 14 // icon, space, "environment"
	gapW    = 2
)

func (t *taskTable) divided() bool { return t.split > 0 && t.split < len(t.tasks) }

// line is the display line of row i.
func (t *taskTable) line(i int) int {
	if t.divided() && i >= t.split {
		return i + 1
	}
	return i
}

func (t *taskTable) lines() int { return t.line(len(t.tasks)-1) + 1 }

func (t *taskTable) setRows(ts []todo.Todo, split int) {
	t.tasks, t.split = ts, split
	t.cursor = min(t.cursor, max(0, len(ts)-1))
	t.follow()
}

func (t *taskTable) setHeight(h int) {
	t.height = max(1, h)
	t.follow()
}

// move shifts the cursor by n rows, staying in the list.
func (t *taskTable) move(n int) {
	t.cursor = max(0, min(len(t.tasks)-1, t.cursor+n))
	t.follow()
}

func (t *taskTable) top() {
	t.cursor = 0
	t.follow()
}

func (t *taskTable) bottom() { t.move(len(t.tasks)) }

// follow scrolls so the cursor's row is visible, and the divider with it
// when the cursor is on the first row under it.
func (t *taskTable) follow() {
	if len(t.tasks) == 0 {
		t.cursor, t.offset = 0, 0
		return
	}
	l := t.line(t.cursor)
	if t.divided() && t.cursor == t.split {
		l--
	}
	if l < t.offset {
		t.offset = l
	}
	if end := t.line(t.cursor); end >= t.offset+t.height {
		t.offset = end - t.height + 1
	}
	t.offset = max(0, min(t.offset, t.lines()-t.height))
}

func (t *taskTable) selected() *todo.Todo {
	if t.cursor < 0 || t.cursor >= len(t.tasks) {
		return nil
	}
	return &t.tasks[t.cursor]
}

// view draws the header and the visible rows at width. The selected row is
// one plain highlighted bar; the others are colored per cell.
func (t *taskTable) view(width int, g render.Glyphs, home string) string {
	p := render.NewProfile(io.Discard, lipgloss.ColorProfile(), 0)
	titleW := max(10, width-idW-prioW-statusW-cmdW-4*gapW)
	gap := strings.Repeat(" ", gapW)
	var b strings.Builder
	header := cell("ID", idW) + gap + cell("PRIORITY", prioW) + gap + cell("STATUS", statusW) + gap + cell("COMMAND", cmdW) + gap + "TITLE"
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(header) + "\n")
	b.WriteString(faintStyle.Render(strings.Repeat("─", max(1, width))) + "\n")
	for l := t.offset; l < min(t.offset+t.height, t.lines()); l++ {
		i := l
		if t.divided() && l >= t.split {
			if l == t.split {
				b.WriteString(faintStyle.Render(divider(width)) + "\n")
				continue
			}
			i = l - 1
		}
		tk := t.tasks[i]
		marker := g.Priority[tk.Priority]
		if marker != "" {
			marker += " "
		}
		cells := []string{cell(fmt.Sprintf("%d", tk.ID), idW), cell(marker+string(tk.Priority), prioW),
			cell(tk.Status.Label(), statusW), cell(g.Icon(tk.Command)+tk.Command, cmdW), cell(render.Tilde(tk.Title, home), titleW)}
		if i == t.cursor {
			b.WriteString(cursorStyle.Render(ansi.Truncate(strings.Join(cells, gap), width, "")) + "\n")
			continue
		}
		titleStyle := lipgloss.NewStyle()
		if tk.Status.Closed() {
			titleStyle = faintStyle
		}
		b.WriteString(faintStyle.Render(cells[0]) + gap + p.PriorityStyle(tk.Priority).Render(cells[1]) + gap +
			p.StatusStyle(tk.Status).Render(cells[2]) + gap + taskCmdStyle.Render(cells[3]) + gap + titleStyle.Render(cells[4]) + "\n")
	}
	return b.String()
}

var taskCmdStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

// cell is s cut or padded to w cells.
func cell(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	return s + strings.Repeat(" ", max(0, w-ansi.StringWidth(s)))
}

// divider is the faint line between a section's tasks and the rest.
func divider(width int) string {
	label := " other commands "
	left := 2
	return strings.Repeat("─", left) + label + strings.Repeat("─", max(0, width-left-len(label)))
}
