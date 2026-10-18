// Package tui is the interactive dashboard: an overview of every command's
// saved results, a scrollable report per command, rescans with a spinner and
// a task editor.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// Backend is what the UI needs from the application.
type Backend interface {
	Statuses(ctx context.Context) ([]render.CommandStatus, error)
	// Report renders the saved run of command at width; ok is false when
	// the command has never run.
	Report(ctx context.Context, command string, width int) (text string, ok bool, err error)
	// Rescan scans command and returns how many tasks changed.
	Rescan(ctx context.Context, command string) (int, error)
	Todos(ctx context.Context) ([]todo.Todo, error)
	SetStatus(ctx context.Context, id int64, s todo.Status) (todo.Todo, error)
	SetNote(ctx context.Context, id int64, note string) (todo.Todo, error)
	// Explain asks the AI about task id and renders the answer at width;
	// refresh skips the cache.
	Explain(ctx context.Context, id int64, width int, refresh bool) (string, error)
}

type screen int

const (
	screenDashboard screen = iota
	screenReport
	screenTodos
	// screenExplain shows an AI explanation of a task; esc returns to the
	// task list.
	screenExplain
)

// input is what the text field at the bottom of the task list is editing.
type input int

const (
	inputNone input = iota
	inputNote
	inputSearch
)

// Model is the Bubble Tea model.
type Model struct {
	ctx context.Context
	b   Backend
	now func() time.Time

	screen        screen
	standalone    bool // started on the task list; leaving it quits
	width, height int
	status        string
	statusErr     bool

	rows   []render.CommandStatus
	cursor int

	report       viewport.Model
	reportCmd    string
	reportLoaded bool

	busy    string // command being rescanned, "" when idle
	spinner spinner.Model

	explainID int64 // task shown on screenExplain

	tasks   []todo.Todo // after filtering
	all     []todo.Todo
	filter  todo.Filter
	table   table.Model
	input   input
	field   textinput.Model
	editing int64
}

// Option configures a Model.
type Option func(*Model)

// WithClock sets the clock used for ages.
func WithClock(now func() time.Time) Option { return func(m *Model) { m.now = now } }

// StartInTodos opens the task list first, filtered by f.
func StartInTodos(f todo.Filter) Option {
	return func(m *Model) { m.screen, m.filter, m.standalone = screenTodos, f, true }
}

// New returns a Model over b.
func New(ctx context.Context, b Backend, opts ...Option) *Model {
	m := &Model{ctx: ctx, b: b, now: time.Now, width: 80, height: 24,
		spinner: spinner.New(spinner.WithSpinner(spinner.Dot))}
	m.field = textinput.New()
	m.field.CharLimit = 500
	m.field.Cursor.SetMode(cursor.CursorStatic)
	m.table = table.New(table.WithFocused(true))
	st := table.DefaultStyles()
	st.Header = st.Header.Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	st.Selected = st.Selected.Foreground(lipgloss.Color("0")).Background(lipgloss.Color("12")).Bold(false)
	m.table.SetStyles(st)
	for _, o := range opts {
		o(m)
	}
	m.layout()
	return m
}

// Run starts the program on the terminal.
func Run(ctx context.Context, b Backend, opts ...Option) error {
	p := tea.NewProgram(New(ctx, b, opts...), tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	return err
}

type statusesMsg struct {
	rows []render.CommandStatus
	err  error
}

type reportMsg struct {
	command string
	text    string
	ok      bool
	err     error
}

type rescanMsg struct {
	command string
	changed int
	err     error
}

type explainMsg struct {
	id   int64
	text string
	err  error
}

type todosMsg struct {
	tasks []todo.Todo
	err   error
}

type taskMsg struct {
	task todo.Todo
	err  error
}

func (m *Model) loadStatuses() tea.Cmd {
	return func() tea.Msg {
		rows, err := m.b.Statuses(m.ctx)
		return statusesMsg{rows, err}
	}
}

func (m *Model) loadReport(command string) tea.Cmd {
	width := m.width
	return func() tea.Msg {
		text, ok, err := m.b.Report(m.ctx, command, width)
		return reportMsg{command, text, ok, err}
	}
}

func (m *Model) loadTodos() tea.Cmd {
	return func() tea.Msg {
		ts, err := m.b.Todos(m.ctx)
		return todosMsg{ts, err}
	}
}

func (m *Model) explain(id int64, refresh bool) tea.Cmd {
	m.screen, m.explainID, m.busy = screenExplain, id, "explain"
	m.reportLoaded = false
	m.report.SetContent("")
	m.report.GotoTop()
	m.layout()
	m.setStatus(fmt.Sprintf("asking the AI about #%d...", id), false)
	width := m.width
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		text, err := m.b.Explain(m.ctx, id, width, refresh)
		return explainMsg{id, text, err}
	})
}

func (m *Model) rescan(command string) tea.Cmd {
	m.busy = command
	m.setStatus("scanning "+command+"...", false)
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		n, err := m.b.Rescan(m.ctx, command)
		return rescanMsg{command, n, err}
	})
}

// Init loads the first screen's data.
func (m *Model) Init() tea.Cmd {
	if m.screen == screenTodos {
		return m.loadTodos()
	}
	return m.loadStatuses()
}

func (m *Model) setStatus(s string, isErr bool) { m.status, m.statusErr = s, isErr }

// Update handles one message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		if m.screen == screenReport && m.reportCmd != "" {
			return m, m.loadReport(m.reportCmd)
		}
		return m, nil
	case spinner.TickMsg:
		if m.busy == "" {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case statusesMsg:
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			return m, nil
		}
		m.rows = msg.rows
		if m.cursor >= len(m.rows) {
			m.cursor = max(0, len(m.rows)-1)
		}
		return m, nil
	case reportMsg:
		if msg.command != m.reportCmd {
			return m, nil
		}
		switch {
		case msg.err != nil:
			m.setStatus(msg.err.Error(), true)
		case !msg.ok:
			m.report.SetContent(fmt.Sprintf("\n  %s has never run. Press r to scan now.", msg.command))
		default:
			m.report.SetContent(msg.text)
		}
		m.reportLoaded = true
		return m, nil
	case rescanMsg:
		m.busy = ""
		if msg.err != nil {
			m.setStatus(msg.command+": "+msg.err.Error(), true)
		} else {
			m.setStatus(fmt.Sprintf("%s scanned; %d task(s) updated", msg.command, msg.changed), false)
		}
		cmds := []tea.Cmd{m.loadStatuses(), m.loadTodos()}
		if m.screen == screenReport && m.reportCmd == msg.command {
			cmds = append(cmds, m.loadReport(msg.command))
		}
		return m, tea.Batch(cmds...)
	case explainMsg:
		m.busy = ""
		if msg.id != m.explainID {
			return m, nil
		}
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			m.report.SetContent("\n  The AI could not answer. Press r to try again, esc to go back.")
		} else {
			m.setStatus("", false)
			m.report.SetContent(msg.text)
		}
		m.reportLoaded = true
		return m, nil
	case todosMsg:
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			return m, nil
		}
		m.all = msg.tasks
		m.applyFilter()
		return m, nil
	case taskMsg:
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			return m, nil
		}
		for i := range m.all {
			if m.all[i].ID == msg.task.ID {
				m.all[i] = msg.task
			}
		}
		m.setStatus(fmt.Sprintf("#%d %s", msg.task.ID, msg.task.Status.Label()), false)
		m.applyFilter()
		return m, m.loadStatuses()
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	if m.input != inputNone {
		return m.inputKey(k)
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "t":
		if m.screen != screenTodos {
			m.screen, m.standalone = screenTodos, false
			m.layout()
			return m, m.loadTodos()
		}
	case "esc", "backspace", "h", "left":
		if m.screen == screenTodos && m.standalone {
			return m, tea.Quit
		}
		if m.screen == screenExplain {
			m.screen = screenTodos
			m.layout()
			return m, nil
		}
		if m.screen != screenDashboard {
			m.screen = screenDashboard
			return m, m.loadStatuses()
		}
	}
	switch m.screen {
	case screenDashboard:
		return m.dashboardKey(k)
	case screenReport:
		return m.reportKey(k)
	case screenExplain:
		if k.String() == "r" {
			if m.busy == "" {
				return m, m.explain(m.explainID, true)
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.report, cmd = m.report.Update(k)
		return m, cmd
	default:
		return m.todosKey(k)
	}
}

func (m *Model) dashboardKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case "enter", "l", "right":
		if len(m.rows) == 0 {
			return m, nil
		}
		m.screen = screenReport
		m.reportCmd = m.rows[m.cursor].Command
		m.reportLoaded = false
		m.report.SetContent("")
		m.report.GotoTop()
		m.layout()
		return m, m.loadReport(m.reportCmd)
	case "r":
		if len(m.rows) > 0 && m.busy == "" {
			return m, m.rescan(m.rows[m.cursor].Command)
		}
	}
	return m, nil
}

func (m *Model) reportKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "r" {
		if m.busy == "" {
			return m, m.rescan(m.reportCmd)
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.report, cmd = m.report.Update(k)
	return m, cmd
}

// statusKeys maps keys to the status they set in the task list.
var statusKeys = map[string]todo.Status{"o": todo.Open, "i": todo.InProgress, "d": todo.Done, "w": todo.WontDo}

func (m *Model) todosKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	sel := m.selected()
	if st, ok := statusKeys[k.String()]; ok {
		if sel == nil {
			return m, nil
		}
		id := sel.ID
		return m, func() tea.Msg {
			t, err := m.b.SetStatus(m.ctx, id, st)
			return taskMsg{t, err}
		}
	}
	switch k.String() {
	case "n":
		if sel != nil {
			m.input, m.editing = inputNote, sel.ID
			m.field.Prompt = fmt.Sprintf("note #%d: ", sel.ID)
			m.field.SetValue(sel.Note)
			m.field.CursorEnd()
			return m, m.field.Focus()
		}
		return m, nil
	case "e":
		if sel != nil && m.busy == "" {
			return m, m.explain(sel.ID, false)
		}
		return m, nil
	case "/":
		m.input = inputSearch
		m.field.Prompt = "find: "
		m.field.SetValue(m.filter.Search)
		m.field.CursorEnd()
		return m, m.field.Focus()
	case "a":
		m.filter.ShowClosed = !m.filter.ShowClosed
		m.applyFilter()
		return m, nil
	case "c":
		m.filter.Command = m.nextCommand(m.filter.Command)
		m.applyFilter()
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(k)
	return m, cmd
}

// nextCommand cycles the task list's command filter through every command
// that has tasks, then back to all.
func (m *Model) nextCommand(cur string) string {
	var cmds []string
	seen := map[string]bool{}
	for _, t := range m.all {
		if !seen[t.Command] {
			seen[t.Command] = true
			cmds = append(cmds, t.Command)
		}
	}
	if cur == "" {
		if len(cmds) > 0 {
			return cmds[0]
		}
		return ""
	}
	for i, c := range cmds {
		if c == cur && i+1 < len(cmds) {
			return cmds[i+1]
		}
	}
	return ""
}

func (m *Model) inputKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		if m.input == inputSearch {
			m.filter.Search = ""
			m.applyFilter()
		}
		m.input = inputNone
		m.field.Blur()
		return m, nil
	case "enter":
		which, val, id := m.input, m.field.Value(), m.editing
		m.input = inputNone
		m.field.Blur()
		if which == inputSearch {
			m.filter.Search = strings.TrimSpace(val)
			m.applyFilter()
			return m, nil
		}
		return m, func() tea.Msg {
			t, err := m.b.SetNote(m.ctx, id, val)
			return taskMsg{t, err}
		}
	}
	var cmd tea.Cmd
	m.field, cmd = m.field.Update(k)
	if m.input == inputSearch {
		m.filter.Search = strings.TrimSpace(m.field.Value())
		m.applyFilter()
	}
	return m, cmd
}

func (m *Model) selected() *todo.Todo {
	if len(m.tasks) == 0 {
		return nil
	}
	i := m.table.Cursor()
	if i < 0 || i >= len(m.tasks) {
		return nil
	}
	return &m.tasks[i]
}

func (m *Model) applyFilter() {
	ts := m.filter.Apply(m.all)
	todo.Sort(ts)
	m.tasks = ts
	rows := make([]table.Row, len(ts))
	for i, t := range ts {
		rows[i] = table.Row{fmt.Sprintf("%d", t.ID), string(t.Priority), t.Status.Label(), t.Command, t.Title}
	}
	cur := m.table.Cursor()
	m.table.SetRows(rows)
	if cur >= len(rows) {
		m.table.SetCursor(max(0, len(rows)-1))
	}
}

// chrome is the number of lines the title, footer and status use.
const chrome = 4

func (m *Model) layout() {
	body := max(3, m.height-chrome)
	m.report.Width, m.report.Height = m.width, body
	// The detail pane under the task table takes three lines.
	m.table.SetHeight(max(3, body-3))
	title := max(10, m.width-6-12-12-13-8)
	m.table.SetColumns([]table.Column{{Title: "ID", Width: 5}, {Title: "PRIORITY", Width: 10},
		{Title: "STATUS", Width: 11}, {Title: "COMMAND", Width: 12}, {Title: "TITLE", Width: title}})
	m.field.Width = max(10, m.width-20)
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	faintStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	staleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	oldStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	cursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("12"))
)

// View draws the current screen.
func (m *Model) View() string {
	var b strings.Builder
	switch m.screen {
	case screenDashboard:
		b.WriteString(titleStyle.Render("audit") + faintStyle.Render("  dashboard") + "\n\n")
		b.WriteString(m.dashboardView())
	case screenReport, screenExplain:
		title := "audit " + m.reportCmd
		if m.screen == screenExplain {
			title = fmt.Sprintf("audit todo explain %d", m.explainID)
		}
		b.WriteString(titleStyle.Render(title) + faintStyle.Render(fmt.Sprintf("  %3.f%%", m.report.ScrollPercent()*100)) + "\n")
		switch {
		case m.reportLoaded:
			b.WriteString(m.report.View())
		case m.screen == screenExplain:
			b.WriteString("\n  " + m.spinner.View() + " asking the AI...")
		default:
			b.WriteString("\n  loading...")
		}
	default:
		b.WriteString(titleStyle.Render("audit todo") + faintStyle.Render("  "+m.filterLabel()) + "\n")
		b.WriteString(m.todosView())
	}
	b.WriteString("\n")
	b.WriteString(m.statusLine() + "\n")
	b.WriteString(faintStyle.Render(m.help()))
	return b.String()
}

func (m *Model) dashboardView() string {
	if len(m.rows) == 0 {
		return faintStyle.Render("  loading...")
	}
	now := m.now()
	var b strings.Builder
	header := fmt.Sprintf("  %-13s %-17s %-8s %-28s %s", "COMMAND", "LAST RUN", "AGE", "FINDINGS", "OPEN TASKS")
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(header) + "\n")
	for i, r := range m.rows {
		last, age, findings := "never", "-", "-"
		ageStyle := faintStyle
		if r.Latest != nil {
			d := now.Sub(r.Latest.FinishedAt)
			last = r.Latest.FinishedAt.Local().Format("2006-01-02 15:04")
			age = run.HumanAge(d)
			findings = render.CountsText(r.Latest.Counts)
			switch run.FreshnessOf(d, r.Thresholds.Warn, r.Thresholds.Old) {
			case run.Old:
				ageStyle = oldStyle
			case run.Stale:
				ageStyle = staleStyle
			default:
				ageStyle = okStyle
			}
		}
		marker := "  "
		name := fmt.Sprintf("%-13s", r.Command)
		if m.busy == r.Command {
			marker = m.spinner.View() + " "
		}
		if i == m.cursor {
			name = cursorStyle.Render(name)
		} else {
			name = titleStyle.Render(name)
		}
		fmt.Fprintf(&b, "%s%s %-17s %s %-28s %s\n", marker, name, last, ageStyle.Render(fmt.Sprintf("%-8s", age)),
			findings, render.TasksText(r.Open))
	}
	return b.String()
}

func (m *Model) filterLabel() string {
	var parts []string
	if m.filter.Command != "" {
		parts = append(parts, "command "+m.filter.Command)
	}
	if m.filter.Search != "" {
		parts = append(parts, fmt.Sprintf("matching %q", m.filter.Search))
	}
	if m.filter.ShowClosed {
		parts = append(parts, "including closed")
	} else {
		parts = append(parts, "open only")
	}
	return fmt.Sprintf("%d task(s), %s", len(m.tasks), strings.Join(parts, ", "))
}

func (m *Model) todosView() string {
	var b strings.Builder
	if len(m.tasks) == 0 {
		b.WriteString(faintStyle.Render("\n  No tasks match.\n\n\n"))
	} else {
		b.WriteString(m.table.View() + "\n")
		sel := m.selected()
		var hint, note string
		if sel != nil {
			hint, note = sel.Hint, sel.Note
		}
		b.WriteString(clip(faintStyle.Render("hint: ")+hint, m.width) + "\n")
		b.WriteString(clip(faintStyle.Render("note: ")+note, m.width) + "\n")
	}
	if m.input != inputNone {
		b.WriteString(m.field.View())
	}
	return b.String()
}

func clip(s string, width int) string {
	return lipgloss.NewStyle().MaxWidth(width).Render(s)
}

func (m *Model) statusLine() string {
	switch {
	case m.status == "":
		return ""
	case m.statusErr:
		return errStyle.Render(m.status)
	case m.busy != "":
		return m.spinner.View() + " " + m.status
	}
	return okStyle.Render(m.status)
}

func (m *Model) help() string {
	switch {
	case m.input == inputNote:
		return "enter save  esc cancel"
	case m.input == inputSearch:
		return "enter keep  esc clear"
	case m.screen == screenDashboard:
		return "j/k move  enter report  r rescan  t tasks  q quit"
	case m.screen == screenReport:
		return "j/k scroll  pgup/pgdn page  r rescan  esc back  t tasks  q quit"
	case m.screen == screenExplain:
		return "j/k scroll  pgup/pgdn page  r ask again  esc back to tasks  q quit"
	}
	return "j/k move  o open  i in progress  d done  w won't do  n note  e explain  / find  c command  a closed  esc back  q quit"
}
