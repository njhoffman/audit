// Package tui is the interactive dashboard: an overview of every command's
// saved results, a scrollable report per command, rescans with a spinner and
// a task editor.
package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	bkey "github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/njhoffman/audit/internal/keys"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// Backend is what the UI needs from the application.
type Backend interface {
	Statuses(ctx context.Context) ([]render.CommandStatus, error)
	// Report renders the saved run of command at width, with every finding
	// in full when expanded or one line each; ok is false when the command
	// has never run.
	Report(ctx context.Context, command string, width int, expanded bool) (text string, ok bool, err error)
	// Rescan scans command and returns how many tasks changed.
	Rescan(ctx context.Context, command string) (int, error)
	Todos(ctx context.Context) ([]todo.Todo, error)
	SetStatus(ctx context.Context, id int64, s todo.Status) (todo.Todo, error)
	SetNote(ctx context.Context, id int64, note string) (todo.Todo, error)
	// Explain asks the AI about task id and renders the answer at width;
	// refresh skips the cache.
	Explain(ctx context.Context, id int64, width int, refresh bool) (string, error)
	// FixSession is an interactive AI session that fixes task id, to run on
	// the terminal.
	FixSession(ctx context.Context, id int64) (*osexec.Cmd, error)
}

type screen int

const (
	screenDashboard screen = iota
	screenReport
	screenTodos
	// screenExplain shows an AI explanation of a task; esc returns to the
	// task list.
	screenExplain
	// screenTask shows every field and detail line of one task; esc returns
	// to the task list.
	screenTask
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
	ctx  context.Context
	b    Backend
	now  func() time.Time
	keys keys.Map

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

	explainID int64     // task shown on screenExplain
	fixing    int64     // task whose AI fix is being checked, 0 when none
	shown     todo.Todo // task shown on screenTask

	tasks  []todo.Todo // after filtering
	all    []todo.Todo
	filter todo.Filter
	// first is the command whose tasks the list shows above the rest: the
	// dashboard row or report the list was opened from.
	first   string
	table   taskTable
	input   input
	field   textinput.Model
	editing int64
	// home is shown as ~ in paths.
	home string
	// glyphs are the markers and icons.
	glyphs render.Glyphs
	// expanded shows reports' findings in full; keepScroll restores the
	// scroll position, as a fraction, once the toggled report arrives.
	expanded   bool
	keepScroll float64
}

// Option configures a Model.
type Option func(*Model)

// WithClock sets the clock used for ages.
func WithClock(now func() time.Time) Option { return func(m *Model) { m.now = now } }

// WithKeys binds actions to keys; actions missing from km keep their default
// keys. km is expected to have passed keys.Validate.
func WithKeys(km keys.Map) Option {
	return func(m *Model) {
		for name, ks := range km {
			m.keys[name] = ks
		}
	}
}

// WithGlyphs sets the markers and icons (render.UnicodeGlyphs by default).
func WithGlyphs(g render.Glyphs) Option { return func(m *Model) { m.glyphs = g } }

// WithHome shows paths under home as ~/...
func WithHome(home string) Option { return func(m *Model) { m.home = home } }

// StartInTodos opens the task list first, filtered by f.
func StartInTodos(f todo.Filter) Option {
	return func(m *Model) { m.screen, m.filter, m.standalone = screenTodos, f, true }
}

// New returns a Model over b.
func New(ctx context.Context, b Backend, opts ...Option) *Model {
	m := &Model{ctx: ctx, b: b, now: time.Now, keys: keys.Defaults(), width: 80, height: 24, keepScroll: -1,
		glyphs:  render.UnicodeGlyphs,
		spinner: spinner.New(spinner.WithSpinner(spinner.Dot))}
	m.field = textinput.New()
	m.field.CharLimit = 500
	m.field.Cursor.SetMode(cursor.CursorStatic)
	for _, o := range opts {
		o(m)
	}
	m.report.KeyMap = viewport.KeyMap{
		Up: m.binding(keys.Up), Down: m.binding(keys.Down),
		PageUp: m.binding(keys.PageUp), PageDown: m.binding(keys.PageDown),
		HalfPageUp: m.binding(keys.HalfPageUp), HalfPageDown: m.binding(keys.HalfPageDown),
		// Reports are wrapped to the window, and h/left go back.
		Left: bkey.NewBinding(bkey.WithDisabled()), Right: bkey.NewBinding(bkey.WithDisabled()),
	}
	m.layout()
	return m
}

// binding is action as a bubbles key binding; an unbound action never matches.
func (m *Model) binding(action string) bkey.Binding {
	ks := m.keys[action]
	if len(ks) == 0 {
		return bkey.NewBinding(bkey.WithDisabled())
	}
	return bkey.NewBinding(bkey.WithKeys(ks...))
}

// is reports whether k is bound to action.
func (m *Model) is(k tea.KeyMsg, action string) bool {
	return slices.Contains(m.keys[action], k.String())
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

type editorMsg struct{ err error }

type fixMsg struct {
	task todo.Todo
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
	width, expanded := m.width, m.expanded
	return func() tea.Msg {
		text, ok, err := m.b.Report(m.ctx, command, width, expanded)
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
			m.report.SetContent(fmt.Sprintf("\n  %s has never run.%s", msg.command, m.press(keys.Rescan, "scan now")))
		default:
			m.report.SetContent(msg.text)
		}
		if m.keepScroll >= 0 {
			m.report.SetYOffset(int(m.keepScroll * float64(max(0, m.report.TotalLineCount()-m.report.Height))))
			m.keepScroll = -1
		}
		m.reportLoaded = true
		return m, nil
	case rescanMsg:
		m.busy = ""
		if msg.err != nil {
			m.fixing = 0
			m.setStatus(msg.command+": "+msg.err.Error(), true)
		} else {
			m.setStatus(fmt.Sprintf("%s scanned; %d task(s) updated", msg.command, msg.changed), false)
		}
		cmds := []tea.Cmd{m.loadStatuses(), m.loadTodos()}
		if m.screen == screenReport && m.reportCmd == msg.command {
			cmds = append(cmds, m.loadReport(msg.command))
		}
		return m, tea.Batch(cmds...)
	case fixMsg:
		if msg.err != nil {
			m.setStatus("fix: "+msg.err.Error(), true)
			return m, m.loadTodos()
		}
		m.fixing = msg.task.ID
		if msg.task.Source.Scanned() && m.busy == "" {
			return m, m.rescan(msg.task.Command)
		}
		return m, m.loadTodos()
	case editorMsg:
		if msg.err != nil {
			m.setStatus("editor: "+msg.err.Error(), true)
		}
		return m, nil
	case explainMsg:
		m.busy = ""
		if msg.id != m.explainID {
			return m, nil
		}
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			m.report.SetContent("\n  The AI could not answer." + m.press(keys.Reask, "try again") + m.press(keys.Back, "go back"))
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
		m.reportFix()
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
		if m.screen == screenTask && m.shown.ID == msg.task.ID {
			m.showTask(msg.task)
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
	switch {
	case m.is(k, keys.Quit):
		return m, tea.Quit
	case m.is(k, keys.ShowTasks) && m.screen != screenTodos:
		switch m.screen {
		case screenDashboard:
			m.first = ""
			if len(m.rows) > 0 {
				m.first = m.rows[m.cursor].Command
			}
			m.table.top()
		case screenReport:
			m.first = m.reportCmd
			m.table.top()
		}
		m.screen, m.standalone = screenTodos, false
		m.layout()
		return m, m.loadTodos()
	case m.is(k, keys.Back):
		if m.screen == screenTodos && m.standalone {
			return m, tea.Quit
		}
		if m.screen == screenExplain || m.screen == screenTask {
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
	case screenTask:
		switch {
		case m.is(k, keys.Editor):
			return m, m.edit(m.shown)
		case m.is(k, keys.FixTask):
			return m, m.fix(m.shown)
		case m.is(k, keys.ExplainTask):
			if m.busy == "" {
				return m, m.explain(m.shown.ID, false)
			}
			return m, nil
		}
		return m, m.scroll(k)
	case screenExplain:
		if m.is(k, keys.Reask) {
			if m.busy == "" {
				return m, m.explain(m.explainID, true)
			}
			return m, nil
		}
		return m, m.scroll(k)
	default:
		return m.todosKey(k)
	}
}

// scroll passes k to the viewport, which has no keys of its own for the top
// and bottom.
func (m *Model) scroll(k tea.KeyMsg) tea.Cmd {
	switch {
	case m.is(k, keys.Top):
		m.report.GotoTop()
		return nil
	case m.is(k, keys.Bottom):
		m.report.GotoBottom()
		return nil
	}
	var cmd tea.Cmd
	m.report, cmd = m.report.Update(k)
	return cmd
}

func (m *Model) dashboardKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case m.is(k, keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case m.is(k, keys.Down):
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case m.is(k, keys.Open):
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
	case m.is(k, keys.Rescan):
		if len(m.rows) > 0 && m.busy == "" {
			return m, m.rescan(m.rows[m.cursor].Command)
		}
	}
	return m, nil
}

func (m *Model) reportKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case m.is(k, keys.Rescan):
		if m.busy == "" {
			return m, m.rescan(m.reportCmd)
		}
		return m, nil
	case m.is(k, keys.Details):
		m.expanded = !m.expanded
		m.keepScroll = m.report.ScrollPercent()
		return m, m.loadReport(m.reportCmd)
	}
	return m, m.scroll(k)
}

// statusActions maps actions to the status they set in the task list.
var statusActions = []struct {
	action string
	status todo.Status
}{{keys.StatusOpen, todo.Open}, {keys.StatusDoing, todo.InProgress}, {keys.StatusDone, todo.Done}, {keys.StatusWontDo, todo.WontDo}}

func (m *Model) todosKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	sel := m.selected()
	for _, sa := range statusActions {
		if !m.is(k, sa.action) {
			continue
		}
		if sel == nil {
			return m, nil
		}
		id, st := sel.ID, sa.status
		return m, func() tea.Msg {
			t, err := m.b.SetStatus(m.ctx, id, st)
			return taskMsg{t, err}
		}
	}
	switch {
	case m.is(k, keys.Note):
		if sel != nil {
			m.input, m.editing = inputNote, sel.ID
			m.field.Prompt = fmt.Sprintf("note #%d: ", sel.ID)
			m.field.SetValue(sel.Note)
			m.field.CursorEnd()
			return m, m.field.Focus()
		}
		return m, nil
	case m.is(k, keys.ExplainTask):
		if sel != nil && m.busy == "" {
			return m, m.explain(sel.ID, false)
		}
		return m, nil
	case m.is(k, keys.Open):
		if sel != nil {
			m.showTask(*sel)
		}
		return m, nil
	case m.is(k, keys.Editor):
		if sel != nil {
			return m, m.edit(*sel)
		}
		return m, nil
	case m.is(k, keys.FixTask):
		if sel != nil {
			return m, m.fix(*sel)
		}
		return m, nil
	case m.is(k, keys.Search):
		m.input = inputSearch
		m.field.Prompt = "find: "
		m.field.SetValue(m.filter.Search)
		m.field.CursorEnd()
		return m, m.field.Focus()
	case m.is(k, keys.ToggleClosed):
		m.filter.ShowClosed = !m.filter.ShowClosed
		m.applyFilter()
		return m, nil
	case m.is(k, keys.CycleCommand):
		m.filter.Command = m.nextCommand(m.filter.Command)
		m.applyFilter()
		return m, nil
	}
	return m, m.moveTasks(k)
}

// moveTasks moves the task list's cursor for the movement keys.
func (m *Model) moveTasks(k tea.KeyMsg) tea.Cmd {
	half := max(1, m.table.height/2)
	switch {
	case m.is(k, keys.Up):
		m.table.move(-1)
	case m.is(k, keys.Down):
		m.table.move(1)
	case m.is(k, keys.PageUp):
		m.table.move(-m.table.height)
	case m.is(k, keys.PageDown):
		m.table.move(m.table.height)
	case m.is(k, keys.HalfPageUp):
		m.table.move(-half)
	case m.is(k, keys.HalfPageDown):
		m.table.move(half)
	case m.is(k, keys.Top):
		m.table.top()
	case m.is(k, keys.Bottom):
		m.table.bottom()
	}
	return nil
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

func (m *Model) selected() *todo.Todo { return m.table.selected() }

// applyFilter filters and sorts the tasks. Without a command filter, the
// tasks of m.first come first, in the same order, above a divider.
func (m *Model) applyFilter() {
	ts := m.filter.Apply(m.all)
	todo.Sort(ts)
	split := 0
	if m.first != "" && m.filter.Command == "" {
		var mine, rest []todo.Todo
		for _, t := range ts {
			if t.Command == m.first {
				mine = append(mine, t)
			} else {
				rest = append(rest, t)
			}
		}
		ts, split = slices.Concat(mine, rest), len(mine)
	}
	m.tasks = ts
	m.table.setRows(ts, split)
}

// chrome is the number of lines the title, footer and status use.
const chrome = 4

func (m *Model) layout() {
	body := max(3, m.height-chrome)
	m.report.Width, m.report.Height = m.width, body
	// The table's header takes two lines and the detail pane under it three.
	m.table.setHeight(body - 5)
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
	case screenReport, screenExplain, screenTask:
		title := "audit " + m.reportCmd
		switch m.screen {
		case screenExplain:
			title = fmt.Sprintf("audit todo explain %d", m.explainID)
		case screenTask:
			title = fmt.Sprintf("audit todo show %d", m.shown.ID)
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
	p := render.NewProfile(io.Discard, lipgloss.ColorProfile(), 0)
	p.Glyphs = m.glyphs
	cc := render.NewCountColumns(m.rows)
	type line struct{ name, last, age, findings, tasks string }
	lines := make([]line, len(m.rows))
	nameW, findW := len("COMMAND"), len("FINDINGS")
	for i, r := range m.rows {
		l := line{name: m.glyphs.Icon(r.Command) + r.Command, last: faintStyle.Render("never"), age: faintStyle.Render("-"),
			findings: p.RunCounts(cc, r), tasks: p.TaskCounts(cc, r.Open)}
		if r.Latest != nil {
			d := now.Sub(r.Latest.FinishedAt)
			l.last = r.Latest.FinishedAt.Local().Format("2006-01-02 15:04")
			ageStyle := okStyle
			switch run.FreshnessOf(d, r.Thresholds.Warn, r.Thresholds.Old) {
			case run.Old:
				ageStyle = oldStyle
			case run.Stale:
				ageStyle = staleStyle
			}
			l.age = ageStyle.Render(run.HumanAge(d))
		}
		nameW = max(nameW, ansi.StringWidth(l.name))
		findW = max(findW, ansi.StringWidth(l.findings))
		lines[i] = l
	}
	pad := func(s string, w int) string { return s + strings.Repeat(" ", max(0, w-ansi.StringWidth(s))) }
	var b strings.Builder
	header := "  " + pad("COMMAND", nameW) + "  " + pad("LAST RUN", 16) + "  " + pad("AGE", 8) + "  " + pad("FINDINGS", findW) +
		"  " + m.glyphs.Icon("tasks") + "OPEN TASKS"
	b.WriteString(lipgloss.NewStyle().Bold(true).Render(header) + "\n")
	for i, l := range lines {
		marker := "  "
		if m.busy == m.rows[i].Command {
			marker = m.spinner.View() + " "
		}
		name := pad(l.name, nameW)
		if i == m.cursor {
			name = cursorStyle.Render(name)
		} else {
			name = titleStyle.Render(name)
		}
		b.WriteString(marker + name + "  " + pad(l.last, 16) + "  " + pad(l.age, 8) + "  " + pad(l.findings, findW) + "  " + l.tasks + "\n")
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
		b.WriteString(m.table.view(m.width, m.glyphs, m.home))
		sel := m.selected()
		var hint, note string
		if sel != nil {
			hint, note = render.Tilde(sel.Hint, m.home), sel.Note
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
	var hints [][]string
	switch {
	case m.input == inputNote:
		return "enter save  esc cancel"
	case m.input == inputSearch:
		return "enter keep  esc clear"
	case m.screen == screenDashboard:
		hints = [][]string{{"move", keys.Down, keys.Up}, {"report", keys.Open}, {"rescan", keys.Rescan},
			{"tasks", keys.ShowTasks}, {"quit", keys.Quit}}
	case m.screen == screenReport:
		hints = [][]string{{"scroll", keys.Down, keys.Up}, {"page", keys.PageUp, keys.PageDown},
			{"details", keys.Details}, {"rescan", keys.Rescan}, {"back", keys.Back}, {"tasks", keys.ShowTasks}, {"quit", keys.Quit}}
	case m.screen == screenExplain:
		hints = [][]string{{"scroll", keys.Down, keys.Up}, {"page", keys.PageUp, keys.PageDown},
			{"ask again", keys.Reask}, {"back to tasks", keys.Back}, {"quit", keys.Quit}}
	case m.screen == screenTask:
		hints = [][]string{{"scroll", keys.Down, keys.Up}, {"page", keys.PageUp, keys.PageDown},
			{"open in editor", keys.Editor}, {"explain", keys.ExplainTask}, {"fix with AI", keys.FixTask}, {"back to tasks", keys.Back}, {"quit", keys.Quit}}
	default:
		hints = [][]string{{"move", keys.Down, keys.Up}, {"details", keys.Open}, {"editor", keys.Editor},
			{"open", keys.StatusOpen}, {"in progress", keys.StatusDoing}, {"done", keys.StatusDone},
			{"won't do", keys.StatusWontDo}, {"note", keys.Note}, {"explain", keys.ExplainTask}, {"fix", keys.FixTask}, {"find", keys.Search},
			{"command", keys.CycleCommand}, {"closed", keys.ToggleClosed}, {"back", keys.Back}, {"quit", keys.Quit}}
	}
	parts := make([]string, 0, len(hints))
	for _, h := range hints {
		var ks []string
		for _, a := range h[1:] {
			if k := m.keys.First(a); k != "" {
				ks = append(ks, k)
			}
		}
		if len(ks) > 0 {
			parts = append(parts, strings.Join(ks, "/")+" "+h[0])
		}
	}
	return strings.Join(parts, "  ")
}

// press is " Press <key> to <what>." for the first key of action, or ""
// when the action is unbound.
func (m *Model) press(action, what string) string {
	if k := m.keys.First(action); k != "" {
		return fmt.Sprintf(" Press %s to %s.", k, what)
	}
	return ""
}

// showTask switches to the detail screen of t.
func (m *Model) showTask(t todo.Todo) {
	var b bytes.Buffer
	p := render.New(&b, false, m.width)
	p.Now, p.Home = m.now, m.home
	p.Todo(t)
	if locs := todo.Locations(t); len(locs) > 0 {
		fmt.Fprintf(&b, "\n%s\n", faintStyle.Render(fmt.Sprintf("%d file location(s).%s", len(locs), m.press(keys.Editor, "open them in $EDITOR"))))
	}
	m.screen, m.shown, m.reportLoaded = screenTask, t, true
	m.report.SetContent(b.String())
	m.report.GotoTop()
	m.layout()
}

// edit opens the file locations of t in the editor (see EditorCommand).
func (m *Model) edit(t todo.Todo) tea.Cmd {
	c, cleanup, err := EditorCommand(t)
	if err != nil {
		m.setStatus(err.Error(), true)
		return nil
	}
	return tea.ExecProcess(c, func(err error) tea.Msg {
		cleanup()
		return editorMsg{err}
	})
}

// EditorCommand opens the file locations of t in $VISUAL or $EDITOR: vim
// and neovim get every location as a quickfix list, other editors the first
// file at its line. cleanup removes the quickfix file once the editor exits.
func EditorCommand(t todo.Todo) (c *osexec.Cmd, cleanup func(), err error) {
	locs := todo.Locations(t)
	if len(locs) == 0 {
		return nil, nil, fmt.Errorf("#%d names no file:line locations", t.ID)
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	args := strings.Fields(editor)
	cleanup = func() {}
	switch filepath.Base(args[0]) {
	case "vim", "nvim", "vi", "gvim", "nvi":
		f, err := os.CreateTemp("", "audit-quickfix-*.txt")
		if err != nil {
			return nil, nil, err
		}
		_, werr := f.WriteString(strings.Join(t.Details, "\n") + "\n")
		if err := f.Close(); werr != nil || err != nil {
			_ = os.Remove(f.Name())
			return nil, nil, fmt.Errorf("write quickfix file: %w", errors.Join(werr, err))
		}
		cleanup = func() { _ = os.Remove(f.Name()) }
		args = append(args, "-q", f.Name())
	default:
		args = append(args, "+"+strconv.Itoa(locs[0].Line), locs[0].Path)
	}
	return osexec.Command(args[0], args[1:]...), cleanup, nil // #nosec G204 G702 -- the user's own $EDITOR on paths from their tasks
}

// fix hands the terminal to an interactive AI session that fixes t (see
// Backend.FixSession). When it exits, a scanned task's command is rescanned
// and the status line says whether the task closed.
func (m *Model) fix(t todo.Todo) tea.Cmd {
	if m.busy != "" {
		m.setStatus("wait for "+m.busy+" to finish", true)
		return nil
	}
	c, err := m.b.FixSession(m.ctx, t.ID)
	if err != nil {
		m.setStatus(err.Error(), true)
		return nil
	}
	return tea.ExecProcess(c, func(err error) tea.Msg { return fixMsg{t, err} })
}

// reportFix shows what became of the task being fixed once the tasks are
// reloaded after its rescan.
func (m *Model) reportFix() {
	if m.fixing == 0 {
		return
	}
	id := m.fixing
	m.fixing = 0
	for _, t := range m.all {
		if t.ID != id {
			continue
		}
		m.setStatus(render.FixOutcome(t), false)
		if m.screen == screenTask && m.shown.ID == id {
			m.showTask(t)
		}
		return
	}
}
