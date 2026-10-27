package tui

import (
	"context"
	"errors"
	"fmt"
	osexec "os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/keys"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type fake struct {
	rows     []render.CommandStatus
	tasks    []todo.Todo
	rescans  []string
	reports  []string
	setCalls []todo.Status
	notes    []string
	failSet  bool
	explains []string
	failAI   bool
	report   string // report text; empty means "report of <command>"
	expanded []bool // the expanded argument of each Report
	fixes    []int64
	resolve  int64 // the task a rescan of its command resolves
}

func (f *fake) FixSession(_ context.Context, id int64) (*osexec.Cmd, error) {
	f.fixes = append(f.fixes, id)
	for _, t := range f.tasks {
		if t.ID == id && t.Status.Closed() {
			return nil, fmt.Errorf("#%d is %s", id, t.Status.Label())
		}
	}
	return osexec.Command("true"), nil
}

func (f *fake) Explain(_ context.Context, id int64, _ int, refresh bool) (string, error) {
	f.explains = append(f.explains, fmt.Sprintf("%d:%v", id, refresh))
	if f.failAI {
		return "", errors.New("claude not found")
	}
	return fmt.Sprintf("why #%d happens", id), nil
}

func (f *fake) Statuses(context.Context) ([]render.CommandStatus, error) { return f.rows, nil }

func (f *fake) Report(_ context.Context, c string, _ int, expanded bool) (string, bool, error) {
	f.reports = append(f.reports, c)
	f.expanded = append(f.expanded, expanded)
	if c == "packages" {
		return "", false, nil
	}
	if f.report != "" {
		return f.report, true, nil
	}
	return "report of " + c, true, nil
}

func (f *fake) Rescan(_ context.Context, c string) (int, error) {
	f.rescans = append(f.rescans, c)
	for i := range f.tasks {
		if f.tasks[i].ID == f.resolve && f.tasks[i].Command == c {
			f.tasks[i].Status = todo.Resolved
		}
	}
	return 3, nil
}

func (f *fake) Todos(context.Context) ([]todo.Todo, error) {
	return append([]todo.Todo(nil), f.tasks...), nil
}

func (f *fake) SetStatus(_ context.Context, id int64, s todo.Status) (todo.Todo, error) {
	if f.failSet {
		return todo.Todo{}, errors.New("db locked")
	}
	f.setCalls = append(f.setCalls, s)
	for i := range f.tasks {
		if f.tasks[i].ID == id {
			f.tasks[i].Status = s
			return f.tasks[i], nil
		}
	}
	return todo.Todo{}, errors.New("no task")
}

func (f *fake) SetNote(_ context.Context, id int64, note string) (todo.Todo, error) {
	f.notes = append(f.notes, note)
	for i := range f.tasks {
		if f.tasks[i].ID == id {
			f.tasks[i].Note = note
			return f.tasks[i], nil
		}
	}
	return todo.Todo{}, errors.New("no task")
}

func newFake() *fake {
	th := config.Thresholds{Warn: 24 * time.Hour, Old: 7 * 24 * time.Hour}
	return &fake{
		rows: []render.CommandStatus{
			{Command: "system", Thresholds: th, Latest: &store.RunInfo{FinishedAt: now.Add(-time.Hour),
				Counts: finding.Counts{finding.Error: 2}}, Open: map[todo.Priority]int{todo.High: 2}},
			{Command: "environment", Thresholds: th, Latest: &store.RunInfo{FinishedAt: now.Add(-10 * 24 * time.Hour)}},
			{Command: "packages", Thresholds: th},
		},
		tasks: []todo.Todo{
			{ID: 1, Command: "system", Title: "fix sshd", Priority: todo.High, Status: todo.Open, Hint: "edit sshd_config", Source: todo.FromFinding},
			{ID: 2, Command: "packages", Title: "remove orphan", Priority: todo.Low, Status: todo.Open, Source: todo.FromFinding},
			{ID: 3, Command: "system", Title: "old thing", Priority: todo.Medium, Status: todo.Done, Source: todo.FromFinding},
		},
	}
}

// drive runs cmd and feeds every message it produces back into the model,
// following batches, until nothing is left. Spinner ticks are dropped so
// the loop ends.
func drive(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	queue := []tea.Cmd{cmd}
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 100 {
			t.Fatal("message loop did not settle")
		}
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		switch msg := msg.(type) {
		case tea.BatchMsg:
			queue = append(queue, msg...)
			continue
		case tea.QuitMsg, nil:
			continue
		}
		if name := fmt.Sprintf("%T", msg); strings.HasPrefix(name, "spinner.") || strings.HasPrefix(name, "cursor.") {
			continue
		}
		_, next := m.Update(msg)
		queue = append(queue, next)
	}
}

func key(t *testing.T, m *Model, k string) {
	t.Helper()
	var msg tea.KeyMsg
	switch k {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	_, cmd := m.Update(msg)
	drive(t, m, cmd)
}

func start(t *testing.T, f *fake, opts ...Option) *Model {
	t.Helper()
	m := New(context.Background(), f, append([]Option{WithClock(func() time.Time { return now })}, opts...)...)
	drive(t, m, m.Init())
	_, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	drive(t, m, cmd)
	return m
}

func TestDashboardShowsCommandsAndAges(t *testing.T) {
	m := start(t, newFake())
	v := m.View()
	for _, s := range []string{"system", "environment", "packages", "1h", "10d", "never", "● 2       ● 2", "✓ none"} {
		if !strings.Contains(v, s) {
			t.Errorf("dashboard missing %q:\n%s", s, v)
		}
	}
}

func TestDashboardOpensReport(t *testing.T) {
	f := newFake()
	m := start(t, f)
	key(t, m, "j")
	key(t, m, "enter")
	if m.screen != screenReport || m.reportCmd != "environment" {
		t.Fatalf("screen=%v cmd=%q", m.screen, m.reportCmd)
	}
	if !strings.Contains(m.View(), "report of environment") {
		t.Errorf("report not shown:\n%s", m.View())
	}
	key(t, m, "esc")
	if m.screen != screenDashboard {
		t.Error("esc should return to the dashboard")
	}
}

func TestNeverRunReportOffersScan(t *testing.T) {
	m := start(t, newFake())
	key(t, m, "j")
	key(t, m, "j")
	key(t, m, "j") // stays on the last row
	key(t, m, "enter")
	if m.reportCmd != "packages" || !strings.Contains(m.View(), "never run") {
		t.Errorf("want never-run notice for packages:\n%s", m.View())
	}
}

func TestRescanFromDashboard(t *testing.T) {
	f := newFake()
	m := start(t, f)
	key(t, m, "r")
	if len(f.rescans) != 1 || f.rescans[0] != "system" {
		t.Fatalf("rescans %v", f.rescans)
	}
	if m.busy != "" || !strings.Contains(m.View(), "system scanned; 3 task(s) updated") {
		t.Errorf("want completion status:\n%s", m.View())
	}
}

func TestRescanFromReportReloadsIt(t *testing.T) {
	f := newFake()
	m := start(t, f)
	key(t, m, "enter")
	key(t, m, "r")
	if len(f.rescans) != 1 || len(f.reports) < 2 {
		t.Errorf("rescans=%v reports=%v", f.rescans, f.reports)
	}
}

func TestTodosChangeStatusAndNote(t *testing.T) {
	f := newFake()
	m := start(t, f)
	key(t, m, "t")
	if m.screen != screenTodos || len(m.tasks) != 2 {
		t.Fatalf("screen=%v tasks=%d", m.screen, len(m.tasks))
	}
	if !strings.Contains(m.View(), "edit sshd_config") {
		t.Errorf("selected task's hint should show:\n%s", m.View())
	}
	key(t, m, "i")
	if len(f.setCalls) != 1 || f.setCalls[0] != todo.InProgress {
		t.Fatalf("set calls %v", f.setCalls)
	}
	key(t, m, "d")
	if len(m.tasks) != 1 {
		t.Errorf("done task should drop out of the open list, have %d", len(m.tasks))
	}
	key(t, m, "a")
	if len(m.tasks) != 3 {
		t.Errorf("a should show closed tasks, have %d", len(m.tasks))
	}

	key(t, m, "n")
	if m.input != inputNote {
		t.Fatal("n should open the note field")
	}
	for _, r := range "later" {
		key(t, m, string(r))
	}
	key(t, m, "q") // typed into the field, not quit
	key(t, m, "enter")
	if len(f.notes) != 1 || f.notes[0] != "laterq" {
		t.Errorf("notes %v", f.notes)
	}
}

func TestTodosSearchAndCommandFilter(t *testing.T) {
	m := start(t, newFake())
	key(t, m, "t")
	key(t, m, "/")
	for _, r := range "orphan" {
		key(t, m, string(r))
	}
	if len(m.tasks) != 1 || m.tasks[0].ID != 2 {
		t.Errorf("search should narrow live: %v", m.tasks)
	}
	key(t, m, "esc")
	if len(m.tasks) != 2 {
		t.Errorf("esc should clear the search, have %d", len(m.tasks))
	}
	key(t, m, "c")
	if m.filter.Command != "system" || len(m.tasks) != 1 {
		t.Errorf("c should filter to the first command: %q %d", m.filter.Command, len(m.tasks))
	}
	key(t, m, "c")
	key(t, m, "c")
	if m.filter.Command != "" {
		t.Errorf("c should cycle back to all, got %q", m.filter.Command)
	}
}

func TestSetStatusErrorShows(t *testing.T) {
	f := newFake()
	f.failSet = true
	m := start(t, f)
	key(t, m, "t")
	key(t, m, "d")
	if !strings.Contains(m.View(), "db locked") {
		t.Errorf("error not shown:\n%s", m.View())
	}
}

func TestStandaloneTodosQuitOnEsc(t *testing.T) {
	m := start(t, newFake(), StartInTodos(todo.Filter{Command: "packages"}))
	if m.screen != screenTodos || len(m.tasks) != 1 {
		t.Fatalf("screen=%v tasks=%d", m.screen, len(m.tasks))
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("esc should quit a standalone task list")
	}
}

func TestEmptyTodos(t *testing.T) {
	f := newFake()
	f.tasks = nil
	m := start(t, f)
	key(t, m, "t")
	key(t, m, "d")
	key(t, m, "n")
	if m.input != inputNone || !strings.Contains(m.View(), "No tasks match") {
		t.Errorf("empty list should ignore edits:\n%s", m.View())
	}
}

func TestTodosExplain(t *testing.T) {
	f := newFake()
	m := start(t, f, StartInTodos(todo.Filter{}))
	key(t, m, "e")
	if m.screen != screenExplain || !strings.Contains(m.View(), "why #1 happens") ||
		!strings.Contains(m.View(), "audit todo explain 1") || !strings.Contains(m.View(), "r ask again") {
		t.Fatalf("explain screen:\n%s", m.View())
	}
	key(t, m, "r")
	if strings.Join(f.explains, ",") != "1:false,1:true" {
		t.Errorf("r asks again without the cache: %v", f.explains)
	}
	key(t, m, "esc")
	if m.screen != screenTodos {
		t.Errorf("esc goes back to the tasks, not out: %v", m.screen)
	}

	f.failAI = true
	key(t, m, "down")
	key(t, m, "e")
	if !strings.Contains(m.View(), "claude not found") || !strings.Contains(m.View(), "could not answer") {
		t.Errorf("an AI failure shows:\n%s", m.View())
	}
}

func TestTaskDetailScreen(t *testing.T) {
	f := newFake()
	f.tasks[0].Details = []string{"/etc/ssh/sshd_config:12: PermitRootLogin yes", "/etc/ssh/sshd_config:40: PasswordAuthentication yes"}
	m := start(t, f, StartInTodos(todo.Filter{}))
	key(t, m, "enter")
	v := m.View()
	if m.screen != screenTask || !strings.Contains(v, "audit todo show 1") || !strings.Contains(v, "edit sshd_config") ||
		!strings.Contains(v, "/etc/ssh/sshd_config:40: PasswordAuthentication yes") || !strings.Contains(v, "2 file location(s)") {
		t.Fatalf("detail screen:\n%s", v)
	}
	t.Setenv("VISUAL", "true")
	if cmd := m.edit(m.shown); cmd == nil {
		t.Error("a task with locations should open the editor")
	}
	key(t, m, "d")
	if m.screen != screenTask {
		t.Errorf("status keys on the detail screen must not leave it: %v", m.screen)
	}
	key(t, m, "esc")
	if m.screen != screenTodos {
		t.Fatalf("esc returns to the tasks: %v", m.screen)
	}
	key(t, m, "down")
	key(t, m, "v")
	if !m.statusErr || !strings.Contains(m.status, "names no file:line locations") {
		t.Errorf("v without locations: %q", m.status)
	}
}

func TestCustomKeys(t *testing.T) {
	f := newFake()
	m := start(t, f, WithKeys(keys.Map{keys.StatusDone: {"x", "ctrl+x"}, keys.Down: {"n"}, keys.ShowTasks: {"T"},
		keys.Note: {"N"}, keys.CycleCommand: {}}))
	key(t, m, "t")
	if m.screen != screenDashboard {
		t.Fatal("t is no longer bound to tasks")
	}
	key(t, m, "n")
	if m.cursor != 1 {
		t.Errorf("n moves down, cursor=%d", m.cursor)
	}
	key(t, m, "T")
	if m.screen != screenTodos {
		t.Fatalf("T opens tasks, screen=%v", m.screen)
	}
	key(t, m, "d")
	if len(f.setCalls) != 0 {
		t.Errorf("d is unbound: %v", f.setCalls)
	}
	key(t, m, "x")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	drive(t, m, cmd)
	if len(f.setCalls) != 2 || f.setCalls[0] != todo.Done || f.setCalls[1] != todo.Done {
		t.Errorf("x and ctrl+x both mark done: %v", f.setCalls)
	}
	key(t, m, "c")
	if m.filter.Command != "" {
		t.Errorf("cycle_command is unbound: %q", m.filter.Command)
	}
	h := m.help()
	for _, want := range []string{"x done", "n/k move", "N note"} {
		if !strings.Contains(h, want) {
			t.Errorf("help %q missing %q", h, want)
		}
	}
	if strings.Contains(h, "command") || strings.Contains(h, "d done") {
		t.Errorf("help shows unbound or replaced keys: %q", h)
	}
}

func TestScrollKeys(t *testing.T) {
	f := newFake()
	f.report = strings.Repeat("line\n", 200)
	m := start(t, f)
	key(t, m, "enter")
	key(t, m, "G")
	if !m.report.AtBottom() {
		t.Error("G goes to the bottom")
	}
	key(t, m, "g")
	if !m.report.AtTop() {
		t.Error("g goes to the top")
	}
	key(t, m, " ")
	if m.report.YOffset == 0 {
		t.Error("space pages down")
	}
	before := m.report.View()
	key(t, m, "l")
	if m.screen != screenReport || m.report.View() != before {
		t.Error("l neither leaves the report nor scrolls sideways")
	}
}

func TestToggleDetails(t *testing.T) {
	f := newFake()
	f.report = strings.Repeat("line\n", 200)
	m := start(t, f)
	key(t, m, "enter")
	key(t, m, "G")
	key(t, m, "x")
	if !reflect.DeepEqual(f.expanded, []bool{false, true}) {
		t.Errorf("reports start collapsed and x expands them: %v", f.expanded)
	}
	if !m.report.AtBottom() {
		t.Error("the toggled report keeps its scroll position")
	}
	key(t, m, "x")
	if f.expanded[len(f.expanded)-1] {
		t.Error("x collapses them again")
	}
	if !strings.Contains(m.help(), "x details") {
		t.Errorf("help: %s", m.help())
	}
}

func TestTaskListMarkersAndColumns(t *testing.T) {
	m := start(t, newFake(), StartInTodos(todo.Filter{ShowClosed: true}))
	v := m.View()
	for _, s := range []string{"PRIORITY", "● high", "○ low", "◐ medium", "done", "fix sshd", "F fix"} {
		if !strings.Contains(v, s) {
			t.Errorf("task list missing %q:\n%s", s, v)
		}
	}
	nerd := start(t, newFake(), StartInTodos(todo.Filter{}), WithGlyphs(render.NerdGlyphs))
	if v := nerd.View(); !strings.Contains(v, render.NerdGlyphs.Icons["system"]+" system") ||
		!strings.Contains(v, render.NerdGlyphs.Priority[todo.High]+" high") {
		t.Errorf("nerd icons missing:\n%s", v)
	}
}

func TestTaskListShowsSectionFirst(t *testing.T) {
	f := newFake()
	f.tasks = append(f.tasks, todo.Todo{ID: 4, Command: "system", Title: "rotate logs", Priority: todo.Low, Status: todo.Open})
	m := start(t, f)
	key(t, m, "j")
	key(t, m, "j") // packages
	key(t, m, "t")
	if ids := taskIDs(m.tasks); ids != "2,1,4" {
		t.Errorf("packages' tasks first, then the rest in order: %s", ids)
	}
	if sel := m.selected(); sel == nil || sel.ID != 2 {
		t.Errorf("cursor starts on the section's first task: %+v", sel)
	}
	if !strings.Contains(m.View(), "other commands") {
		t.Errorf("divider missing:\n%s", m.View())
	}
	key(t, m, "c")
	if strings.Contains(m.View(), "other commands") || taskIDs(m.tasks) != "1,4" {
		t.Errorf("a command filter drops the section split: %s\n%s", taskIDs(m.tasks), m.View())
	}
	key(t, m, "c")
	key(t, m, "c")
	key(t, m, "esc")

	key(t, m, "k")
	key(t, m, "k")
	key(t, m, "enter") // system's report
	key(t, m, "t")
	if ids := taskIDs(m.tasks); ids != "1,4,2" {
		t.Errorf("from a report its command's tasks come first: %s", ids)
	}
	key(t, m, "esc")
	m.rows = nil
	key(t, m, "t")
	if ids := taskIDs(m.tasks); ids != "1,2,4" || strings.Contains(m.View(), "other commands") {
		t.Errorf("no section without a dashboard row: %s", ids)
	}
}

func taskIDs(ts []todo.Todo) string {
	ids := make([]string, len(ts))
	for i, t := range ts {
		ids[i] = fmt.Sprint(t.ID)
	}
	return strings.Join(ids, ",")
}

func TestTaskListScrolls(t *testing.T) {
	f := newFake()
	f.tasks = nil
	for i := 1; i <= 40; i++ {
		f.tasks = append(f.tasks, todo.Todo{ID: int64(i), Command: "system", Title: fmt.Sprintf("task %02d", i), Priority: todo.Medium, Status: todo.Open})
	}
	m := start(t, f, StartInTodos(todo.Filter{}))
	if strings.Contains(m.View(), "task 40") {
		t.Fatal("40 rows do not fit in 30 lines")
	}
	key(t, m, "G")
	if sel := m.selected(); sel == nil || sel.ID != 40 || !strings.Contains(m.View(), "task 40") {
		t.Errorf("G selects and shows the last task:\n%s", m.View())
	}
	key(t, m, "g")
	if sel := m.selected(); sel.ID != 1 || !strings.Contains(m.View(), "task 01") {
		t.Errorf("g goes back to the top")
	}
	key(t, m, " ")
	if sel := m.selected(); sel.ID == 1 {
		t.Error("space pages down")
	}
	if lines := strings.Count(m.View(), "\n"); lines >= 30 {
		t.Errorf("view is %d lines, taller than the window", lines)
	}
}

func TestTaskTableKeepsDividerAndCursorVisible(t *testing.T) {
	tt := taskTable{height: 3}
	ts := make([]todo.Todo, 6)
	tt.setRows(ts, 2) // lines: 0 1 divider 3 4 5 6
	if tt.lines() != 7 {
		t.Fatalf("lines %d", tt.lines())
	}
	tt.move(2) // row 2, line 3
	if tt.offset != 1 {
		t.Errorf("row 2 sits under the divider, which should show: offset %d", tt.offset)
	}
	tt.bottom()
	if tt.cursor != 5 || tt.offset != 4 {
		t.Errorf("bottom: cursor %d offset %d", tt.cursor, tt.offset)
	}
	tt.move(-100)
	if tt.cursor != 0 || tt.offset != 0 {
		t.Errorf("top clamps: cursor %d offset %d", tt.cursor, tt.offset)
	}
	tt.setRows(nil, 0)
	if tt.selected() != nil || tt.view(80, render.UnicodeGlyphs, "") == "" {
		t.Error("an empty table selects nothing but still has a header")
	}
}

func TestFixTask(t *testing.T) {
	f := newFake()
	f.resolve = 1
	m := start(t, f, StartInTodos(todo.Filter{}))
	key(t, m, "F")
	if len(f.fixes) != 1 || f.fixes[0] != 1 {
		t.Fatalf("F starts a session for the selected task: %v", f.fixes)
	}
	// tea.ExecProcess runs the session in a real program; deliver its end.
	_, cmd := m.Update(fixMsg{task: f.tasks[0]})
	drive(t, m, cmd)
	if strings.Join(f.rescans, ",") != "system" || !strings.Contains(m.status, "#1 resolved") {
		t.Errorf("the task's command is rescanned and the outcome shown: %v %q", f.rescans, m.status)
	}

	f.resolve = 0
	_, cmd = m.Update(fixMsg{task: f.tasks[1]})
	drive(t, m, cmd)
	if !strings.Contains(m.status, "#2 is still open: packages still reports it") {
		t.Errorf("unresolved: %q", m.status)
	}

	manual := todo.Todo{ID: 9, Command: "system", Title: "by hand", Status: todo.Open, Source: todo.Manual}
	f.tasks = append(f.tasks, manual)
	n := len(f.rescans)
	_, cmd = m.Update(fixMsg{task: manual})
	drive(t, m, cmd)
	if len(f.rescans) != n || !strings.Contains(m.status, "added by hand") {
		t.Errorf("a manual task is not rescanned: %v %q", f.rescans, m.status)
	}

	_, cmd = m.Update(fixMsg{task: manual, err: errors.New("exit status 1")})
	drive(t, m, cmd)
	if !m.statusErr || !strings.Contains(m.status, "fix: exit status 1") {
		t.Errorf("a failed session shows: %q", m.status)
	}

	key(t, m, "a")
	for m.selected() != nil && !m.selected().Status.Closed() {
		key(t, m, "j")
	}
	key(t, m, "F")
	if !m.statusErr || !strings.Contains(m.status, "is resolved") && !strings.Contains(m.status, "is done") {
		t.Errorf("a closed task is refused: %q", m.status)
	}
}
