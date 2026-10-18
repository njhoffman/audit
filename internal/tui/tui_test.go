package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
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
}

func (f *fake) Statuses(context.Context) ([]render.CommandStatus, error) { return f.rows, nil }

func (f *fake) Report(_ context.Context, c string, _ int) (string, bool, error) {
	f.reports = append(f.reports, c)
	if c == "packages" {
		return "", false, nil
	}
	return "report of " + c, true, nil
}

func (f *fake) Rescan(_ context.Context, c string) (int, error) {
	f.rescans = append(f.rescans, c)
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
			{ID: 1, Command: "system", Title: "fix sshd", Priority: todo.High, Status: todo.Open, Hint: "edit sshd_config"},
			{ID: 2, Command: "packages", Title: "remove orphan", Priority: todo.Low, Status: todo.Open},
			{ID: 3, Command: "system", Title: "old thing", Priority: todo.Medium, Status: todo.Done},
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
	for _, s := range []string{"system", "environment", "packages", "1h", "10d", "never", "2 err", "2 high"} {
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
