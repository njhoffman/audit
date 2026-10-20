package fzf

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/keys"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

func testInterface() Interface {
	return Interface{Self: []string{"/opt/my audit/audit", "-c", "/tmp/it's.yaml"}, Keys: keys.FzfDefaults()}
}

func TestSelfQuotes(t *testing.T) {
	got := testInterface().helper("preview", "task", "{1}")
	want := `'/opt/my audit/audit' '-c' '/tmp/it'\''s.yaml' 'fzf-helper' 'preview' 'task' {1}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAct(t *testing.T) {
	if got := act("reload", "a b"); got != "reload(a b)" {
		t.Error(got)
	}
	if got := act("reload", "x) y]"); got != "reload{x) y]}" {
		t.Error(got)
	}
}

// bindFor returns the action string bound to key.
func bindFor(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--bind" {
			continue
		}
		ks, action, _ := strings.Cut(args[i+1], ":")
		if slices.Contains(strings.Split(ks, ","), key) {
			return action
		}
	}
	return ""
}

func TestTasksArgs(t *testing.T) {
	in := testInterface()
	in.Keys[keys.StatusDone] = []string{"alt-d", "ctrl-d"}
	in.Keys[keys.Note] = nil
	args := in.TasksArgs(State{Command: "system", Closed: true}, "sshd")
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"--prompt\x00tasks system +closed> ", "--query\x00sshd", "nohidden"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %q", want, args)
		}
	}
	done := bindFor(args, "ctrl-d")
	if done == "" || done != bindFor(args, "alt-d") || !strings.Contains(done, `'todo' 'set' {1} 'done'`) ||
		!strings.Contains(done, "+reload(") || !strings.HasPrefix(done, "execute-silent(") {
		t.Errorf("status_done bind: %q", done)
	}
	if bindFor(args, "alt-n") != "" {
		t.Error("an unbound action has no bind")
	}
	if !strings.HasPrefix(bindFor(args, "alt-a"), "transform(") || !strings.HasPrefix(bindFor(args, "enter"), "execute(") {
		t.Errorf("toggle/open binds: %q", args)
	}
	header := args[slices.Index(args, "--header")+1]
	if !strings.Contains(header, "alt-d done") || strings.Contains(header, "note") || !strings.HasSuffix(header, "esc quit") {
		t.Errorf("header: %q", header)
	}
	for _, l := range strings.Split(header, "\n") {
		if len(l) > headerWidth {
			t.Errorf("header line too long: %q", l)
		}
	}
}

func TestDashboardArgs(t *testing.T) {
	args := testInterface().DashboardArgs()
	if !strings.Contains(bindFor(args, "alt-r"), "'rescan' {1}") || !strings.Contains(bindFor(args, "alt-t"), `'todo' '--fzf'`) {
		t.Errorf("dashboard binds: %q", args)
	}
	if bindFor(args, "alt-d") != "" {
		t.Error("task actions are not bound on the command list")
	}
}

func TestStatePrompt(t *testing.T) {
	for _, s := range []State{{}, {Command: "system"}, {Closed: true}, {Command: "ai", Closed: true}} {
		if got := ParsePrompt(s.Prompt()); got != s {
			t.Errorf("%+v -> %q -> %+v", s, s.Prompt(), got)
		}
	}
	if got := (State{}).Prompt(); got != "tasks> " {
		t.Error(got)
	}
}

func TestSwitch(t *testing.T) {
	got := testInterface().Switch(State{Closed: true})
	if !strings.HasPrefix(got, "change-prompt(tasks +closed> )+reload(") || !strings.HasSuffix(got, "'lines' 'tasks')+first") {
		t.Error(got)
	}
}

func TestFilterEncoding(t *testing.T) {
	f := Filter{Priorities: []todo.Priority{todo.High, todo.Low}, Statuses: []todo.Status{todo.InProgress}}
	if got := DecodeFilter(f.Encode()); !reflect.DeepEqual(got, f) {
		t.Errorf("%+v", got)
	}
	if got := DecodeFilter(""); !reflect.DeepEqual(got, Filter{}) {
		t.Errorf("%+v", got)
	}
}

func TestTaskLines(t *testing.T) {
	ts := []todo.Todo{
		{ID: 1, Command: "system", Title: "fix sshd", Priority: todo.High, Status: todo.Open},
		{ID: 2, Command: "packages", Title: "remove orphan", Priority: todo.Low, Status: todo.Open},
		{ID: 3, Command: "system", Title: "old thing", Priority: todo.Medium, Status: todo.Done},
	}
	ids := func(lines []string) []string {
		var out []string
		for _, l := range lines {
			out = append(out, strings.Fields(l)[0])
		}
		return out
	}
	if got := ids(TaskLines(ts, State{}, Filter{})); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Errorf("open: %v", got)
	}
	if got := ids(TaskLines(ts, State{Command: "system", Closed: true}, Filter{})); !reflect.DeepEqual(got, []string{"1", "3"}) {
		t.Errorf("system with closed: %v", got)
	}
	if got := ids(TaskLines(ts, State{}, Filter{Priorities: []todo.Priority{todo.Low}})); !reflect.DeepEqual(got, []string{"2"}) {
		t.Errorf("low only: %v", got)
	}
	if l := TaskLines(ts, State{}, Filter{})[0]; !strings.HasSuffix(l, "fix sshd") || !strings.Contains(l, " open ") || !strings.Contains(l, " high ") {
		t.Errorf("line: %q", l)
	}
	cmds := Commands(ts)
	if !reflect.DeepEqual(cmds, []string{"system", "packages"}) || Next(cmds, "") != "system" ||
		Next(cmds, "system") != "packages" || Next(cmds, "packages") != "" || Next(nil, "") != "" {
		t.Errorf("cycle: %v", cmds)
	}
}

func TestDashboardLines(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	th := config.Thresholds{Warn: time.Hour, Old: 2 * time.Hour}
	lines := DashboardLines([]render.CommandStatus{
		{Command: "system", Thresholds: th, Latest: &store.RunInfo{FinishedAt: now.Add(-time.Hour), Counts: finding.Counts{finding.Error: 2}}},
		{Command: "packages", Thresholds: th},
	}, now)
	if len(lines) != 2 || strings.Fields(lines[0])[0] != "system" || !strings.Contains(lines[0], "1h") ||
		!strings.Contains(lines[0], "2 err") || !strings.Contains(lines[1], "never") {
		t.Errorf("%q", lines)
	}
}
