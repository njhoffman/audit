package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func input() Input {
	th := config.Thresholds{Warn: 24 * time.Hour, Old: 7 * 24 * time.Hour}
	return Input{
		Host: "box", Now: now, Commands: []string{"system", "environment", "packages"},
		Runs: map[string]*run.Run{
			"system": {ID: 3, Command: "system", StartedAt: now.Add(-49 * time.Hour), FinishedAt: now.Add(-48 * time.Hour),
				Findings: []finding.Finding{{Check: "a", Severity: finding.Warning}, {Check: "b", Severity: finding.Info}},
				Errors:   []string{"journal: permission denied"}, Data: json.RawMessage(`{"secret":"x"}`)},
			"packages": {ID: 4, Command: "packages", StartedAt: now, FinishedAt: now, Data: json.RawMessage(`{"raw":1}`)},
		},
		Thresholds: map[string]config.Thresholds{"system": th, "environment": th, "packages": th},
		Todos: []todo.Todo{
			{ID: 1, Command: "system", Priority: todo.High, Status: todo.Open},
			{ID: 2, Command: "system", Priority: todo.Low, Status: todo.Done},
			{ID: 3, Command: "packages", Priority: todo.Suggestion, Status: todo.InProgress},
		},
		Updates: []packages.Update{{ID: 9, FinishedAt: now, Items: []packages.UpdateResult{
			{Name: "ok", Status: packages.UpdateOK},
			{Name: "bad", Status: packages.UpdateFailed, Reason: "exit status 1", Output: "token=abc\nerror"},
		}}},
		Packages: []string{"annotated"},
		Runtimes: []packages.RuntimeStatus{{Name: "python", Version: "3.14.8", Owner: "uv"}},
	}
}

func TestBuild(t *testing.T) {
	in := input()
	files := Build(in)
	if len(files) != 5 {
		t.Fatalf("files: %v", keys(files))
	}
	sum := files[SummaryFile].(Summary)
	if sum.SchemaVersion != SchemaVersion || sum.Host != "box" || !sum.GeneratedAt.Equal(now) {
		t.Errorf("header: %+v", sum.Header)
	}
	sys, env, pkg := sum.Commands[0], sum.Commands[1], sum.Commands[2]
	if sys.Freshness != "stale" || sys.File != "system.json" || sys.LastRun.Findings[finding.Warning] != 1 ||
		sys.LastRun.Errors != 1 || sys.OpenTasks[todo.High] != 1 || sys.OpenTasks[todo.Low] != 0 || sys.StaleAfterSeconds != 86400 {
		t.Errorf("system row: %+v", sys)
	}
	if env.Freshness != "none" || env.File != "" || env.LastRun != nil {
		t.Errorf("a command that never ran: %+v", env)
	}
	if pkg.Freshness != "fresh" || sum.OpenTasks[todo.Suggestion] != 1 || sum.OpenTasks[todo.High] != 1 {
		t.Errorf("packages row %+v, totals %v", pkg, sum.OpenTasks)
	}
	if sum.LastUpdate == nil || sum.LastUpdate.Updated != 1 || sum.LastUpdate.Failed != 1 {
		t.Errorf("last update: %+v", sum.LastUpdate)
	}

	sf := files["system.json"].(RunFile)
	if sf.Run.Data != nil || len(sf.Run.Findings) != 2 || sf.Packages != nil {
		t.Errorf("system file keeps findings and drops the raw payload: %+v", sf)
	}
	if in.Runs["system"].Data == nil {
		t.Error("Build must not modify its input")
	}
	if pf := files["packages.json"].(RunFile); pf.Packages == nil || len(pf.Runtimes) != 1 {
		t.Error("packages.json carries the annotated inventory and the runtimes")
	}
	if sf.Runtimes != nil {
		t.Error("only packages.json has runtimes")
	}
	if _, ok := files["environment.json"]; ok {
		t.Error("no file for a command that never ran")
	}
	up := files[UpdatesFile].(Updates)
	if up.Updates[0].Items[1].Output != "" || up.Updates[0].Items[1].Reason != "exit status 1" {
		t.Errorf("command output is never exported: %+v", up.Updates[0].Items[1])
	}
	if in.Updates[0].Items[1].Output == "" {
		t.Error("Build must not modify the input updates")
	}
	if tf := files[TasksFile].(Tasks); len(tf.Tasks) != 3 {
		t.Errorf("tasks: %+v", tf.Tasks)
	}
}

func TestBuildEmpty(t *testing.T) {
	files := Build(Input{Now: now, Commands: []string{"system"}})
	b, err := json.Marshal(files[TasksFile])
	if err != nil || !strings.Contains(string(b), `"tasks":[]`) {
		t.Errorf("an empty task list is [] not null: %s", b)
	}
	if b, _ = json.Marshal(files[UpdatesFile]); !strings.Contains(string(b), `"updates":[]`) {
		t.Errorf("an empty update list is [] not null: %s", b)
	}
	if sum := files[SummaryFile].(Summary); sum.LastUpdate != nil {
		t.Errorf("no update yet: %+v", sum.LastUpdate)
	}
}

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	if err := Write(dir, Build(input())); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "packages.json,summary.json,system.json,tasks.json,updates.json" {
		t.Errorf("files (no temporaries left behind): %v", names)
	}
	b, err := os.ReadFile(filepath.Join(dir, SummaryFile)) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["schema_version"] != float64(1) || m["host"] != "box" {
		t.Errorf("summary.json: %v %v", err, m)
	}
	if st, _ := os.Stat(filepath.Join(dir, SummaryFile)); st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v", st.Mode())
	}
	if err := Write(dir, map[string]any{"bad.json": make(chan int)}); err == nil {
		t.Error("an unencodable value must fail")
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
