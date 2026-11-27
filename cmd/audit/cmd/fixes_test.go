package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/todo"
)

func TestHistoryRunsFixes(t *testing.T) {
	env(t)
	if r := runArgs(t, "history", "runs", "fixes"); r.e != nil || !strings.Contains(r.out, "Nothing recorded yet") {
		t.Fatalf("empty: %v %q", r.e, r.out)
	}
	a, _, _ := loadedApp(t)
	ctx := context.Background()
	at := testNow.Add(-3 * time.Hour)
	tk := todo.Todo{Key: "repos:repo.dirty:/r/a", Command: "repos", Check: "repo.dirty", Title: "commit /r/a", Priority: todo.Low,
		Status: todo.Open, Source: todo.FromFinding, CreatedAt: at, UpdatedAt: at, LastSeenAt: at}
	if err := a.store.SaveTodos(ctx, []todo.Todo{tk}); err != nil {
		t.Fatal(err)
	}
	ts, _ := a.store.Todos(ctx, "")
	tk = ts[0]
	tk.Status, tk.ResolvedAt, tk.UpdatedAt = todo.Resolved, testNow.Add(-2*time.Hour), testNow.Add(-2*time.Hour)
	if err := a.store.SaveTodos(ctx, []todo.Todo{tk}); err != nil {
		t.Fatal(err)
	}
	tk.Status, tk.ResolvedAt, tk.UpdatedAt = todo.Open, time.Time{}, testNow.Add(-time.Hour)
	if err := a.store.SaveTodos(ctx, []todo.Todo{tk}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveUpdate(ctx, &packages.Update{StartedAt: testNow, FinishedAt: testNow, Items: []packages.UpdateResult{
		{Manager: "uv", Name: "ruff", ID: "ruff", From: "0.8.0", To: "0.9.0", Status: packages.UpdateOK}}}); err != nil {
		t.Fatal(err)
	}
	a.close()

	r := runArgs(t, "history", "runs", "fixes")
	for _, w := range []string{"Tasks fixed", "repos", "1 low", "Steps done: 1 package.", "Reopened: 1 task(s)", "ruff 0.8.0 -> 0.9.0", "resolved", "reopened"} {
		if r.e != nil || !strings.Contains(r.out, w) {
			t.Errorf("missing %q: %v\n%s", w, r.e, r.out)
		}
	}
	if r := runArgs(t, "history", "runs", "fixes", "-s", "90m", "-j"); r.e != nil || strings.Count(r.out, `"kind"`) != 2 {
		t.Errorf("since: %v\n%s", r.e, r.out)
	}
	if r := runArgs(t, "todo", "show", "1"); r.e != nil || !strings.Contains(r.out, "fixed before: resolved by a rescan on") {
		t.Errorf("a reopened task says it was fixed before: %v\n%s", r.e, r.out)
	}
}
