package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/taskserver"
	"github.com/njhoffman/audit/internal/todo"
)

func TestTodoHTML(t *testing.T) {
	_, dataHome := env(t)
	reports := filepath.Join(dataHome, "audit", "reports")
	if r := runArgs(t, "todo", "add", "check", "the", "</script>", "backups"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runArgs(t, "todo", "-H")
	if r.e != nil || !strings.Contains(r.err, "tasks: "+filepath.Join(reports, "tasks.html")) || r.out != "" {
		t.Fatalf("todo -H: %q %q %v", r.out, r.err, r.e)
	}
	page, err := os.ReadFile(filepath.Join(reports, "tasks.html")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `check the \u003c/script\u003e backups`) {
		t.Errorf("task missing or unescaped in page")
	}
	index, _ := os.ReadFile(filepath.Join(reports, "index.html")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(index), `href="tasks.html"`) {
		t.Errorf("index should link the tasks page")
	}

	// A later change refreshes the existing page on exit.
	if r := runArgs(t, "todo", "set", "1", "wont-do"); r.e != nil || r.err != "" {
		t.Fatal(r.e, r.err)
	}
	page, _ = os.ReadFile(filepath.Join(reports, "tasks.html")) // #nosec G304 -- test temp dir
	if !strings.Contains(string(page), `"status":"wont_do"`) {
		t.Errorf("tasks page not refreshed after a status change")
	}

	if r := runArgs(t, "todo", "-o"); r.e == nil || !strings.Contains(r.e.Error(), "opener called") {
		t.Errorf("--open should open the page: %v", r.e)
	}
	for _, args := range [][]string{{"todo", "-H", "-j"}, {"todo", "-s", "-i"}} {
		if r := runArgs(t, args...); r.e == nil {
			t.Errorf("%v should fail", args)
		}
	}
}

func TestTodoShowLines(t *testing.T) {
	env(t)
	a, out, _ := loadedApp(t)
	ts := []todo.Todo{{Key: "scripts:script.shellcheck:shellcheck.high:*", Command: "scripts", Title: "Fix shellcheck errors in 2 scripts",
		Priority: todo.High, Status: todo.Open, Source: todo.FromAggregate,
		Details: []string{"/home/u/bin/a:3: SC2276 bad", "/home/u/bin/b:9: SC2086 quote"}}}
	if err := a.store.SaveTodos(context.Background(), ts); err != nil {
		t.Fatal(err)
	}
	a.close()
	_ = out
	r := runArgs(t, "todo", "show", "1", "-l")
	if r.e != nil || r.out != "/home/u/bin/a:3: SC2276 bad\n/home/u/bin/b:9: SC2086 quote\n" {
		t.Errorf("show -l: %q %v", r.out, r.e)
	}
	if r := runArgs(t, "todo", "show", "1", "-l", "-j"); r.e == nil {
		t.Error("--lines and --json are exclusive")
	}
}

func TestServeTasks(t *testing.T) {
	env(t)
	a, _, errOut := loadedApp(t)
	if err := a.store.SaveTodos(context.Background(), []todo.Todo{{Key: "manual:x", Command: "manual", Title: "rotate keys",
		Priority: todo.Medium, Status: todo.Open, Source: todo.Manual}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	urls := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- a.serveTasks(ctx, 0, false, func(u string) { urls <- u }) }()
	var url string
	select {
	case url = <-urls:
	case err := <-done:
		t.Fatalf("server stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.Contains(url, "/?token=") {
		t.Fatalf("url %q", url)
	}
	resp, err := http.Get(url) // #nosec G107 -- local test server
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "rotate keys") {
		t.Fatalf("page %d", resp.StatusCode)
	}

	token := url[strings.Index(url, "token=")+len("token="):]
	base, _, _ := strings.Cut(url, "/?")
	req, _ := http.NewRequest("POST", base+"/api/tasks/1", strings.NewReader(`{"status":"done","note":"rotated"}`))
	req.Header.Set(taskserver.TokenHeader, token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got todo.Todo
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || got.Status != todo.Done || got.Note != "rotated" {
		t.Fatalf("change: %d %+v", resp.StatusCode, got)
	}
	saved, err := a.store.GetTodo(context.Background(), 1)
	if err != nil || saved.Status != todo.Done || saved.Note != "rotated" {
		t.Errorf("not saved: %+v %v", saved, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop")
	}
	if !strings.Contains(errOut.String(), "serving tasks at http://127.0.0.1:") {
		t.Errorf("no URL printed: %q", errOut.String())
	}
}
