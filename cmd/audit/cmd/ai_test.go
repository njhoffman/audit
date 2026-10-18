package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/todo"
)

// fakeAI writes an executable that saves its stdin and arguments next to
// itself and prints answer.
func fakeAI(t *testing.T, name, answer string) (path, stdin, argv string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, name)
	stdin, argv = filepath.Join(dir, "stdin"), filepath.Join(dir, "argv")
	script := "#!/bin/sh\n/bin/cat > '" + stdin + "'\nprintf '%s\\n' \"$@\" > '" + argv + "'\n/bin/cat <<'EOF'\n" + answer + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	return path, stdin, argv
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func claudeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seedScan saves a packages run with one broken executable and its task.
func seedScan(t *testing.T) {
	t.Helper()
	a, _, _ := loadedApp(t)
	s := &fakeScanner{findings: []finding.Finding{
		{Command: "packages", Check: "exe.broken", Severity: finding.Error, Subject: "black", Message: "black runs /gone/python",
			Details: []string{"interpreter /gone/python missing"}},
	}}
	if err := a.runScan(context.Background(), s, &scanFlags{}, nil); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, cfgHome, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeReview(t *testing.T) {
	cfgHome, _ := env(t)
	claude, stdin, argv := fakeAI(t, "claude", claudeJSON(t, map[string]any{"subtype": "success", "result": "## Root cause\n\nblack lost its python",
		"total_cost_usd": 0.02}))
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude+", model: m1}}\n")
	if r := runArgs(t, "analyze"); r.e == nil || !strings.Contains(r.e.Error(), "no command has run yet") {
		t.Fatalf("empty store: %v", r.e)
	}
	seedScan(t)
	r := runArgs(t, "analyze", "-L", "brief")
	if r.e != nil || !strings.Contains(r.out, "AI review of all commands") || !strings.Contains(r.out, "black lost its python") {
		t.Fatalf("review: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if p := readFile(t, stdin); !strings.Contains(p, "black runs /gone/python") || !strings.Contains(p, `"open_tasks"`) {
		t.Errorf("prompt:\n%s", p)
	}
	if a := readFile(t, argv); !strings.Contains(a, "m1") || !strings.Contains(a, "under 250 words") {
		t.Errorf("argv:\n%s", a)
	}
	// The second ask is served from the cache.
	if err := os.Remove(stdin); err != nil {
		t.Fatal(err)
	}
	r = runArgs(t, "analyze", "-L", "brief", "-j")
	var ans aiAnswer
	if r.e != nil || json.Unmarshal([]byte(r.out), &ans) != nil || !ans.Cached || ans.Text == "" {
		t.Errorf("cached json: %v %q", r.e, r.out)
	}
	if _, err := os.Stat(stdin); !os.IsNotExist(err) {
		t.Error("a cached answer must not run the CLI")
	}
}

func TestAnalyzeTasks(t *testing.T) {
	cfgHome, _ := env(t)
	answer := func(titles ...string) string {
		var sg []map[string]any
		for _, title := range titles {
			sg = append(sg, map[string]any{"title": title, "priority": "medium", "command": "packages",
				"details": []string{"evidence"}, "fix": "uv tool install --reinstall black", "related": []string{"exe.broken"}})
		}
		return claudeJSON(t, map[string]any{"subtype": "success", "result": "",
			"structured_output": map[string]any{"suggestions": sg}})
	}
	claude, _, argv := fakeAI(t, "claude", answer("Reinstall black on the current python", "Pin tools to a managed python"))
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude+"}}\n")
	seedScan(t)
	r := runArgs(t, "analyze", "-t")
	if r.e != nil || !strings.Contains(r.out, "Reinstall black on the current python") || !strings.Contains(r.err, "2 AI suggestion(s), 2 task(s) changed") {
		t.Fatalf("tasks: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if !strings.Contains(readFile(t, argv), "--json-schema") {
		t.Error("suggestions are asked with a schema")
	}

	// The user takes one on; the next analysis drops both suggestions.
	a, _, _ := loadedApp(t)
	ts, err := a.store.Todos(context.Background(), "packages")
	if err != nil {
		t.Fatal(err)
	}
	var pin int64
	for _, tk := range ts {
		if tk.Title == "Pin tools to a managed python" {
			pin = tk.ID
			if tk.Source != todo.FromAI || tk.Hint != "uv tool install --reinstall black" {
				t.Errorf("ai task: %+v", tk)
			}
		}
	}
	if _, err := a.store.SetTodoStatus(context.Background(), pin, todo.InProgress, nil, testNow); err != nil {
		t.Fatal(err)
	}
	a.close()
	claude2, _, _ := fakeAI(t, "claude", answer())
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude2+"}}\n")
	r = runArgs(t, "analyze", "-t", "-A")
	if r.e != nil || !strings.Contains(r.out, "Pin tools to a managed python") || strings.Contains(r.out, "Reinstall black") {
		t.Errorf("after the second analysis: %v\n%s", r.e, r.out)
	}
	// A rescan of packages leaves AI tasks under packages alone.
	seedScan(t)
	a, _, _ = loadedApp(t)
	ts, _ = a.store.Todos(context.Background(), "packages")
	for _, tk := range ts {
		if tk.ID == pin && tk.Status != todo.InProgress {
			t.Errorf("a rescan touched the AI task: %+v", tk)
		}
	}
}

func TestTodoExplain(t *testing.T) {
	cfgHome, _ := env(t)
	codex, stdin, argv := fakeAI(t, "codex", "## Cause\n\nThe interpreter was removed.")
	writeConfig(t, cfgHome, "ai: {provider: codex, codex: {command: "+codex+"}}\n")
	seedScan(t)
	r := runArgs(t, "todo", "explain", "1")
	if r.e != nil || !strings.Contains(r.out, "The interpreter was removed.") || !strings.Contains(r.out, "#1 ") {
		t.Fatalf("explain: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if p := readFile(t, stdin); !strings.Contains(p, "Explain task #1") || !strings.Contains(p, "interpreter /gone/python missing") ||
		!strings.HasPrefix(p, "Answer from the data in this message only.") {
		t.Errorf("codex prompt:\n%s", p)
	}
	if a := readFile(t, argv); !strings.Contains(a, "read-only") {
		t.Errorf("codex argv:\n%s", a)
	}
	if r := runArgs(t, "todo", "explain", "99"); r.e == nil {
		t.Error("unknown task must fail")
	}
}

func TestAIProviderFlag(t *testing.T) {
	cfgHome, _ := env(t)
	codex, stdin, _ := fakeAI(t, "codex", "codex says hi")
	writeConfig(t, cfgHome, "ai: {codex: {command: "+codex+"}, claude: {command: /nonexistent/claude}}\n")
	seedScan(t)
	if r := runArgs(t, "todo", "explain", "1"); r.e == nil || !strings.Contains(r.e.Error(), "not found") {
		t.Errorf("claude by default: %v", r.e)
	}
	r := runArgs(t, "-I", "codex", "todo", "explain", "1")
	if r.e != nil || !strings.Contains(r.out, "codex says hi") {
		t.Errorf("-I codex: %v\n%s", r.e, r.out)
	}
	if _, err := os.Stat(stdin); err != nil {
		t.Error("codex should have run")
	}
	if r := runArgs(t, "-I", "gemini", "todo", "explain", "1"); r.e == nil || !strings.Contains(r.e.Error(), "unknown AI provider") {
		t.Errorf("bad provider: %v", r.e)
	}
}

func TestExplainUpdateFailures(t *testing.T) {
	gh := updateEnv(t)
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	claude, stdin, _ := fakeAI(t, "claude", claudeJSON(t, map[string]any{"subtype": "success", "result": "The network was down."}))
	cfg := readFile(t, filepath.Join(cfgHome, "audit.yaml"))
	writeConfig(t, cfgHome, cfg+"ai: {claude: {command: "+claude+"}}\n")
	r := runUpdate(t, gh, false, "", "packages", "update", "-y", "-e")
	if r.e == nil || !strings.Contains(r.out, "Why these failed") || !strings.Contains(r.out, "The network was down.") {
		t.Fatalf("explain after update: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if p := readFile(t, stdin); !strings.Contains(p, `"item": "gh:bad"`) || !strings.Contains(p, "network error") ||
		strings.Contains(p, `"item": "gh:ok"`) {
		t.Errorf("failures prompt:\n%s", p)
	}
	r = runUpdate(t, gh, false, "", "packages", "update", "-L", "-e")
	if r.e != nil || !strings.Contains(r.out, "The network was down.") {
		t.Errorf("-L -e: %v\n%s", r.e, r.out)
	}
	if r := runUpdate(t, gh, false, "", "packages", "update", "-L", "-e", "-j"); r.e == nil {
		t.Error("--explain and --json are exclusive")
	}
}
