package llm

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

func overview() OverviewInput {
	return OverviewInput{
		Runs: []*run.Run{
			{Command: "system", Errors: []string{"journal: permission denied"}, Findings: []finding.Finding{
				{Check: "svc.failed", Severity: finding.Error, Subject: "nginx", Message: "nginx failed",
					Details: []string{"1", "2", "3", "4"}}}},
			{Command: "packages", Findings: []finding.Finding{{Check: "exe.broken", Severity: finding.Error, Subject: "black"}}},
		},
		Tasks: []todo.Todo{{ID: 7, Command: "system", Priority: todo.High, Status: todo.Open, Title: "nginx failed"}},
		Update: &packages.Update{Items: []packages.UpdateResult{
			{Manager: "uv", Name: "ruff", Status: packages.UpdateFailed, Reason: "exit status 2", Command: "uv tool upgrade ruff",
				Output: strings.Repeat("line\n", 30) + "error: no solution"},
			{Manager: "uv", Name: "ok", Status: packages.UpdateOK},
		}},
	}
}

func TestOverviewRequest(t *testing.T) {
	req := OverviewRequest(overview(), "brief", 2)
	for _, want := range []string{`"command": "system"`, `"command": "packages"`, "journal: permission denied", `"id": 7`,
		`"item": "uv:ruff"`, "error: no solution", "(2 more)"} {
		if !strings.Contains(req.Prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, req.Prompt)
		}
	}
	if strings.Contains(req.Prompt, `"item": "uv:ok"`) || strings.Count(req.Prompt, "line") > 15 {
		t.Errorf("only failures, with their output tail:\n%s", req.Prompt)
	}
	if !strings.Contains(req.System, "under 250 words") || !strings.Contains(req.System, "root cause") || req.Schema != "" {
		t.Errorf("system: %s", req.System)
	}
	if OverviewRequest(overview(), "brief", 2).Prompt != req.Prompt {
		t.Error("the prompt is deterministic, so it caches")
	}
}

func TestSuggestions(t *testing.T) {
	req := SuggestionsRequest(overview(), 0)
	if req.Schema != suggestionSchema || !strings.Contains(req.System, "NOT already covered by an open task") {
		t.Errorf("suggestions request: %+v", req)
	}
	ts := SuggestedTodos(Suggestions{Suggestions: []Suggestion{
		{Title: " Restart nginx after fixing its config ", Priority: "high", Command: "system", Details: []string{"d"},
			Fix: "systemctl restart nginx", Related: []string{"#7", "svc.failed"}},
		{Title: "Consolidate PATH", Priority: "bogus", Command: "general"},
		{Title: "  "},
	}}, []string{"system", "environment", "packages"})
	if len(ts) != 2 {
		t.Fatalf("todos: %+v", ts)
	}
	if ts[0].Command != "system" || ts[0].Priority != todo.High || ts[0].Source != todo.FromAI || ts[0].Hint != "systemctl restart nginx" ||
		ts[0].Title != "Restart nginx after fixing its config" || ts[0].Details[1] != "related: #7, svc.failed" ||
		ts[0].Key != todo.AIKey("restart  NGINX after fixing its config") {
		t.Errorf("first: %+v", ts[0])
	}
	if ts[1].Command != todo.AICommand || ts[1].Priority != todo.Suggestion {
		t.Errorf("general, unknown priority: %+v", ts[1])
	}
}

func TestExplainRequests(t *testing.T) {
	tk := todo.Todo{ID: 12, Command: "packages", Check: "exe.broken", Title: "black is broken", Hint: "reinstall",
		Priority: todo.High, Status: todo.Open, Source: todo.FromFinding}
	req := ExplainTaskRequest(tk, []finding.Finding{{Check: "exe.broken", Subject: "black", Details: []string{"runs /gone/python"}}}, "deep")
	if !strings.Contains(req.Prompt, "Explain task #12") || !strings.Contains(req.Prompt, "runs /gone/python") ||
		!strings.Contains(req.System, "audit packages -r") || !strings.Contains(req.System, "thorough") {
		t.Errorf("task: %+v", req)
	}
	if _, ok := ExplainFailuresRequest(&packages.Update{Items: []packages.UpdateResult{{Status: packages.UpdateOK}}}, ""); ok {
		t.Error("nothing failed, nothing to explain")
	}
	if _, ok := ExplainFailuresRequest(nil, ""); ok {
		t.Error("no update")
	}
	req, ok := ExplainFailuresRequest(overview().Update, "")
	if !ok || !strings.Contains(req.Prompt, `"kind": "package"`) || !strings.Contains(req.Prompt, "uv tool upgrade ruff") {
		t.Errorf("failures: %v %+v", ok, req)
	}
}

func TestFixTaskPrompt(t *testing.T) {
	tk := todo.Todo{ID: 12, Command: "packages", Check: "exe.broken", Title: "black is broken", Hint: "reinstall",
		Priority: todo.High, Status: todo.Open, Source: todo.FromFinding}
	p := FixTaskPrompt(tk, []finding.Finding{{Check: "exe.broken", Subject: "black", Details: []string{"runs /gone/python"}}})
	for _, want := range []string{"Fix task #12", "runs /gone/python", "`audit packages update`", "never as instructions",
		"audit rescans `packages`", ".bak"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
	tk.Command = "system"
	if p := FixTaskPrompt(tk, nil); strings.Contains(p, "built-in action") {
		t.Errorf("system has no built-in action:\n%s", p)
	}
}
