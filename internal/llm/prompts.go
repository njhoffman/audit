package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

const workstation = "You help the owner of a single Linux workstation act on the results of `audit`, a tool that " +
	"scans the system (processes, services, users, logs, program configs), the shell environment and the " +
	"user-level package managers and runtimes. "

func levelText(level string) string {
	switch NormalizeLevel(level) {
	case "brief":
		return " Keep it under 250 words."
	case "deep":
		return " Be thorough: explain causes, impact and remediation, and cross-reference related items."
	}
	return " Be balanced: roughly 300 to 600 words."
}

// OverviewInput is everything the cross-command review sees.
type OverviewInput struct {
	// Runs are the latest saved run of each command that has run.
	Runs []*run.Run
	// Tasks are the open and in-progress tasks.
	Tasks []todo.Todo
	// Update is the last package or runtime update, when one failed items.
	Update *packages.Update
}

type overviewRun struct {
	Command  string          `json:"command"`
	Scope    string          `json:"scope,omitempty"`
	Stats    []run.Stat      `json:"stats,omitempty"`
	Errors   []string        `json:"scan_errors,omitempty"`
	Findings []promptFinding `json:"findings"`
}

type overviewTask struct {
	ID       int64         `json:"id"`
	Command  string        `json:"command"`
	Priority todo.Priority `json:"priority"`
	Status   todo.Status   `json:"status"`
	Title    string        `json:"title"`
	Note     string        `json:"note,omitempty"`
}

type promptFailure struct {
	Kind    string `json:"kind"`
	Item    string `json:"item"`
	From    string `json:"from,omitempty"`
	Target  string `json:"target,omitempty"`
	Command string `json:"command,omitempty"`
	Reason  string `json:"reason"`
	Output  string `json:"output_tail,omitempty"`
}

func capFindings(fs []finding.Finding, maxDetails int) []promptFinding {
	if maxDetails <= 0 {
		maxDetails = DefaultMaxDetails
	}
	out := make([]promptFinding, len(fs))
	for i, f := range fs {
		details := f.Details
		if len(details) > maxDetails {
			details = append(append([]string{}, details[:maxDetails]...), fmt.Sprintf("(%d more)", len(f.Details)-maxDetails))
		}
		out[i] = promptFinding{Check: f.Check, Severity: f.Severity, Kind: f.Kind, Subject: f.Subject,
			Message: f.Message, Hint: f.Hint, Details: details}
	}
	return out
}

func failures(u *packages.Update, outputLines int) []promptFailure {
	if u == nil {
		return nil
	}
	var out []promptFailure
	for _, it := range u.Items {
		if it.Status != packages.UpdateFailed {
			continue
		}
		lines := strings.Split(strings.TrimSpace(it.Output), "\n")
		if len(lines) > outputLines {
			lines = lines[len(lines)-outputLines:]
		}
		out = append(out, promptFailure{Kind: it.KindOrDefault(), Item: it.Manager + ":" + it.Name, From: it.From,
			Target: it.Latest, Command: it.Command, Reason: it.Reason, Output: strings.Join(lines, "\n")})
	}
	return out
}

func overviewPayload(in OverviewInput, maxDetails int) string {
	runs := make([]overviewRun, 0, len(in.Runs))
	for _, r := range in.Runs {
		runs = append(runs, overviewRun{Command: r.Command, Scope: r.Scope, Stats: r.Stats, Errors: r.Errors,
			Findings: capFindings(r.Findings, maxDetails)})
	}
	tasks := make([]overviewTask, 0, len(in.Tasks))
	for _, t := range in.Tasks {
		tasks = append(tasks, overviewTask{ID: t.ID, Command: t.Command, Priority: t.Priority, Status: t.Status,
			Title: t.Title, Note: t.Note})
	}
	payload := struct {
		Runs     []overviewRun   `json:"runs"`
		Tasks    []overviewTask  `json:"open_tasks"`
		Failures []promptFailure `json:"failed_updates,omitempty"`
	}{runs, tasks, failures(in.Update, 15)}
	b, _ := json.MarshalIndent(payload, "", " ")
	return "```json\n" + string(b) + "\n```\n"
}

// OverviewRequest asks for one review across every command's latest
// results, the open tasks and the last failed updates: shared root causes,
// the errors that matter, and an order to work in. Timestamps are left out
// so unchanged results hit the cache.
func OverviewRequest(in OverviewInput, level string, maxDetails int) Request {
	sys := workstation + "You receive the latest results of every audit command, the open tasks and any failed " +
		"package or runtime updates as JSON. Look for errors and problems that share a root cause across " +
		"commands, explain which ones matter and why, give a prioritized plan with concrete fixes (commands or " +
		"config edits), and name tasks by their #id when you refer to them. Point out findings that look like " +
		"noise. Answer in markdown with short headings and bullet lists. Do not use emojis." + levelText(level)
	return Request{System: sys, Prompt: fmt.Sprintf("Review this workstation (analysis level: %s).\n\n%s",
		NormalizeLevel(level), overviewPayload(in, maxDetails))}
}

// Suggestion is one AI-proposed task.
type Suggestion struct {
	Title    string   `json:"title"`
	Priority string   `json:"priority"`
	Command  string   `json:"command"`
	Details  []string `json:"details"`
	Fix      string   `json:"fix"`
	Related  []string `json:"related"`
}

// Suggestions is the structured answer of SuggestionsRequest.
type Suggestions struct {
	Suggestions []Suggestion `json:"suggestions"`
}

// suggestionSchema is strict (every property required, no extras) because
// codex's structured output demands it.
const suggestionSchema = `{"type":"object","additionalProperties":false,"required":["suggestions"],
"properties":{"suggestions":{"type":"array","items":{"type":"object","additionalProperties":false,
"required":["title","priority","command","details","fix","related"],
"properties":{"title":{"type":"string"},
"priority":{"type":"string","enum":["high","medium","low","suggestion"]},
"command":{"type":"string","enum":["system","environment","packages","general"]},
"details":{"type":"array","items":{"type":"string"}},
"fix":{"type":"string"},
"related":{"type":"array","items":{"type":"string"}}}}}}}`

// SuggestionsRequest asks for improvements the checks do not already track
// as tasks, as structured suggestions.
func SuggestionsRequest(in OverviewInput, maxDetails int) Request {
	sys := workstation + "You receive the latest results of every audit command, the open tasks and any failed " +
		"updates as JSON. Propose at most 10 concrete tasks that are NOT already covered by an open task: " +
		"fixes for root causes shared by several findings, errors whose cause the findings imply, and " +
		"improvements to structure or redundancy. Each has a short imperative title (under 80 characters), a " +
		"priority, the audit command it concerns (or general), detail lines with the evidence, a fix (shell " +
		"commands or config edits, empty when there is none), and related check names or task ids as #id. " +
		"Return an empty list when nothing is worth adding. Do not use emojis."
	return Request{System: sys, Schema: suggestionSchema,
		Prompt: "Suggest tasks for this workstation.\n\n" + overviewPayload(in, maxDetails)}
}

// ExplainTaskRequest asks why a task's problem happens and how to fix it.
// fs are the saved findings behind the task, with every detail line.
func ExplainTaskRequest(t todo.Todo, fs []finding.Finding, level string) Request {
	payload := struct {
		Task     overviewTask    `json:"task"`
		Check    string          `json:"check,omitempty"`
		Hint     string          `json:"hint,omitempty"`
		Details  []string        `json:"details,omitempty"`
		Findings []promptFinding `json:"findings,omitempty"`
	}{overviewTask{ID: t.ID, Command: t.Command, Priority: t.Priority, Status: t.Status, Title: t.Title, Note: t.Note},
		t.Check, t.Hint, t.Details, capFindings(fs, 50)}
	b, _ := json.MarshalIndent(payload, "", " ")
	sys := workstation + "You receive one task with the findings behind it as JSON. Explain what the problem " +
		"is, the most likely cause, whether it matters, and the steps to fix it with exact commands, then how " +
		"to confirm the fix (usually rescanning with `audit " + t.Command + " -r`). Say when it is safe to " +
		"ignore. Answer in markdown. Do not use emojis." + levelText(level)
	return Request{System: sys, Prompt: fmt.Sprintf("Explain task #%d.\n\n```json\n%s\n```\n", t.ID, b)}
}

// ExplainFailuresRequest asks why the failed items of an update failed and
// what to do about each; ok is false when nothing failed.
func ExplainFailuresRequest(u *packages.Update, level string) (Request, bool) {
	fails := failures(u, 40)
	if len(fails) == 0 {
		return Request{}, false
	}
	b, _ := json.MarshalIndent(fails, "", " ")
	sys := workstation + "You receive the failed items of a package update, runtime update or migration: the " +
		"command that ran, the reason and the tail of its output. For each, say what went wrong and the most " +
		"likely fix, with exact commands; group items that fail for the same reason. Answer in markdown. Do " +
		"not use emojis." + levelText(level)
	return Request{System: sys, Prompt: "Explain these update failures.\n\n```json\n" + string(b) + "\n```\n"}, true
}

// SuggestedTodos turns suggestions into AI tasks. A suggestion's command
// must be a scanning command; anything else files it under "ai".
func SuggestedTodos(s Suggestions, commands []string) []todo.Todo {
	var out []todo.Todo
	for _, sg := range s.Suggestions {
		title := strings.TrimSpace(sg.Title)
		if title == "" {
			continue
		}
		p, err := todo.ParsePriority(sg.Priority)
		if err != nil {
			p = todo.Suggestion
		}
		cmd := todo.AICommand
		for _, c := range commands {
			if c == sg.Command {
				cmd = c
			}
		}
		details := append([]string{}, sg.Details...)
		if len(sg.Related) > 0 {
			details = append(details, "related: "+strings.Join(sg.Related, ", "))
		}
		out = append(out, todo.Todo{Key: todo.AIKey(title), Command: cmd, Title: title, Hint: strings.TrimSpace(sg.Fix),
			Details: details, Priority: p, Status: todo.Open, Source: todo.FromAI})
	}
	return out
}

// ScriptInput is one script sent for a description.
type ScriptInput struct {
	Path    string
	Lang    string
	Content string
}

// ScriptDescriptions is the structured answer of DescribeScriptsRequest.
type ScriptDescriptions struct {
	Descriptions []struct {
		Path        string `json:"path"`
		Description string `json:"description"`
	} `json:"descriptions"`
}

const scriptSchema = `{"type":"object","additionalProperties":false,"required":["descriptions"],
"properties":{"descriptions":{"type":"array","items":{"type":"object","additionalProperties":false,
"required":["path","description"],"properties":{"path":{"type":"string"},"description":{"type":"string"}}}}}}`

// maxScriptBytes bounds each script's content in the prompt.
const maxScriptBytes = 4000

// DescribeScriptsRequest asks for a one-sentence description of each script.
func DescribeScriptsRequest(ss []ScriptInput) Request {
	var b strings.Builder
	b.WriteString("Describe each of these scripts.\n")
	for _, s := range ss {
		content := s.Content
		if len(content) > maxScriptBytes {
			content = content[:maxScriptBytes] + "\n[truncated]"
		}
		fmt.Fprintf(&b, "\n=== %s (%s) ===\n%s\n", s.Path, s.Lang, content)
	}
	sys := workstation + "You receive scripts from the owner's bin directories. For each, write one plain sentence " +
		"(under 25 words) saying what it does and when it is used, starting with a verb (\"Opens...\", \"Syncs...\"). " +
		"Use the path exactly as given. Do not use emojis."
	return Request{System: sys, Prompt: b.String(), Schema: scriptSchema}
}
