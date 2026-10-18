package cmd

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/todo"
)

// aiClient builds the client of the configured provider (or
// --ai-provider); level overrides the configured analysis level when set.
func (a *app) aiClient(level string) *llm.Client {
	if level != "" {
		a.cfg.AI.AnalysisLevel = level
	}
	name, pc := a.cfg.AI.For(a.flags.aiProvider)
	return &llm.Client{Runner: exec.NewOSRunner(a.env), Provider: name, Command: pc.Command, Model: pc.Model,
		Timeout: a.cfg.AI.Timeout, Cache: a.store}
}

func checkProvider(p string) error {
	if p != "" && !slices.Contains(config.Providers, p) {
		return fmt.Errorf("unknown AI provider %q; choose from %s", p, strings.Join(config.Providers, ", "))
	}
	return nil
}

// aiAnswer is what the AI commands print as JSON.
type aiAnswer struct {
	Text    string    `json:"text"`
	Model   string    `json:"model,omitempty"`
	Cached  bool      `json:"cached"`
	CostUSD float64   `json:"cost_usd,omitempty"`
	At      time.Time `json:"created_at"`
}

func answerOf(r *llm.Response) aiAnswer {
	return aiAnswer{Text: r.Text, Model: r.Model, Cached: r.Cached, CostUSD: r.CostUSD, At: r.CreatedAt}
}

// ask runs one request behind a spinner.
func (a *app) ask(ctx context.Context, c *llm.Client, req llm.Request, refresh, bar bool, what string) (*llm.Response, error) {
	rep := a.progress(bar)
	rep.Phase(what+" ("+c.Label()+")", 0)
	defer rep.Done()
	return c.Ask(ctx, req, refresh)
}

func (a *app) printAnswer(title string, r *llm.Response) {
	a.printer().AI(title, r.Model, r.Cached, r.CreatedAt, r.CostUSD, r.Text)
}

type aiFlags struct {
	refresh bool
	level   string
	json    bool
}

func addAIFlags(c *cobra.Command, f *aiFlags) {
	fl := c.Flags()
	fl.BoolVarP(&f.refresh, "ai-refresh", "A", false, "ask again instead of using the cached answer")
	fl.StringVarP(&f.level, "level", "L", "", "analysis level: brief, standard or deep (default from config)")
	fl.BoolVarP(&f.json, "json", "j", false, "print the answer as JSON")
}

func newAnalyzeCmd(a *app) *cobra.Command {
	var f aiFlags
	var tasks bool
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Review every command's saved results together with AI",
		Long: `Send the latest saved results of every command, the open tasks and the last
failed package or runtime update to the AI CLI (ai.provider, or
--ai-provider) and print its review: problems that share a root cause
across commands, the errors that matter and an order to fix them in.
Nothing is scanned; run the commands first for fresh results.

--tasks asks instead for structured suggestions not already tracked, and
files them as tasks with source "ai" under the command they concern (or
"ai"). A later --tasks run keeps the suggestions it repeats, adds new ones
and resolves open AI tasks it no longer suggests; tasks you moved to in
progress, done or won't do keep their status. Answers are cached by
prompt, so unchanged results cost nothing; --ai-refresh asks again.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			return a.analyze(c.Context(), f, tasks)
		},
	}
	addAIFlags(c, &f)
	c.Flags().BoolVarP(&tasks, "tasks", "t", false, "file AI suggestions as tasks instead of printing a review")
	return c
}

// overviewInput collects the saved state the cross-command prompts read.
func (a *app) overviewInput(ctx context.Context) (llm.OverviewInput, error) {
	var in llm.OverviewInput
	for _, cmd := range core.Commands {
		r, err := a.engine.Saved(ctx, cmd, "")
		if err != nil {
			return in, err
		}
		if r != nil {
			in.Runs = append(in.Runs, r)
		}
	}
	ts, err := a.store.Todos(ctx, "")
	if err != nil {
		return in, err
	}
	for _, t := range ts {
		if !t.Status.Closed() {
			in.Tasks = append(in.Tasks, t)
		}
	}
	todo.Sort(in.Tasks)
	u, err := a.store.LastUpdate(ctx)
	if err != nil {
		return in, err
	}
	if _, failed, _ := countsOf(u); failed > 0 {
		in.Update = u
	}
	return in, nil
}

func countsOf(u *packages.Update) (int, int, int) {
	if u == nil {
		return 0, 0, 0
	}
	return u.Counts()
}

func (a *app) analyze(ctx context.Context, f aiFlags, tasks bool) error {
	in, err := a.overviewInput(ctx)
	if err != nil {
		return err
	}
	if len(in.Runs) == 0 {
		return fmt.Errorf("nothing to analyze: no command has run yet; try `audit %s`", strings.Join(core.Commands, "`, `audit "))
	}
	client := a.aiClient(f.level)
	if !tasks {
		resp, err := a.ask(ctx, client, llm.OverviewRequest(in, a.cfg.AI.AnalysisLevel, a.cfg.AI.MaxDetails), f.refresh, !f.json, "analyzing")
		if err != nil {
			return err
		}
		if f.json {
			return a.writeJSON(answerOf(resp))
		}
		a.printAnswer("AI review of all commands", resp)
		return nil
	}

	rep := a.progress(!f.json)
	rep.Phase("asking for suggestions ("+client.Label()+")", 0)
	var sg llm.Suggestions
	resp, err := client.AskJSON(ctx, llm.SuggestionsRequest(in, a.cfg.AI.MaxDetails), f.refresh, &sg)
	rep.Done()
	if err != nil {
		return err
	}
	suggested := llm.SuggestedTodos(sg, core.Commands)
	existing, err := a.store.Todos(ctx, "")
	if err != nil {
		return err
	}
	writes, changes := todo.ReconcileAI(existing, suggested, timeNow())
	if err := a.store.SaveTodos(ctx, writes); err != nil {
		return err
	}
	all, err := a.store.Todos(ctx, "")
	if err != nil {
		return err
	}
	var ai []todo.Todo
	for _, t := range all {
		if t.Source == todo.FromAI && !t.Status.Closed() {
			ai = append(ai, t)
		}
	}
	todo.Sort(ai)
	if f.json {
		return a.writeJSON(struct {
			Model   string      `json:"model,omitempty"`
			Cached  bool        `json:"cached"`
			Changes int         `json:"task_changes"`
			Tasks   []todo.Todo `json:"tasks"`
		}{resp.Model, resp.Cached, changes, ai})
	}
	if len(ai) == 0 {
		sayln(a.out, "No AI suggestions.")
	} else {
		a.printer().Todos(ai)
	}
	say(a.errOut, "%d AI suggestion(s), %d task(s) changed (%s%s).\n", len(suggested), changes, resp.Model, cachedNote(resp))
	return nil
}

func cachedNote(r *llm.Response) string {
	if r.Cached {
		return ", cached"
	}
	return ""
}

func newTodoExplainCmd(a *app) *cobra.Command {
	var f aiFlags
	c := &cobra.Command{
		Use:   "explain ID",
		Short: "Ask the AI why a task's problem happens and how to fix it",
		Long: `Send one task, with every detail of the saved findings behind it, to the AI
CLI (ai.provider, or --ai-provider) and print the likely cause, whether it
matters, the fix and how to confirm it. The answer is cached by prompt.
In the task editor (audit todo -i), e does the same for the selected task.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			t, resp, err := a.explainTask(c.Context(), id, f.refresh, f.level, !f.json)
			if err != nil {
				return err
			}
			if f.json {
				return a.writeJSON(answerOf(resp))
			}
			a.printAnswer(fmt.Sprintf("#%d %s", t.ID, t.Title), resp)
			return nil
		},
	}
	addAIFlags(c, &f)
	return c
}

// explainTask asks about task id with the findings behind it.
func (a *app) explainTask(ctx context.Context, id int64, refresh bool, level string, bar bool) (todo.Todo, *llm.Response, error) {
	t, err := a.store.GetTodo(ctx, id)
	if err != nil {
		return t, nil, err
	}
	var fs []finding.Finding
	if t.Source.Scanned() {
		r, err := a.engine.Saved(ctx, t.Command, "")
		if err != nil {
			return t, nil, err
		}
		if r != nil {
			fs = findingsFor(t, r.Findings)
		}
	}
	client := a.aiClient(level)
	resp, err := a.ask(ctx, client, llm.ExplainTaskRequest(t, fs, a.cfg.AI.AnalysisLevel), refresh, bar, fmt.Sprintf("explaining #%d", id))
	return t, resp, err
}

// findingsFor picks the findings a scanned task was derived from.
func findingsFor(t todo.Todo, fs []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		switch {
		case t.Source == todo.FromFinding && f.Key() == t.Key:
		case t.Source == todo.FromAggregate && f.Check == t.Check && todo.PriorityFor(f) == "" &&
			(f.Group == nil && t.Key == todo.AggregateKey(f.Command, f.Check) ||
				f.Group != nil && t.Key == todo.GroupKey(f.Command, f.Check, f.Group.ID)):
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

// explainUpdate asks why the failed items of u failed and prints the answer.
func (a *app) explainUpdate(ctx context.Context, u *packages.Update, f aiFlags) error {
	if u == nil {
		return nil
	}
	req, ok := llm.ExplainFailuresRequest(u, a.cfg.AI.AnalysisLevel)
	if !ok {
		sayln(a.out, "\nNothing failed, so there is nothing to explain.")
		return nil
	}
	if f.level != "" {
		req, _ = llm.ExplainFailuresRequest(u, f.level)
	}
	resp, err := a.ask(ctx, a.aiClient(f.level), req, f.refresh, true, "explaining the failures")
	if err != nil {
		return err
	}
	sayln(a.out)
	a.printAnswer("Why these failed", resp)
	return nil
}
