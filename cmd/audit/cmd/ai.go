package cmd

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/gitfix"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
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
	t, fs, err := a.taskFindings(ctx, id)
	if err != nil {
		return t, nil, err
	}
	client := a.aiClient(level)
	resp, err := a.ask(ctx, client, llm.ExplainTaskRequest(t, fs, a.cfg.AI.AnalysisLevel), refresh, bar, fmt.Sprintf("explaining #%d", id))
	return t, resp, err
}

// taskFindings loads task id and, for a scanned task, the saved findings
// behind it.
func (a *app) taskFindings(ctx context.Context, id int64) (todo.Todo, []finding.Finding, error) {
	t, err := a.store.GetTodo(ctx, id)
	if err != nil {
		return t, nil, err
	}
	a.withFixHistory(ctx, &t)
	if !t.Source.Scanned() {
		return t, nil, nil
	}
	r, err := a.engine.Saved(ctx, t.Command, "")
	if err != nil || r == nil {
		return t, nil, err
	}
	return t, findingsFor(t, r.Findings), nil
}

func newTodoFixCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "fix ID",
		Short: "Fix a task in an interactive AI session, then rescan to check it",
		Long: `Start the AI CLI (ai.provider, or --ai-provider) interactively with the
task and every detail of the saved findings behind it, asking it to fix the
task. The CLI asks before each edit or command as usual. Tasks that a
built-in action handles (packages update, repos sync, files, configs and
containers clean) are pointed at that action. When the session exits, the task's
command is rescanned and the task's new status printed.
In the task editor (audit todo -i), F does the same for the selected task.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if !a.interactive() {
				return fmt.Errorf("todo fix needs a terminal")
			}
			if err := a.load(); err != nil {
				return err
			}
			return a.fixTask(c.Context(), id)
		},
	}
}

// fixTask runs the AI session that fixes task id on the terminal, then
// checks the result.
func (a *app) fixTask(ctx context.Context, id int64) error {
	cmd, err := a.fixSession(ctx, id)
	if err != nil {
		return err
	}
	snap := a.fixSnapshot(ctx, id)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", cmd.Args[0], err)
	}
	t, err := a.store.GetTodo(ctx, id)
	if err != nil {
		return err
	}
	defer func() { a.offerFixCommit(ctx, t, snap) }()
	if t.Source.Scanned() {
		// A fixed apt, snap or flatpak task only closes on a scan that
		// includes its manager, whatever packages.system_managers says.
		if _, fs, err := a.taskFindings(ctx, id); err == nil && touchesSystemManager(t, fs) {
			a.setSystemAnswer(true)
		}
		s, err := a.defaultScanner(ctx, t.Command)
		if err != nil {
			return err
		}
		if _, err := a.engine.Execute(ctx, s, a.progress(true)); err != nil {
			return err
		}
		if t, err = a.store.GetTodo(ctx, id); err != nil {
			return err
		}
	}
	sayln(a.errOut, render.FixOutcome(t))
	return nil
}

// touchesSystemManager reports whether a packages task is about apt, snap
// or flatpak: its findings' subjects are "manager:id" or the bare manager,
// and grouped ones are grouped by manager.
func touchesSystemManager(t todo.Todo, fs []finding.Finding) bool {
	if t.Command != packages.Command {
		return false
	}
	for _, f := range fs {
		m, _, _ := strings.Cut(f.Subject, ":")
		if f.Group != nil && slices.Contains(packages.SystemNames(), f.Group.ID) || slices.Contains(packages.SystemNames(), m) {
			return true
		}
	}
	return false
}

// fixSession is the interactive AI session that fixes task id. Closed
// tasks are refused.
func (a *app) fixSession(ctx context.Context, id int64) (*osexec.Cmd, error) {
	t, fs, err := a.taskFindings(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.Status.Closed() {
		return nil, fmt.Errorf("#%d is %s", t.ID, t.Status.Label())
	}
	client := a.aiClient("")
	return client.SessionCommand(ctx, llm.FixTaskPrompt(t, fs, a.cachedExplanation(ctx, client, t, fs))), nil
}

// cachedExplanation is the answer an earlier `audit todo explain` gave for t
// and its current findings, at the configured analysis level first and then
// at the others; "" when there is none. A failed cache read only loses the
// context, so it is logged.
func (a *app) cachedExplanation(ctx context.Context, client *llm.Client, t todo.Todo, fs []finding.Finding) string {
	levels := append([]string{a.cfg.AI.AnalysisLevel}, llm.Levels...)
	for _, level := range levels {
		hit, err := client.Cached(ctx, llm.ExplainTaskRequest(t, fs, level))
		if err != nil {
			a.log.Warn("read the cached explanation", "task", t.ID, "err", err)
			return ""
		}
		if hit != nil {
			return hit.Text
		}
	}
	return ""
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

// fixPaths are where a fix session for t is likely to change files: the
// task's file locations, the absolute paths its findings name, and the
// directory audit was started in (where the session runs).
func (a *app) fixPaths(ctx context.Context, id int64) []string {
	t, fs, err := a.taskFindings(ctx, id)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range todo.Locations(t) {
		out = append(out, l.Path)
	}
	abs := func(p string) {
		if filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
		}
	}
	for _, f := range fs {
		abs(f.Subject)
		for _, d := range f.Details {
			p, _, _ := strings.Cut(d, ":")
			abs(p)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, wd)
	}
	return out
}

// fixSnapshot records the git work trees a fix may touch, unless
// ai.commit_fixes is never. A failure only loses the commit offer.
func (a *app) fixSnapshot(ctx context.Context, id int64) gitfix.Snapshot {
	if a.cfg.AI.CommitFixes == config.CommitNever {
		return nil
	}
	snap, err := gitfix.Take(ctx, a.env, gitfix.Roots(ctx, a.env, a.fixPaths(ctx, id)))
	if err != nil {
		a.log.Warn("snapshot git work trees before the fix", "err", err)
		return nil
	}
	return snap
}

// fixCommitMessage names the task the commit fixes.
func fixCommitMessage(t todo.Todo) string {
	title := t.Title
	if len(title) > 60 {
		title = strings.TrimSpace(title[:60]) + "..."
	}
	return fmt.Sprintf("audit: fix #%d %s", t.ID, title)
}

// offerFixCommit asks, per git work tree the session changed, whether to
// commit the files it changed that were clean before; files that already
// had the user's changes are named and left alone. It only offers once the
// task is closed (or was never scanned), and only on a terminal.
func (a *app) offerFixCommit(ctx context.Context, t todo.Todo, snap gitfix.Snapshot) {
	if len(snap) == 0 {
		return
	}
	cs, err := gitfix.Diff(ctx, a.env, snap)
	if err != nil {
		a.log.Warn("compare git work trees after the fix", "err", err)
		return
	}
	if len(cs) == 0 {
		return
	}
	if t.Source.Scanned() && !t.Status.Closed() {
		say(a.errOut, "Not offering a commit: #%d is still open.\n", t.ID)
		return
	}
	msg := fixCommitMessage(t)
	for _, c := range cs {
		for _, m := range c.Mixed {
			say(a.errOut, "%s: %s had your changes before the fix and changed again; left uncommitted.\n", c.Root, m)
		}
		if len(c.Files) == 0 {
			continue
		}
		say(a.errOut, "The fix changed in %s:\n  %s\n", c.Root, strings.Join(c.Files, "\n  "))
		if !a.interactive() {
			continue
		}
		ok, err := a.confirm(fmt.Sprintf("Commit %d file(s) as %q?", len(c.Files), msg))
		if err != nil || !ok {
			continue
		}
		if err := gitfix.Commit(ctx, a.env, c, msg); err != nil {
			say(a.errOut, "Commit failed: %v\n", err)
			continue
		}
		say(a.errOut, "Committed in %s.\n", c.Root)
	}
}
