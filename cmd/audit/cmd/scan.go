package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/system"
)

// scanFlags are shared by every scanning command.
type scanFlags struct {
	rescan      bool
	report      bool
	list        bool
	summary     bool
	json        bool
	html        bool
	open        bool
	ai          bool
	aiRefresh   bool
	level       string
	minSeverity string
	check       string
	diff        bool
	// impliesList, when set and true, turns a plain run into --list (the
	// packages query flags).
	impliesList func() bool
	// jsonExtra, when set, adds a command-specific value to --json output.
	jsonExtra func(ctx context.Context, r *run.Run) (any, error)
	// viewOnly makes --list print the view without the findings before
	// it, counting them instead, unless a finding filter was given.
	viewOnly bool
	// listHint is the command that lists the findings viewOnly leaves out.
	listHint string
	// reportFooter, when set, adds a line under the default report.
	reportFooter func(ctx context.Context, r *run.Run) (string, error)
}

// viewFunc prints a command's inventory for --list. An error (unreadable
// saved data, a failed cache read) fails the command, since the requested
// list is missing.
type viewFunc func(ctx context.Context, p *render.Printer, r *run.Run) error

func (f *scanFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.BoolVarP(&f.rescan, "rescan", "r", false, "scan now even if saved results are fresh")
	fl.BoolVarP(&f.report, "report", "R", false, "print the full report of saved results (no scan)")
	fl.BoolVarP(&f.list, "list", "l", false, "print one line per finding plus the command's inventory (no scan)")
	fl.BoolVarP(&f.summary, "summary", "s", false, "print the header and summary statistics only (no scan)")
	fl.BoolVarP(&f.json, "json", "j", false, "print the run as JSON (no scan)")
	fl.BoolVarP(&f.html, "html", "H", false, "write the HTML report and print its path")
	fl.BoolVarP(&f.open, "open", "o", false, "write the HTML report and open it")
	fl.BoolVarP(&f.ai, "ai", "a", false, "add an AI review through the AI CLI (ai.provider; cached per result set)")
	fl.BoolVarP(&f.aiRefresh, "ai-refresh", "A", false, "like --ai, but ask again instead of using the cache")
	fl.StringVarP(&f.level, "level", "L", "", "AI analysis level: brief, standard or deep (default from config)")
	fl.StringVarP(&f.minSeverity, "min-severity", "m", "", "hide findings below this severity (critical, error, warning, notice, info)")
	fl.StringVarP(&f.check, "check", "k", "", "show only findings whose check id starts with this prefix")
	fl.BoolVarP(&f.diff, "diff", "w", false, "show what changed since the previous run: findings added, resolved and changed in severity (no scan unless --rescan)")
	c.MarkFlagsMutuallyExclusive("report", "list", "summary", "json")
	c.MarkFlagsMutuallyExclusive("diff", "report", "list", "summary")
}

func (f *scanFlags) mode() core.Mode {
	switch {
	case f.rescan:
		return core.Rescan
	case f.report || f.list || f.summary || f.json || f.diff:
		return core.SavedOnly
	}
	return core.Auto
}

func (f *scanFlags) filter() (finding.Filter, error) {
	flt := finding.Filter{Check: f.check}
	if f.minSeverity != "" {
		s, err := finding.ParseSeverity(f.minSeverity)
		if err != nil {
			return flt, err
		}
		flt.MinSeverity = s
	}
	return flt, nil
}

// scanNeeded reports whether runScan with f would scan command rather than
// show its saved full run.
func (a *app) scanNeeded(ctx context.Context, command string, f *scanFlags) (bool, error) {
	list := f.list || (f.impliesList != nil && f.impliesList())
	switch {
	case f.rescan:
		return true, nil
	case f.report || list || f.summary || f.json || f.diff:
		return false, nil
	}
	r, err := a.engine.Saved(ctx, command, "")
	if err != nil {
		return false, err
	}
	if r == nil {
		return true, nil
	}
	th := a.cfg.Stale.For(command)
	return run.FreshnessOf(r.Age(timeNow()), th.Warn, th.Old) != run.Fresh, nil
}

// scanCommand builds one scanning subcommand. build turns the parsed flags
// into a scanner; view prints the command-specific inventory for --list.
func scanCommand(a *app, use, short, long string, build func(context.Context) (core.Scanner, error),
	view viewFunc) (*cobra.Command, *scanFlags) {
	f := &scanFlags{}
	c := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			s, err := build(c.Context())
			if err != nil {
				return err
			}
			return a.runScan(c.Context(), s, f, view)
		},
	}
	f.register(c)
	return c, f
}

func (a *app) runScan(ctx context.Context, s core.Scanner, f *scanFlags, view viewFunc) error {
	if f.impliesList != nil && f.impliesList() && !f.report && !f.summary && !f.json {
		f.list = true
	}
	flt, err := f.filter()
	if err != nil {
		return err
	}
	res, err := a.engine.Resolve(ctx, s, f.mode(), a.progress(!f.json))
	if errors.Is(err, core.ErrNoSavedRun) {
		return fmt.Errorf("%w; run `%s` first", err, core.RescanHint(s.Command(), s.Scope()))
	}
	if err != nil {
		return err
	}
	r := res.Run
	if !res.Saved {
		a.log.Info("scan saved", "command", r.Command, "findings", len(r.Findings), "tasks changed", res.TaskChanges)
		if res.TaskChanges > 0 && !f.json && !a.flags.quiet {
			say(a.errOut, "%d task(s) updated; see `audit todo --cmd %s`.\n", res.TaskChanges, r.Command)
		}
	}
	if f.ai || f.aiRefresh {
		a.engine.AI = a.aiClient(f.level)
		rep := a.progress(!f.json)
		rep.Phase("asking the AI for a review", 0)
		err := a.engine.Analyze(ctx, r, f.aiRefresh)
		rep.Done()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			a.log.Warn("ai review failed", "err", err)
			if r.Analysis == nil {
				say(a.errOut, "AI review failed: %v\n", err)
			}
		}
	}
	if f.html || f.open {
		path, err := a.writeReport(ctx, r)
		if err != nil {
			return err
		}
		if f.open {
			if err := a.opener(path); err != nil {
				return err
			}
		}
		if !f.json {
			sayln(a.errOut, "report: "+path)
		}
	}

	if f.diff {
		return a.printDiff(ctx, r, flt, f.json)
	}
	if f.json {
		var extra any
		if f.jsonExtra != nil {
			if extra, err = f.jsonExtra(ctx, r); err != nil {
				return err
			}
		}
		return a.writeJSON(struct {
			Saved    bool     `json:"saved"`
			Run      *run.Run `json:"run"`
			Packages any      `json:"packages,omitempty"`
		}{res.Saved, r, extra})
	}
	p := a.printer()
	o := render.ReportOptions{Thresholds: a.cfg.Stale.For(r.Command), Saved: res.Saved, Filter: flt,
		RescanHint: core.RescanHint(r.Command, r.Scope)}
	switch {
	case f.summary:
		p.Brief(r, o)
	case f.list:
		viewOnly := f.viewOnly && view != nil && len(r.Data) > 0 && f.minSeverity == "" && f.check == ""
		if !viewOnly {
			p.List(r, o)
		}
		if view != nil && len(r.Data) > 0 {
			if !viewOnly {
				sayln(a.out)
			}
			if err := view(ctx, p, r); err != nil {
				return err
			}
		}
		if viewOnly && len(r.Findings) > 0 {
			say(a.out, "%d finding(s) in this run; `%s` lists them.\n", len(r.Findings), f.listHint)
		}
	default:
		p.Report(r, o)
		if f.reportFooter != nil && len(r.Data) > 0 {
			line, err := f.reportFooter(ctx, r)
			if err != nil {
				return err
			}
			if line != "" {
				sayln(a.out, line)
			}
		}
	}
	return nil
}

func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func newSystemCmd(a *app) *cobra.Command {
	var only []string
	c, _ := scanCommand(a, "system", "Scan processes, services, users, logs and program configs",
		`Scan system health: running processes, systemd units, user and group
accounts, the journal, dmesg and boot logs, and the configuration of known
programs (nginx, apache, sshd, postgres, docker, cron).

Results are saved. Without --rescan, saved results younger than the stale
warn threshold are shown instead of scanning again.`,
		func(context.Context) (core.Scanner, error) { return a.systemScanner(splitList(only)) }, nil)
	c.Flags().StringSliceVarP(&only, "only", "O", nil, "scan only these parts: "+strings.Join(system.Kinds, ", "))
	return c
}

func newEnvironmentCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "environment", "Scan shell startup, PATH and environment variables",
		`Start each configured login shell with and without a terminal, capture the
resulting environment and any unexpected output, trace which startup files
are sourced, then check PATH, environment variables and the startup scripts
(syntax, shellcheck, start-up time).`,
		func(context.Context) (core.Scanner, error) { return core.NewEnvironment(a.cfg, a.env) },
		func(_ context.Context, p *render.Printer, r *run.Run) error {
			var d environment.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				return fmt.Errorf("read environment data: %w", err)
			}
			p.Environment(d)
			return nil
		})
	return c
}

// printDiff prints what changed from the run saved before r to r, with
// the finding filter applied to both.
func (a *app) printDiff(ctx context.Context, r *run.Run, flt finding.Filter, asJSON bool) error {
	prev, err := a.store.PreviousRun(ctx, r)
	if err != nil {
		return err
	}
	if prev == nil {
		if asJSON {
			return a.writeJSON(diffJSON{To: runRef(r)})
		}
		say(a.out, "No earlier %s run is kept to compare with; `%s` makes one.\n", r.Command, core.RescanHint(r.Command, r.Scope))
		return nil
	}
	return a.showDiff(prev, r, flt, asJSON)
}

func (a *app) showDiff(from, to *run.Run, flt finding.Filter, asJSON bool) error {
	d := finding.Diff(flt.Apply(from.Findings), flt.Apply(to.Findings))
	if asJSON {
		ref := runRef(from)
		return a.writeJSON(diffJSON{From: &ref, To: runRef(to), Delta: &d})
	}
	a.printer().Diff(from, to, d)
	return nil
}

// diffJSON is the --diff --json output; From and Delta are null when no
// earlier run is kept.
type diffJSON struct {
	From  *diffRun       `json:"from"`
	To    diffRun        `json:"to"`
	Delta *finding.Delta `json:"delta"`
}

type diffRun struct {
	ID         int64     `json:"id"`
	Command    string    `json:"command"`
	Scope      string    `json:"scope"`
	FinishedAt time.Time `json:"finished_at"`
}

func runRef(r *run.Run) diffRun {
	return diffRun{ID: r.ID, Command: r.Command, Scope: r.Scope, FinishedAt: r.FinishedAt}
}

// systemScanner builds the system scanner with the saved packages to match
// the program checks against.
func (a *app) systemScanner(only []string) (*core.SystemScanner, error) {
	s, err := core.NewSystem(a.cfg, a.env, only)
	if err != nil {
		return nil, err
	}
	if a.store != nil {
		s.Packages = a.store
	}
	return s, nil
}
