package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
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
}

func (f *scanFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.BoolVarP(&f.rescan, "rescan", "r", false, "scan now even if saved results are fresh")
	fl.BoolVarP(&f.report, "report", "R", false, "print the full report of saved results (no scan)")
	fl.BoolVarP(&f.list, "list", "l", false, "print one line per finding plus the command's inventory (no scan)")
	fl.BoolVarP(&f.summary, "summary", "s", false, "print the header and summary statistics only (no scan)")
	fl.BoolVarP(&f.json, "json", "j", false, "print the run as JSON (no scan)")
	fl.BoolVarP(&f.html, "html", "H", false, "write the HTML report and print its path")
	fl.BoolVarP(&f.open, "open", "o", false, "write the HTML report and open it")
	fl.BoolVarP(&f.ai, "ai", "a", false, "add an AI review through the claude CLI (cached per result set)")
	fl.BoolVarP(&f.aiRefresh, "ai-refresh", "A", false, "like --ai, but ask again instead of using the cache")
	fl.StringVarP(&f.level, "level", "L", "", "AI analysis level: brief, standard or deep (default from config)")
	fl.StringVarP(&f.minSeverity, "min-severity", "m", "", "hide findings below this severity (critical, error, warning, notice, info)")
	fl.StringVarP(&f.check, "check", "k", "", "show only findings whose check id starts with this prefix")
	c.MarkFlagsMutuallyExclusive("report", "list", "summary", "json")
}

func (f *scanFlags) mode() core.Mode {
	switch {
	case f.rescan:
		return core.Rescan
	case f.report || f.list || f.summary || f.json:
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

// scanCommand builds one scanning subcommand. build turns the parsed flags
// into a scanner; view prints the command-specific inventory for --list.
func scanCommand(a *app, use, short, long string, build func() (core.Scanner, error),
	view func(*render.Printer, *run.Run)) (*cobra.Command, *scanFlags) {
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
			s, err := build()
			if err != nil {
				return err
			}
			return a.runScan(c.Context(), s, f, view)
		},
	}
	f.register(c)
	return c, f
}

func (a *app) runScan(ctx context.Context, s core.Scanner, f *scanFlags, view func(*render.Printer, *run.Run)) error {
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
		rep.Phase("asking claude for a review", 0)
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

	if f.json {
		return a.writeJSON(struct {
			Saved bool     `json:"saved"`
			Run   *run.Run `json:"run"`
		}{res.Saved, r})
	}
	p := a.printer()
	o := render.ReportOptions{Thresholds: a.cfg.Stale.For(r.Command), Saved: res.Saved, Filter: flt,
		RescanHint: core.RescanHint(r.Command, r.Scope)}
	switch {
	case f.summary:
		p.Brief(r, o)
	case f.list:
		p.List(r, o)
		if view != nil && len(r.Data) > 0 {
			sayln(a.out)
			view(p, r)
		}
	default:
		p.Report(r, o)
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
		func() (core.Scanner, error) { return core.NewSystem(a.cfg, splitList(only)) }, nil)
	c.Flags().StringSliceVarP(&only, "only", "O", nil, "scan only these parts: "+strings.Join(system.Kinds, ", "))
	return c
}

func newEnvironmentCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "environment", "Scan shell startup, PATH and environment variables",
		`Start each configured login shell with and without a terminal, capture the
resulting environment and any unexpected output, trace which startup files
are sourced, then check PATH, environment variables and the startup scripts
(syntax, shellcheck, start-up time).`,
		func() (core.Scanner, error) { return core.NewEnvironment(a.cfg, a.env) },
		func(p *render.Printer, r *run.Run) {
			var d environment.Data
			if json.Unmarshal(r.Data, &d) == nil {
				p.Environment(d)
			}
		})
	return c
}

func newPackagesCmd(a *app) *cobra.Command {
	var managers []string
	c, _ := scanCommand(a, "packages", "Inventory user package managers and check their installs",
		`Inventory packages installed by user-level package managers (`+strings.Join(packages.Names(), ", ")+`)
and check for broken or shadowed executables, runtime drift, stale runtime
directories and misplaced installs. --list prints the inventory.`,
		func() (core.Scanner, error) { return core.NewPackages(a.cfg, a.env, splitList(managers)) },
		func(p *render.Printer, r *run.Run) {
			var d packages.Data
			if json.Unmarshal(r.Data, &d) == nil {
				p.Packages(d)
			}
		})
	c.Flags().StringSliceVarP(&managers, "manager", "M", nil, "inventory only these managers: "+strings.Join(packages.Names(), ", "))
	return c
}
