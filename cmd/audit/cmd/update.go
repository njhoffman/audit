package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
)

type updateFlags struct {
	managers    []string
	dryRun      bool
	yes         bool
	major       bool
	stopOnError bool
	last        bool
	json        bool
	explain     bool
}

func newPackagesUpdateCmd(a *app) *cobra.Command {
	var f updateFlags
	c := &cobra.Command{
		Use:   "update [package...]",
		Short: "Update outdated packages with their own managers",
		Long: `Update packages behind their latest release, one at a time, with each
manager's own command (uv tool upgrade, pnpm add -g NAME@latest, cargo
install --locked, go install PKG@latest, gem update --user-install, gh
extension upgrade).

The inventory is scanned and the registry cache refreshed first, then the
plan is printed and confirmed; --dry-run stops after the plan and --yes
skips the question (required when stdin is not a terminal). Without
packages, every outdated package is planned except major releases (pass
--major), packages.update.exclude entries and packages installed from git
or a path. Named packages are always listed, with the reason when one is
skipped.

A package counts as updated only when a fresh inventory shows a new
version, so a command that exits 0 without changing anything is a failure.
Failures are itemized with the tail of their output and saved; --last
shows the last update again. The inventory is rescanned afterwards so
tasks follow, and a failed attempt is noted on the package's outdated task.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if f.last {
				if len(args) > 0 || f.dryRun || f.yes {
					return errors.New("--last takes no packages, --dry-run or --yes")
				}
				return a.lastUpdate(c.Context(), f.json, f.explain, packages.KindPackage)
			}
			return a.update(c.Context(), parseRefs(args), f)
		},
	}
	fl := c.Flags()
	fl.StringSliceVarP(&f.managers, "manager", "M", nil, "update only these managers: "+strings.Join(packages.Names(), ", "))
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "update without asking")
	fl.BoolVarP(&f.major, "major", "m", false, "also update across major releases")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining updates after the first failure")
	fl.BoolVarP(&f.last, "last", "L", false, "show the last update and its errors; update nothing")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the update as JSON")
	fl.BoolVarP(&f.explain, "explain", "e", false, "ask the AI why the failed updates failed (with --last, the last update's)")
	c.MarkFlagsMutuallyExclusive("explain", "json")
	return c
}

func (a *app) update(ctx context.Context, refs []packages.Ref, f updateFlags) error {
	show := !f.json && !a.flags.quiet
	s, err := a.packagesScanner(splitList(f.managers))
	if err != nil {
		return err
	}
	s.Refresh = a.registryRefresh(refs, false)
	res, err := a.engine.Execute(ctx, s, a.progress(!f.json))
	if err != nil {
		return err
	}
	var d packages.Data
	if err := json.Unmarshal(res.Run.Data, &d); err != nil {
		return fmt.Errorf("read packages inventory: %w", err)
	}
	metas, err := a.store.PackageMeta(ctx)
	if err != nil {
		return err
	}
	plan := packages.PlanUpdates(d.Inventories, metas, packages.PlanOptions{
		Refs: refs, Major: f.major, Exclude: parseRefs(a.cfg.Packages.Update.Exclude)})
	if len(plan.Unmatched) > 0 {
		return fmt.Errorf("no installed package matches %s", strings.Join(plan.Unmatched, ", "))
	}
	runnable := len(plan.Runnable())
	switch {
	case f.json && f.dryRun:
		return a.writeJSON(plan)
	case !f.json:
		a.printPlan(plan, f.dryRun)
	}
	if runnable == 0 || f.dryRun {
		if runnable == 0 && !f.json {
			sayln(a.out, "Nothing to update.")
		}
		return nil
	}
	if !f.yes {
		ok, err := a.confirm(fmt.Sprintf("Update %d package(s)?", runnable))
		if err != nil || !ok {
			return err
		}
	}

	u := a.runUpdates(ctx, s, plan, f, show)
	if err := a.store.SaveUpdate(context.WithoutCancel(ctx), u); err != nil {
		return fmt.Errorf("save update: %w", err)
	}
	if err := a.store.PruneUpdates(context.WithoutCancel(ctx), a.cfg.History); err != nil {
		a.log.Warn("prune updates", "err", err)
	}
	if err := ctx.Err(); err != nil {
		a.printUpdate(u, false)
		return err
	}

	var attempted []packages.Ref
	for _, it := range u.Items {
		if it.Status != packages.UpdateSkipped {
			attempted = append(attempted, packages.Ref{Manager: it.Manager, Name: it.Name})
		}
	}
	if len(attempted) > 0 {
		s2, err := a.packagesScanner(splitList(f.managers))
		if err != nil {
			return err
		}
		s2.Refresh = a.registryRefresh(attempted, false)
		res, err := a.engine.Execute(ctx, s2, a.progress(!f.json))
		if err != nil {
			return fmt.Errorf("rescan after the update: %w", err)
		}
		if show && res.TaskChanges > 0 {
			say(a.errOut, "%d task(s) updated; see `audit todo --cmd %s`.\n", res.TaskChanges, packages.Command)
		}
	}
	if f.json {
		if err := a.writeJSON(u); err != nil {
			return err
		}
	} else {
		a.printUpdate(u, false)
	}
	if _, failed, _ := u.Counts(); failed > 0 {
		if f.explain {
			if err := a.explainUpdate(ctx, u, aiFlags{}); err != nil {
				a.log.Warn("explain the failures", "err", err)
			}
		}
		return fmt.Errorf("%d package update(s) failed", failed)
	}
	return nil
}

// runUpdates runs the plan with a progress bar and one status line per
// package, then checks the results against a fresh inventory of the
// managers that changed.
func (a *app) runUpdates(ctx context.Context, s *core.PackagesScanner, plan packages.Plan, f updateFlags, show bool) *packages.Update {
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	rep := a.progress(!f.json)
	u.Items = a.execPlan(ctx, s.ScanEnv, plan, "updating packages", f.stopOnError, !f.json, show)
	if ctx.Err() == nil {
		var touched []packages.Manager
		for _, m := range s.Managers {
			if slices.ContainsFunc(u.Items, func(r packages.UpdateResult) bool {
				return r.Manager == m.Name() && r.Status == packages.UpdateOK
			}) {
				touched = append(touched, m)
			}
		}
		if len(touched) > 0 {
			rep.Phase("checking the new versions", len(touched))
			invs := packages.CollectAll(ctx, s.ScanEnv, touched, func(inv packages.Inventory) { rep.Step(inv.Manager) })
			rep.Done()
			if ctx.Err() == nil {
				packages.Verify(u.Items, invs)
			}
		}
	}
	u.FinishedAt = timeNow()
	return u
}

// execPlan runs the plan's commands behind a progress bar with one status
// line per item.
func (a *app) execPlan(ctx context.Context, env *exec.Env, plan packages.Plan, phase string, stopOnError, bar, show bool) []packages.UpdateResult {
	rep := a.progress(bar)
	lines := a.errOut
	if !show {
		lines = io.Discard
	}
	rep.Phase(phase, len(plan.Runnable()))
	defer rep.Done()
	return packages.RunUpdates(ctx, env, plan, packages.RunOptions{
		Timeout:     a.cfg.Packages.Update.Timeout,
		StopOnError: stopOnError,
		OnStart: func(it packages.Planned) {
			progress.Status(rep, fmt.Sprintf("%s:%s %s -> %s", it.Manager, it.Name, it.Version, it.Latest))
		},
		OnDone: func(it packages.Planned, r packages.UpdateResult) {
			rep.Step(it.Manager + ":" + it.Name)
			status := "ok"
			if r.Status == packages.UpdateFailed {
				status = "FAILED"
			}
			line := fmt.Sprintf("%-6s  %s:%s %s -> %s  (%s)", status, it.Manager, it.Name, it.Version, it.Latest, r.Duration.Round(100*time.Millisecond))
			if r.Status == packages.UpdateFailed {
				line += "  " + r.Reason
			}
			progress.Println(rep, lines, line)
		},
	})
}

// confirm asks a yes/no question on the terminal; without one it refuses.
func (a *app) confirm(question string) (bool, error) {
	if !a.interactive() {
		return false, errors.New("refusing to update without --yes: not running in a terminal")
	}
	say(a.errOut, "%s [y/N] ", question)
	line, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil && line == "" {
		sayln(a.errOut)
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// printPlan lists what an update would do; dryRun shows the commands.
func (a *app) printPlan(plan packages.Plan, dryRun bool) {
	p := a.printer()
	if len(plan.Items) > 0 {
		head := "ACTION"
		if dryRun {
			head = "COMMAND"
		}
		rows := make([][]string, len(plan.Items))
		for i, it := range plan.Items {
			action := "update"
			switch {
			case it.Skip != "":
				action = "skip: " + it.Skip
			case dryRun:
				action = strings.Join(it.Command, " ")
			case it.Gap != packages.GapUnknown:
				action += " (" + string(it.Gap) + ")"
			}
			rows[i] = []string{it.Manager + ":" + it.Name, it.Version, it.Latest, action}
		}
		from, to := "INSTALLED", "LATEST"
		if !slices.ContainsFunc(plan.Items, func(it packages.Planned) bool { return it.Kind != packages.KindMigration }) {
			from, to = "RUNS ON", "MOVES TO"
		}
		p.Table([]string{"PACKAGE", from, to, head}, rows)
	}
	runnable := len(plan.Runnable())
	msg := fmt.Sprintf("%d to update, %d skipped.", runnable, len(plan.Items)-runnable)
	if plan.NotFromRegistry > 0 {
		msg += fmt.Sprintf(" %d package(s) installed from git or a path are not updated.", plan.NotFromRegistry)
	}
	if len(plan.Items) > 0 || plan.NotFromRegistry > 0 {
		sayln(a.out, msg)
	}
}

// printUpdate summarizes an update and itemizes its failures; table also
// lists every result.
func (a *app) printUpdate(u *packages.Update, table bool) {
	p := a.printer()
	if table {
		rows := make([][]string, len(u.Items))
		for i, it := range u.Items {
			to := it.To
			if to == "" {
				to = it.Latest
			}
			status := it.Status
			if it.Reason != "" && it.Status == packages.UpdateSkipped {
				status += ": " + it.Reason
			}
			rows[i] = []string{it.Manager + ":" + it.Name, it.From, to, status, it.Duration.Round(100 * time.Millisecond).String()}
		}
		p.Table([]string{"PACKAGE", "FROM", "TO", "STATUS", "TIME"}, rows)
	}
	say(a.out, "Update %s on %s: %s.\n", u.FinishedAt.Local().Format("2006-01-02 15:04"), u.Host, u.Summary())
	limit := a.cfg.Display.Details
	for _, it := range u.Items {
		if it.Status != packages.UpdateFailed {
			continue
		}
		say(a.out, "\nFAILED %s:%s %s -> %s: %s\n", it.Manager, it.Name, it.From, it.Latest, it.Reason)
		if it.Command != "" {
			say(a.out, "  $ %s\n", it.Command)
		}
		lines := strings.Split(it.Output, "\n")
		if !a.flags.verbose && len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				say(a.out, "  | %s\n", l)
			}
		}
	}
}

// showLastUpdate prints the newest saved update.
func (a *app) lastUpdate(ctx context.Context, asJSON, explain bool, kinds ...string) error {
	u, err := a.store.LastUpdateOf(ctx, kinds...)
	if err != nil {
		return err
	}
	if asJSON {
		return a.writeJSON(u)
	}
	if u == nil {
		sayln(a.out, "Nothing has been updated yet.")
		return nil
	}
	a.printUpdate(u, true)
	if explain {
		return a.explainUpdate(ctx, u, aiFlags{})
	}
	return nil
}
