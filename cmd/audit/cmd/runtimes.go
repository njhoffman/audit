package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/registry"
	"github.com/njhoffman/audit/internal/version"
)

type runtimeFlags struct {
	dryRun      bool
	yes         bool
	major       bool
	rebuild     bool
	prune       bool
	stopOnError bool
	last        bool
	force       bool
	json        bool
}

func newRuntimesCmd(a *app) *cobra.Command {
	var f runtimeFlags
	c := &cobra.Command{
		Use:   "runtimes",
		Short: "List the runtimes packages run on and their newer releases",
		Long: `List python, node, rust, go and ruby: the installed version, what owns it
(uv, pnpm, rustup, the system or a manual install), the newest release of its
line and the newest release overall (the newest LTS for node), and how many
packages were installed against another version.

Releases come from uv's download list, nodejs.org, go.dev and rustup check,
cached for packages.registry.max_age (--force looks them up again); ruby is
left to the system package manager. The packages scan is saved, so the
runtime.drift and runtime.outdated tasks follow.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			_, d, err := a.runtimeScan(c.Context(), nil, f.force, !f.json)
			if err != nil {
				return err
			}
			if f.json {
				return a.writeJSON(d.Runtimes)
			}
			a.printRuntimes(d.Runtimes)
			return nil
		},
	}
	c.Flags().BoolVarP(&f.force, "force", "F", false, "look the releases up again, ignoring the cache age")
	c.Flags().BoolVarP(&f.json, "json", "j", false, "print the runtimes as JSON")
	c.AddCommand(newRuntimesUpdateCmd(a), newRuntimesMigrateCmd(a))
	return c
}

func newRuntimesUpdateCmd(a *app) *cobra.Command {
	var f runtimeFlags
	c := &cobra.Command{
		Use:   "update [runtime...]",
		Short: "Update runtimes owned by uv, pnpm or rustup",
		Long: `Update runtimes with their owners' commands: uv python upgrade MINOR for each
uv-managed python, pnpm runtime set node VERSION -g, and rustup update
TOOLCHAIN for each rustup toolchain with a newer release. Runtimes from the
system package manager or a manual install are listed and skipped.

By default a runtime stays on its line: a python minor gets its newest patch,
node its newest release of the same major. --major also installs the newest
python minor (uv python install) and moves node to the newest LTS major.
rustup toolchains follow their channel and are not limited.

Releases are looked up first, the plan is printed and confirmed (--yes skips
the question, --dry-run stops after the plan), and each update counts only
when the runtime reports the new version afterwards. Packages keep running on
the interpreter they were installed with; audit packages runtimes migrate
moves them. --last shows the last runtime update or migration.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if f.last {
				if len(args) > 0 || f.dryRun || f.yes {
					return errors.New("--last takes no runtimes, --dry-run or --yes")
				}
				return a.showLastUpdate(c.Context(), f.json, packages.KindRuntime, packages.KindMigration)
			}
			return a.runtimesUpdate(c.Context(), args, f)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "update without asking")
	fl.BoolVarP(&f.major, "major", "m", false, "also move to a new python minor or node LTS major")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining updates after the first failure")
	fl.BoolVarP(&f.last, "last", "L", false, "show the last runtime update or migration; update nothing")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the update as JSON")
	return c
}

func newRuntimesMigrateCmd(a *app) *cobra.Command {
	var f runtimeFlags
	c := &cobra.Command{
		Use:   "migrate [runtime...]",
		Short: "Move packages onto the current runtimes",
		Long: `Reinstall packages that run on a runtime other than the current one:

  python  uv tools on another interpreter, with uv tool upgrade --reinstall
          --python MINOR (this also upgrades each tool within its
          constraints)
  node    every pnpm global after a node major change, with pnpm add -g
          --force NAME@VERSION; pnpm records no node version, so audit
          remembers the major the globals were installed under
  ruby    user gems found only in another ruby's gem directory, with gem
          install --user-install NAME -v VERSION
  rust    with --rebuild, crates built by an older rustc (cargo install
          --locked --force NAME@VERSION)
  go      with --rebuild, binaries built by an older go (go install
          PKG@VERSION)

Packages in packages.update.exclude, and packages installed from git or a
path, are skipped. The plan is confirmed like an update and checked against a
fresh inventory. Afterwards audit offers to move stale runtime directories to
the trash (gio trash) and to uninstall python patch releases that a newer
patch replaced and no tool uses; with --yes they are kept unless --prune is
given.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			return a.runtimesMigrate(c.Context(), args, f)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "migrate without asking")
	fl.BoolVarP(&f.rebuild, "rebuild", "b", false, "also rebuild cargo and go binaries built by an older toolchain")
	fl.BoolVarP(&f.prune, "prune", "P", false, "with --yes, also remove stale runtime directories and replaced pythons")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining migrations after the first failure")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the migration as JSON")
	return c
}

// runtimeScan scans packages with a runtime lookup and returns the saved
// result's inventory. names limits the lookup.
func (a *app) runtimeScan(ctx context.Context, names []string, force, bar bool) (*core.PackagesScanner, packages.Data, error) {
	var d packages.Data
	if bad := packages.UnknownRuntimes(names); len(bad) > 0 {
		return nil, d, fmt.Errorf("unknown runtime %s; choose from %s", strings.Join(bad, ", "), strings.Join(packages.RuntimeNames, ", "))
	}
	s, err := a.packagesScanner(nil)
	if err != nil {
		return nil, d, err
	}
	s.RuntimeRefresh = &core.RuntimeRefresh{Names: names, MaxAge: a.cfg.Packages.Registry.MaxAge, Force: force,
		Looker: a.rtLooker, UserAgent: "audit/" + version.Version + " (+https://github.com/njhoffman/audit)",
		Timeout: a.cfg.Packages.Registry.Timeout}
	res, err := a.engine.Execute(ctx, s, a.progress(bar))
	if err != nil {
		return nil, d, err
	}
	if err := json.Unmarshal(res.Run.Data, &d); err != nil {
		return nil, d, fmt.Errorf("read packages inventory: %w", err)
	}
	if bar && !a.flags.quiet && res.TaskChanges > 0 {
		say(a.errOut, "%d task(s) updated; see `audit todo --cmd %s`.\n", res.TaskChanges, packages.Command)
	}
	for _, e := range res.Run.Errors {
		a.log.Warn(e)
	}
	return s, d, nil
}

func (a *app) printRuntimes(sts []packages.RuntimeStatus) {
	if len(sts) == 0 {
		sayln(a.out, "No runtimes found.")
		return
	}
	var rows [][]string
	for _, st := range sts {
		note := st.Error
		switch {
		case note != "":
			note = "lookup failed: " + note
		case st.Drifted > 0:
			note = fmt.Sprintf("%d %s package(s) on another version", st.Drifted, st.Manager)
		}
		rows = append(rows, []string{st.Name, st.Version, st.Owner, st.Latest, st.Newest, note})
		for _, l := range st.Lines {
			mark := ""
			if l.Default {
				mark = "default"
			}
			rows = append(rows, []string{"  " + l.Name, l.Version, "", firstNonEmptyStr(l.Latest, l.Version), "", mark})
		}
	}
	a.printer().Table([]string{"RUNTIME", "INSTALLED", "OWNER", "LATEST", "NEWEST", "NOTE"}, rows)
}

func firstNonEmptyStr(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (a *app) runtimesUpdate(ctx context.Context, names []string, f runtimeFlags) error {
	show := !f.json && !a.flags.quiet
	s, d, err := a.runtimeScan(ctx, names, true, !f.json)
	if err != nil {
		return err
	}
	plan := packages.PlanRuntimeUpdates(d.Runtimes, packages.RuntimePlanOptions{Names: names, Major: f.major})
	ok, err := a.planGate(plan, f, "Update %d runtime(s)?", "Nothing to update.")
	if !ok || err != nil {
		return err
	}
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	u.Items = a.execPlan(ctx, s.ScanEnv, plan, "updating runtimes", f.stopOnError, !f.json, show)
	var after packages.Data
	if ctx.Err() == nil {
		if _, after, err = a.runtimeScan(ctx, names, true, !f.json); err != nil {
			a.log.Warn("rescan after the update", "err", err)
		} else {
			packages.VerifyRuntimes(u.Items, after.Runtimes)
		}
	}
	if err := a.finishUpdate(ctx, u, f.json); err != nil {
		return err
	}
	if show {
		for _, st := range after.Runtimes {
			if st.Drifted > 0 {
				say(a.out, "%d %s package(s) run on another %s; `audit packages runtimes migrate %s` moves them.\n",
					st.Drifted, st.Manager, st.Name, st.Name)
			}
		}
	}
	return failedErr(u, "runtime update")
}

func (a *app) runtimesMigrate(ctx context.Context, names []string, f runtimeFlags) error {
	show := !f.json && !a.flags.quiet
	s, d, err := a.runtimeScan(ctx, names, false, !f.json)
	if err != nil {
		return err
	}
	plan := packages.PlanMigrations(d.Inventories, d.Runtimes, d.NodeMajor, packages.RuntimePlanOptions{
		Names: names, Rebuild: f.rebuild, Exclude: parseRefs(a.cfg.Packages.Update.Exclude)})
	if plan.Rebuildable > 0 && !f.json {
		say(a.out, "%d cargo/go binary(ies) were built by an older toolchain; pass --rebuild to rebuild them.\n", plan.Rebuildable)
	}
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	ok, err := a.planGate(plan, f, "Migrate %d package(s)?", "Nothing to migrate.")
	if err != nil || !ok && len(plan.Runnable()) > 0 {
		// Declined, refused or a dry run: leave the leftovers alone too.
		return err
	}
	after := d
	if ok {
		u.Items = a.execPlan(ctx, s.ScanEnv, plan, "migrating packages", f.stopOnError, !f.json, show)
		if ctx.Err() == nil {
			if _, after, err = a.runtimeScan(ctx, nil, false, !f.json); err != nil {
				a.log.Warn("rescan after the migration", "err", err)
				after = packages.Data{}
			} else {
				packages.VerifyMigrations(u.Items, after.Inventories)
				a.rememberNodeMajor(ctx, u, after)
			}
		}
	}
	if ctx.Err() == nil && !f.dryRun && after.Inventories != nil {
		u.Items = append(u.Items, a.cleanup(ctx, s, after, f, show)...)
	}
	if len(u.Items) == 0 {
		return nil
	}
	if err := a.finishUpdate(ctx, u, f.json); err != nil {
		return err
	}
	return failedErr(u, "migration")
}

// planGate prints the plan and asks to run it. ok is false when there is
// nothing to run, on a dry run, or when the answer is no.
func (a *app) planGate(plan packages.Plan, f runtimeFlags, question, nothing string) (bool, error) {
	runnable := len(plan.Runnable())
	switch {
	case f.json && f.dryRun:
		return false, a.writeJSON(plan)
	case !f.json:
		a.printPlan(plan, f.dryRun)
	}
	if runnable == 0 || f.dryRun {
		if runnable == 0 && !f.json {
			sayln(a.out, nothing)
		}
		return false, nil
	}
	if f.yes {
		return true, nil
	}
	return a.confirm(fmt.Sprintf(question, runnable))
}

// rememberNodeMajor records the current node major once every pnpm global
// moved onto it.
func (a *app) rememberNodeMajor(ctx context.Context, u *packages.Update, after packages.Data) {
	moved := false
	for _, it := range u.Items {
		if it.Kind != packages.KindMigration || it.Manager != "pnpm" {
			continue
		}
		if it.Status != packages.UpdateOK {
			return
		}
		moved = true
	}
	if !moved {
		return
	}
	for _, st := range after.Runtimes {
		if st.Name == packages.RuntimeNode {
			if err := a.store.SetSetting(ctx, core.NodeMajorSetting, packages.VersionLine(packages.RuntimeNode, st.Version)); err != nil {
				a.log.Warn("remember the node major", "err", err)
			}
		}
	}
}

// cleanup offers to trash stale runtime directories and uninstall python
// patches no tool uses, and runs what was accepted.
func (a *app) cleanup(ctx context.Context, s *core.PackagesScanner, d packages.Data, f runtimeFlags, show bool) []packages.UpdateResult {
	plan := a.cleanupPlan(ctx, s, d)
	if len(plan.Items) == 0 {
		return nil
	}
	if !f.json {
		sayln(a.out, "\nStale runtime leftovers:")
		a.printPlan(plan, true)
	}
	runnable := len(plan.Runnable())
	if runnable == 0 {
		return nil
	}
	switch {
	case f.yes && !f.prune:
		if !f.json {
			say(a.out, "Kept %d item(s); pass --prune with --yes to remove them.\n", runnable)
		}
		return nil
	case !f.yes:
		ok, err := a.confirm(fmt.Sprintf("Remove %d item(s)?", runnable))
		if err != nil || !ok {
			return nil
		}
	}
	rs := a.execPlan(ctx, s.ScanEnv, plan, "removing stale runtimes", f.stopOnError, !f.json, show)
	var pythons map[string]bool
	for i := range rs {
		r := &rs[i]
		if r.Status != packages.UpdateOK {
			continue
		}
		if r.Manager == "trash" {
			if _, err := os.Stat(r.Name); err == nil {
				r.Status, r.Reason = packages.UpdateFailed, "still there after gio trash"
			}
			continue
		}
		if pythons == nil {
			pythons = a.installedPythons(ctx, s)
		}
		if pythons[r.From] {
			r.Status, r.Reason = packages.UpdateFailed, "still installed after uv python uninstall"
		}
	}
	return rs
}

func (a *app) cleanupPlan(ctx context.Context, s *core.PackagesScanner, d packages.Data) packages.Plan {
	var plan packages.Plan
	trash := s.ScanEnv.Which("gio")
	if r, err := a.engine.Saved(ctx, packages.Command, ""); err == nil && r != nil {
		for _, fd := range r.Findings {
			if fd.Check != "runtime.stale_dirs" {
				continue
			}
			it := packages.Planned{Kind: packages.KindMigration, Package: packages.Package{Manager: "trash", Name: fd.Subject},
				Command: []string{"gio", "trash", fd.Subject}}
			if trash == "" {
				it.Skip = "gio not found; delete it by hand"
			}
			plan.Items = append(plan.Items, it)
		}
	}
	metas, err := a.store.RuntimeMeta(ctx)
	if err != nil {
		a.log.Warn("load runtime cache", "err", err)
		return plan
	}
	var uv *packages.Inventory
	for i := range d.Inventories {
		if d.Inventories[i].Manager == "uv" && d.Inventories[i].Available {
			uv = &d.Inventories[i]
		}
	}
	if uv == nil {
		return plan
	}
	for _, v := range packages.SupersededPythons(metas[packages.RuntimePython], uv) {
		plan.Items = append(plan.Items, packages.Planned{Kind: packages.KindMigration,
			Package: packages.Package{Manager: "uv", Name: "python" + v, Version: v},
			Command: []string{"uv", "python", "uninstall", v}})
	}
	return plan
}

func (a *app) installedPythons(ctx context.Context, s *core.PackagesScanner) map[string]bool {
	out := map[string]bool{}
	l := a.rtLooker
	if l == nil {
		l = registry.NewClient(s.ScanEnv, "", a.cfg.Packages.Registry.Timeout)
	}
	m, err := l.LookupRuntime(ctx, packages.RuntimePython)
	if err != nil {
		a.log.Warn("list pythons", "err", err)
		return out
	}
	for _, in := range m.Installs {
		out[in.Version] = true
	}
	return out
}

// finishUpdate saves an update, prunes old ones and prints it.
func (a *app) finishUpdate(ctx context.Context, u *packages.Update, asJSON bool) error {
	u.FinishedAt = timeNow()
	if err := a.store.SaveUpdate(context.WithoutCancel(ctx), u); err != nil {
		return fmt.Errorf("save update: %w", err)
	}
	if err := a.store.PruneUpdates(context.WithoutCancel(ctx), a.cfg.History); err != nil {
		a.log.Warn("prune updates", "err", err)
	}
	if asJSON {
		if err := a.writeJSON(u); err != nil {
			return err
		}
	} else {
		a.printUpdate(u, false)
	}
	return ctx.Err()
}

func failedErr(u *packages.Update, what string) error {
	if _, failed, _ := u.Counts(); failed > 0 {
		return fmt.Errorf("%d %s(s) failed", failed, what)
	}
	return nil
}
