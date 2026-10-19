package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newFilesCmd(a *app) *cobra.Command {
	c, f := scanCommand(a, "files", "Show where disk space goes and what can be reclaimed",
		`Measure files.roots (home by default) without crossing into other
filesystems, and find space to reclaim: tool and system caches (uv, pip,
go, pnpm, npm, yarn, cargo, thumbnails, apt archives, the journal,
disabled snap revisions, docker), node_modules, target, .venv and other
build directories of projects idle for files.stale_after, data in
~/.cache, ~/.local/share and ~/.local/state of programs that look
uninstalled, the largest files, downloads older than files.old_downloads,
a large trash, duplicate files (confirmed by hash), core dumps, empty
directories and broken symlinks.

--list prints the largest directories and every candidate. Nothing is
deleted here; audit files clean plans the cleanup.`,
		func() (core.Scanner, error) { return core.NewFiles(a.cfg, a.env), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) {
			var d files.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				a.log.Warn("read files data", "err", err)
				return
			}
			p.Files(d, a.env.Home)
		})
	f.jsonExtra = func(_ context.Context, r *run.Run) (any, error) {
		var d files.Data
		err := json.Unmarshal(r.Data, &d)
		return d, err
	}
	c.AddCommand(newFilesCleanCmd(a))
	return c
}

type cleanFlags struct {
	dryRun, yes, stopOnError, last, json, explain bool
	categories                                    []string
}

func newFilesCleanCmd(a *app) *cobra.Command {
	var f cleanFlags
	c := &cobra.Command{
		Use:   "clean [path...]",
		Short: "Reclaim the space audit files found",
		Long: `Plan and run the cleanup of the saved files results (run audit files -r
first for fresh ones). Categories (--categories, default cache,build,cores):

  cache       caches with a cleaner run it (uv cache clean, go clean -cache,
              pnpm store prune, sudo apt-get clean, sudo journalctl
              --vacuum-size=500M, sudo snap remove --revision, docker system
              prune); other caches are deleted
  build       idle projects' node_modules, target, .venv... deleted; they are
              rebuilt on demand
  cores       core dumps, deleted
  orphaned    data of programs that look uninstalled, moved to the trash
  downloads   old downloads, moved to the trash
  duplicates  every copy but the first (in sorted order), moved to the trash
  trash       empties the trash (cannot be undone)

Paths limit the plan to those targets. Every target must still exist, lie
inside files.roots and be neither a root nor home; the rest are skipped
with the reason. The plan is confirmed like a package update (--yes,
--dry-run), sudo is asked once for system caches, and the results are
saved; --last shows the last cleanup.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if f.last {
				return a.lastUpdate(c.Context(), f.json, f.explain, files.KindClean)
			}
			return a.cleanFiles(c.Context(), args, f)
		},
	}
	fl := c.Flags()
	fl.StringSliceVarP(&f.categories, "categories", "C", nil, "what to clean: "+strings.Join(files.Categories, ", ")+" or all")
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "clean without asking")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining steps after the first failure")
	fl.BoolVarP(&f.last, "last", "L", false, "show the last cleanup; change nothing")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the cleanup as JSON")
	fl.BoolVarP(&f.explain, "explain", "e", false, "ask the AI why the failed steps failed")
	c.MarkFlagsMutuallyExclusive("explain", "json")
	return c
}

func (a *app) cleanFiles(ctx context.Context, paths []string, f cleanFlags) error {
	cats, err := files.ParseCategories(splitList(f.categories))
	if err != nil {
		return err
	}
	r, err := a.engine.Saved(ctx, files.Command, "")
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("no saved files results; run `audit files -r` first")
	}
	var d files.Data
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return fmt.Errorf("read files data: %w", err)
	}
	s := core.NewFiles(a.cfg, a.env)
	abs := make([]string, len(paths))
	for i, p := range paths {
		abs[i], _ = filepath.Abs(a.env.Expand(p))
	}
	plan := files.PlanClean(d, files.CleanOptions{Categories: cats, Paths: abs, Home: a.env.Home, Roots: s.Options.Roots,
		CacheMinMB: a.cfg.Files.CacheMinMB})
	if !f.json && !f.dryRun {
		say(a.errOut, "Planning from the files scan of %s.\n", r.FinishedAt.Local().Format("2006-01-02 15:04"))
	}
	var stopSudo func()
	defer func() {
		if stopSudo != nil {
			stopSudo()
		}
	}()
	if !f.dryRun && plan.NeedsRoot() && !a.interactive() {
		if stop, err := a.sudoSession(ctx, a.env, "system caches"); err != nil {
			plan = skipRoot(plan, "needs sudo: "+err.Error())
		} else {
			stopSudo = stop
		}
	}
	ok, err := a.planGate(plan, runtimeFlags{dryRun: f.dryRun, yes: f.yes, json: f.json}, "Run %d cleanup step(s)?", "Nothing to clean.")
	if !ok || err != nil {
		return err
	}
	if plan.NeedsRoot() && stopSudo == nil {
		stop, err := a.sudoSession(ctx, a.env, "system caches")
		if err != nil {
			plan = skipRoot(plan, "needs sudo: "+err.Error())
		} else {
			stopSudo = stop
		}
	}
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	u.Items = a.execPlan(ctx, a.env, plan, "cleaning", f.stopOnError, !f.json, !f.json && !a.flags.quiet)
	files.VerifyClean(u.Items)
	if err := a.finishUpdate(ctx, u, f.json); err != nil {
		return err
	}
	if !f.json {
		var freed int64
		for _, it := range plan.Items {
			for _, res := range u.Items {
				if res.ID == it.Ident && res.Manager == it.Manager && res.Status == packages.UpdateOK {
					freed += sizeOf(d, it)
				}
			}
		}
		say(a.out, "About %s freed or moved to the trash; run audit files -r to measure again.\n", files.Human(freed))
	}
	return a.failedErr(ctx, u, "cleanup step", f.explain)
}

// sizeOf finds a planned target's size in the scan data.
func sizeOf(d files.Data, it packages.Planned) int64 {
	for _, c := range d.Caches {
		if c.Path == it.Ident || c.Name == it.Ident {
			return c.Bytes
		}
	}
	for _, b := range d.Build {
		if b.Path == it.Ident {
			return b.Bytes
		}
	}
	for _, o := range d.Orphans {
		if o.Path == it.Ident {
			return o.Bytes
		}
	}
	for _, fl := range append(append([]files.File{}, d.Downloads...), d.Cores...) {
		if fl.Path == it.Ident {
			return fl.Bytes
		}
	}
	for _, x := range d.Dups {
		if slices.Contains(x.Paths[1:], it.Ident) {
			return x.Bytes
		}
	}
	if it.Ident == d.TrashPath {
		return d.Trash
	}
	return 0
}
