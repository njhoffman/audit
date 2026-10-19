package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/configs"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newConfigsCmd(a *app) *cobra.Command {
	var orphansOnly bool
	c, f := scanCommand(a, "configs", "Check config files and find configs of uninstalled programs",
		`Parse the json, jsonc, yaml, toml, ini and xml files under configs.roots
(~/.config by default) for syntax errors, run the read-only checks
programs offer for their own configs (git config --list, ssh -G,
systemd-analyze --user verify, i3 -C, sway -C, fish -n, tmux source-file
-n when a tmux server runs), and report files holding credential-looking
values that other users can read (the key name only, never the value).

Each ~/.config entry and home dotfile is matched to the program it belongs
to: package inventories, apt packages (executables traced with dpkg -S),
flatpaks, snaps and PATH executables. Entries matching nothing are
config.orphaned, with an uninstalled apt package of the same name when
apt-cache knows one. --list shows every entry with its owner; --orphans
only the orphans. audit configs clean moves orphans to the trash.`,
		func() (core.Scanner, error) { return a.configsScanner(context.Background()), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) {
			var d configs.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				a.log.Warn("read configs data", "err", err)
				return
			}
			var rows [][]string
			for _, e := range d.Entries {
				owner := e.Owner
				if owner == "" {
					owner = "orphaned"
					if e.Guess != "" {
						owner += " (" + e.Guess + "?)"
					}
				} else if orphansOnly {
					continue
				}
				rows = append(rows, []string{shortPath(e.Path, a.env.Home), files.Human(e.Bytes), owner})
			}
			p.Table([]string{"CONFIG", "SIZE", "OWNER"}, rows)
			say(a.out, "%d config file(s) parsed.\n", d.Parsed)
		})
	c.Flags().BoolVarP(&orphansOnly, "orphans", "O", false, "list only configs that belong to no installed program (implies --list)")
	f.impliesList = func() bool { return orphansOnly }
	f.jsonExtra = func(_ context.Context, r *run.Run) (any, error) {
		var d configs.Data
		err := json.Unmarshal(r.Data, &d)
		return d, err
	}
	c.AddCommand(newConfigsCleanCmd(a))
	return c
}

func shortPath(p, home string) string {
	if rest, ok := strings.CutPrefix(p, home); ok {
		return "~" + rest
	}
	return p
}

// configsScanner builds the scanner with the saved package inventories.
func (a *app) configsScanner(ctx context.Context) *core.ConfigsScanner {
	var invs []packages.Inventory
	if _, saved, err := a.savedInventory(ctx); err == nil {
		invs = saved
	}
	return core.NewConfigs(a.cfg, a.env, invs)
}

func newConfigsCleanCmd(a *app) *cobra.Command {
	var f cleanFlags
	c := &cobra.Command{
		Use:   "clean [path...]",
		Short: "Move configs of uninstalled programs to the trash",
		Long: `Plan moving the orphaned configs of the saved configs results to the trash
(gio trash), each one confirmed in the plan like a package update (--yes,
--dry-run). Paths limit the plan. An entry must still exist and lie in
home; ignore false matches with configs:config.orphaned:PATH so they are
never planned. --last shows the last cleanup (files or configs).`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if f.last {
				return a.lastUpdate(c.Context(), f.json, f.explain, files.KindClean)
			}
			return a.cleanConfigs(c.Context(), args, f)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "clean without asking")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining steps after the first failure")
	fl.BoolVarP(&f.last, "last", "L", false, "show the last cleanup; change nothing")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the cleanup as JSON")
	fl.BoolVarP(&f.explain, "explain", "e", false, "ask the AI why the failed steps failed")
	c.MarkFlagsMutuallyExclusive("explain", "json")
	return c
}

func (a *app) cleanConfigs(ctx context.Context, paths []string, f cleanFlags) error {
	r, err := a.engine.Saved(ctx, configs.Command, "")
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("no saved configs results; run `audit configs -r` first")
	}
	var d configs.Data
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return fmt.Errorf("read configs data: %w", err)
	}
	// Orphans the user ignored stay out: the saved findings already have
	// the ignore rules applied.
	reported := map[string]bool{}
	for _, fd := range r.Findings {
		if fd.Check == "config.orphaned" {
			reported[fd.Subject] = true
		}
	}
	opts := files.CleanOptions{Home: a.env.Home, Roots: []string{a.env.Home}}
	var plan packages.Plan
	for _, e := range d.Entries {
		if e.Owner != "" || !reported[e.Path] || !named(e.Path, paths, a) {
			continue
		}
		it := packages.Planned{Kind: files.KindClean, Package: packages.Package{Manager: "config", Name: e.Path, Ident: e.Path,
			Version: files.Human(e.Bytes)}, Latest: "in the trash", Command: []string{"gio", "trash", "--", e.Path}}
		if !opts.Safe(e.Path) {
			it.Skip = "gone, or outside home"
		}
		plan.Items = append(plan.Items, it)
	}
	ok, err := a.planGate(plan, runtimeFlags{dryRun: f.dryRun, yes: f.yes, json: f.json}, "Move %d config(s) to the trash?", "Nothing to clean.")
	if !ok || err != nil {
		return err
	}
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	u.Items = a.execPlan(ctx, a.env, plan, "cleaning configs", f.stopOnError, !f.json, !f.json && !a.flags.quiet)
	files.VerifyClean(u.Items)
	if err := a.finishUpdate(ctx, u, f.json); err != nil {
		return err
	}
	return a.failedErr(ctx, u, "cleanup step", f.explain)
}

func named(p string, paths []string, a *app) bool {
	if len(paths) == 0 {
		return true
	}
	for _, n := range paths {
		abs, err := filepath.Abs(a.env.Expand(n))
		if err == nil && (p == abs || strings.HasPrefix(p, abs+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}
