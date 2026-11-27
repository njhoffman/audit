package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/containers"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newContainersCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "containers", "Check docker and podman for leftovers: dangling images, unused volumes, old containers",
		`Ask each installed container engine (containers.engines: docker, podman)
for its objects, with listing commands only. Findings: containers stopped
and created longer than containers.stopped_after ago (30 days), dangling
images, volumes no container uses, and an engine that cannot be reached
(stopped, or a socket this user may not open). The summary shows each
engine's version, whether it runs rootless, and its system df with what
it could reclaim. --list shows every stopped container, dangling image and
unused volume. The scan removes nothing; audit containers clean removes
what it reported.`,
		func() (core.Scanner, error) { return core.NewContainers(a.cfg, a.env), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) error {
			var d containers.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				return fmt.Errorf("read containers data: %w", err)
			}
			var rows [][]string
			for _, e := range d.Engines {
				for _, c := range e.Stopped {
					created := "-"
					if !c.Created.IsZero() {
						created = run.HumanAge(r.FinishedAt.Sub(c.Created)) + " ago"
					}
					rows = append(rows, []string{e.Name, "stopped container", c.Name + " (" + c.ID + ")", c.Image + ", created " + created})
				}
				for _, im := range e.Dangling {
					rows = append(rows, []string{e.Name, "dangling image", im.ID, im.Size})
				}
				for _, v := range e.Volumes {
					rows = append(rows, []string{e.Name, "unused volume", v, ""})
				}
			}
			if len(rows) == 0 {
				sayln(a.out, "No stopped containers, dangling images or unused volumes.")
				return nil
			}
			p.Table([]string{"ENGINE", "KIND", "NAME", "DETAIL"}, rows)
			return nil
		})
	c.AddCommand(newContainersCleanCmd(a))
	return c
}

type containersCleanFlags struct {
	cleanFlags
	volumes bool
}

func newContainersCleanCmd(a *app) *cobra.Command {
	var f containersCleanFlags
	c := &cobra.Command{
		Use:   "clean [name...]",
		Short: "Remove the stopped containers and dangling images audit containers found",
		Long: `Plan removing what the saved containers results reported: containers
stopped and created longer than containers.stopped_after ago, and dangling
images; with --volumes also the volumes no container uses (left out by
default, since a volume holds data). Names (container names or IDs, image
IDs, volume names) limit the plan. Each step is the engine's plain remove
(docker rm, rmi, volume rm), which refuses a container running again or
an image or volume a container uses since the scan; the step then fails
and the object stays. Confirmed like a package update (--yes, --dry-run);
an ignored finding keeps its objects out of the plan. --last shows the
last cleanup (files, configs or containers).`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if f.last {
				return a.lastUpdate(c.Context(), f.json, f.explain, containers.KindClean)
			}
			return a.cleanContainers(c.Context(), args, f)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&f.volumes, "volumes", "V", false, "also remove the volumes no container uses")
	fl.BoolVarP(&f.dryRun, "dry-run", "N", false, "print the plan and the commands it would run, then stop")
	fl.BoolVarP(&f.yes, "yes", "y", false, "clean without asking")
	fl.BoolVarP(&f.stopOnError, "stop-on-error", "x", false, "skip the remaining steps after the first failure")
	fl.BoolVarP(&f.last, "last", "L", false, "show the last cleanup; change nothing")
	fl.BoolVarP(&f.json, "json", "j", false, "print the plan (with --dry-run) or the cleanup as JSON")
	fl.BoolVarP(&f.explain, "explain", "e", false, "ask the AI why the failed steps failed")
	c.MarkFlagsMutuallyExclusive("explain", "json")
	return c
}

func (a *app) cleanContainers(ctx context.Context, names []string, f containersCleanFlags) error {
	r, err := a.engine.Saved(ctx, containers.Command, "")
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("no saved containers results; run `audit containers -r` first")
	}
	var d containers.Data
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return fmt.Errorf("read containers data: %w", err)
	}
	// The saved findings have the ignore rules applied: an ignored one
	// keeps its objects out of the plan.
	reported := map[string]bool{}
	for _, fd := range r.Findings {
		reported[fd.Check+"\x00"+fd.Subject] = true
	}
	plan := containers.CleanPlan(d, containers.CleanOptions{
		StoppedAfter: a.cfg.Containers.StoppedAfter, ScannedAt: r.FinishedAt, Volumes: f.volumes, Names: names,
		Reported: func(check, engine string) bool { return reported[check+"\x00"+engine] },
	})
	ok, err := a.planGate(plan, runtimeFlags{dryRun: f.dryRun, yes: f.yes, json: f.json}, "Remove %d container object(s)?", "Nothing to clean.")
	if !ok || err != nil {
		return err
	}
	u := &packages.Update{Host: a.engine.Host, StartedAt: timeNow()}
	u.Items = a.execPlan(ctx, a.env, plan, "cleaning containers", f.stopOnError, !f.json, !f.json && !a.flags.quiet)
	containers.VerifyClean(ctx, a.env, u.Items)
	if err := a.finishUpdate(ctx, u, f.json); err != nil {
		return err
	}
	return a.failedErr(ctx, u, "cleanup step", f.explain)
}
