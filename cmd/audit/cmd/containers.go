package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/containers"
	"github.com/njhoffman/audit/internal/core"
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
unused volume. Nothing is removed; the hints name the prune commands.`,
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
	return c
}
