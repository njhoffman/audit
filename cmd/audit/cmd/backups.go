package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/backups"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newBackupsCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "backups", "Check when backups last ran and which paths they cover",
		`Check the workstation's backups: Deja Dup (read from its settings when
installed) and the sources in backups.sources, each a command that prints
when its last backup finished. Findings: no backup at all, one that never
finished, one older than backups.max_age (an error past four times it),
Deja Dup not backing up automatically, a backups.paths entry no source
covers, and a source whose command fails. --list shows each source.`,
		func(context.Context) (core.Scanner, error) { return core.NewBackups(a.cfg, a.env), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) error {
			var d backups.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				return fmt.Errorf("read backups data: %w", err)
			}
			rows := make([][]string, len(d.Backups))
			for i, b := range d.Backups {
				last := "never"
				if !b.Last.IsZero() {
					last = b.Last.Local().Format("2006-01-02 15:04") + " (" + run.HumanAge(r.FinishedAt.Sub(b.Last)) + " ago)"
				}
				if b.Error != "" {
					last = "error: " + b.Error
				}
				sched := "-"
				if b.Scheduled != nil {
					sched = map[bool]string{true: "yes", false: "no"}[*b.Scheduled]
				}
				rows[i] = []string{b.Name, last, sched, strings.Join(b.Covers, ", ")}
			}
			p.Table([]string{"BACKUP", "LAST", "AUTOMATIC", "COVERS"}, rows)
			return nil
		})
	return c
}
