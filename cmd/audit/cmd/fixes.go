package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// withFixHistory adds a detail line to an open task that was closed before,
// saying when and how, so show, explain and fix see the problem came back.
func (a *app) withFixHistory(ctx context.Context, t *todo.Todo) {
	if t.Status.Closed() || t.Key == "" {
		return
	}
	prev, err := a.store.PreviousFix(ctx, t.Key)
	if err != nil || prev == nil {
		if err != nil {
			a.log.Warn("read the task's history", "err", err)
		}
		return
	}
	how := "resolved by a rescan"
	if prev.Action == string(todo.Done) {
		how = "marked done"
	}
	t.Details = append(t.Details, fmt.Sprintf("fixed before: %s on %s, and it came back", how, prev.At.Local().Format("2006-01-02 15:04")))
}

func newHistoryRunsFixesCmd(a *app) *cobra.Command {
	var since time.Duration
	var limit int
	var asJSON bool
	c := &cobra.Command{
		Use:   "fixes",
		Short: "What got fixed: tasks closed and reopened, packages updated, repos synced, files cleaned",
		Long: `List what audit and you got done, newest first: tasks resolved by a rescan,
marked done or won't do, and reopened when their problem came back; and
every action step that succeeded (package and runtime updates, repo
syncs, files, configs and containers cleanups, history prunes). This log is kept when
runs, tasks and update runs are pruned. The totals count tasks closed per
command and priority, reopened tasks, and steps per kind.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			var from time.Time
			if since > 0 {
				from = timeNow().Add(-since)
			}
			as, err := a.store.Activities(c.Context(), from, 0)
			if err != nil {
				return err
			}
			if asJSON {
				if as == nil {
					as = []store.Activity{}
				}
				return a.writeJSON(as)
			}
			p := a.printer()
			p.Now = timeNow
			p.Fixes(as, limit)
			return nil
		},
	}
	fl := c.Flags()
	fl.DurationVarP(&since, "since", "s", 0, "only entries newer than this (e.g. 720h)")
	fl.IntVarP(&limit, "limit", "l", 30, "list at most this many entries (0 for all; the totals count every one)")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the entries as JSON")
	return c
}
