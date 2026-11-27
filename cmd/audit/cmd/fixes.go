package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/run"
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
			if len(as) == 0 {
				sayln(a.out, "Nothing recorded yet: tasks closing and successful updates, syncs and cleanups are logged as they happen.")
				return nil
			}
			a.printFixTotals(as)
			shown := as
			if limit > 0 && len(shown) > limit {
				shown = shown[:limit]
			}
			rows := make([][]string, len(shown))
			for i, x := range shown {
				what := x.Title
				if x.From != "" || x.To != "" {
					what += " " + x.From + " -> " + x.To
				}
				where := x.Command
				if where == "" {
					where = x.Kind
				}
				rows[i] = []string{x.At.Local().Format("2006-01-02 15:04"), run.HumanAge(timeNow().Sub(x.At)), where, x.Action, string(x.Priority), what}
			}
			sayln(a.out, "")
			a.printer().Table([]string{"WHEN", "AGE", "COMMAND", "WHAT", "PRIORITY", "ITEM"}, rows)
			if len(shown) < len(as) {
				say(a.out, "%d older entries; -l 0 lists them all.\n", len(as)-len(shown))
			}
			return nil
		},
	}
	fl := c.Flags()
	fl.DurationVarP(&since, "since", "s", 0, "only entries newer than this (e.g. 720h)")
	fl.IntVarP(&limit, "limit", "l", 30, "list at most this many entries (0 for all; the totals count every one)")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the entries as JSON")
	return c
}

// printFixTotals sums the log: tasks closed per command (by priority),
// reopened ones, and action steps per kind.
func (a *app) printFixTotals(as []store.Activity) {
	closed := map[string]map[todo.Priority]int{}
	reopened, steps := 0, map[string]int{}
	for _, x := range as {
		switch {
		case x.Kind == "task" && x.Action == "reopened":
			reopened++
		case x.Kind == "task" && x.Action != string(todo.WontDo):
			if closed[x.Command] == nil {
				closed[x.Command] = map[todo.Priority]int{}
			}
			closed[x.Command][x.Priority]++
		case x.Kind != "task":
			steps[x.Kind]++
		}
	}
	cmds := make([]string, 0, len(closed))
	for c := range closed {
		cmds = append(cmds, c)
	}
	sort.Strings(cmds)
	var rows [][]string
	for _, c := range cmds {
		total := 0
		var parts []string
		for _, p := range todo.Priorities {
			if n := closed[c][p]; n > 0 {
				total += n
				parts = append(parts, fmt.Sprintf("%d %s", n, p))
			}
		}
		rows = append(rows, []string{c, fmt.Sprint(total), strings.Join(parts, ", ")})
	}
	if len(rows) > 0 {
		sayln(a.out, "Tasks fixed (resolved or done):")
		a.printer().Table([]string{"COMMAND", "FIXED", "BY PRIORITY"}, rows)
	}
	var parts []string
	kinds := make([]string, 0, len(steps))
	for k := range steps {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%d %s", steps[k], k))
	}
	if len(parts) > 0 {
		say(a.out, "Steps done: %s.\n", strings.Join(parts, ", "))
	}
	if reopened > 0 {
		say(a.out, "Reopened: %d task(s) came back after being fixed.\n", reopened)
	}
}
