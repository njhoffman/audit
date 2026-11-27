package cmd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/history"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
)

func newHistoryCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "history", "Check shell history and show histdb statistics",
		`Read shell_history.files (zsh, bash and fish), reporting entries with at
least shell_history.max_lines logical lines, and matches of case-sensitive
literal substrings in shell_history.patterns. Missing files are skipped; oversized or unreadable files are reported as scan errors.
Bash multiline entries require saved timestamps to recover their boundaries.
Only counts and file:line locations are saved, never command text or pattern
values. Repeated commands are retained and are not issues. The history summary
includes histdb total, current-host and current-session entry counts when available.
No history is changed. Use audit history runs to list saved audit runs.`,
		func() (core.Scanner, error) { return core.NewHistory(a.cfg, a.env), nil }, nil)
	c.AddCommand(newHistoryRunsCmd(a), newHistoryPruneCmd(a), newHistorySyncCmd(a), newHistoryBackupsCmd(a))
	return c
}

func newHistorySyncCmd(a *app) *cobra.Command {
	var yes, force bool
	var file string
	c := &cobra.Command{Use: "sync", Short: "Rebuild a zsh history file from histdb", Args: cobra.NoArgs,
		Long: `Rebuild a zsh history file from histdb, keeping histdb's timestamps and
durations, metafied as zsh writes its own history. The target is --file, or
the first configured shell_history.files entry that reads as zsh history.

It refuses when histdb is empty, and when histdb holds fewer entries than the
file (histdb only knows the commands since it was installed, so replacing
the file would drop the rest) unless --force is given. The file is replaced
after confirmation (or --yes) under the same locks and checks as history
prune, after a private backup beside it whose path is printed.`,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			o := core.NewHistory(a.cfg, a.env).Options
			target := ""
			if file != "" {
				abs, err := filepath.Abs(a.env.Expand(file))
				if err != nil {
					return err
				}
				target = abs
			} else {
				for _, p := range o.Files {
					if f, _, err := history.FormatOf(o, p); err == nil && f == "zsh" {
						target = p
						break
					}
				}
			}
			if target == "" {
				return errors.New("no zsh history among shell_history.files; name one with --file")
			}
			plan, err := history.PlanSync(c.Context(), o.HistDB, target)
			if err != nil {
				return err
			}
			say(a.out, "histdb has %d entries; %s has %d.\n", plan.HistDB, target, plan.File)
			if plan.HistDB == 0 || (plan.Refusal != "" && !force) {
				return errors.New(plan.Refusal)
			}
			if !yes {
				ok, err := a.confirm("Replace " + target + " from histdb (private backup kept)?")
				if err != nil {
					return err
				}
				if !ok {
					return nil
				}
			}
			t0 := time.Now()
			backup, err := history.ApplySync(c.Context(), plan, force)
			a.recordHistory(c.Context(), t0, []historyOutcome{{action: "sync", path: target, backup: backup,
				before: plan.File, after: plan.HistDB, err: err, took: time.Since(t0)}})
			if err != nil {
				return err
			}
			say(a.out, "Wrote %d histdb entries to %s; the previous file is in %s.\n", plan.HistDB, target, backup)
			a.retainBackups(core.NewHistory(a.cfg, a.env).Options, true)
			_, err = a.engine.Execute(context.WithoutCancel(c.Context()), core.NewHistory(a.cfg, a.env), a.progress(true))
			return err
		}}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "replace without asking; keep a private backup")
	c.Flags().BoolVarP(&force, "force", "F", false, "replace even when histdb has fewer entries than the file")
	c.Flags().StringVarP(&file, "file", "f", "", "the zsh history file to rebuild (default: the first zsh file in shell_history.files)")
	return c
}

func newHistoryPruneCmd(a *app) *cobra.Command {
	var only []string
	var dryRun, yes, asJSON, last bool
	c := &cobra.Command{
		Use:   "prune [file...]",
		Short: "Preview and remove duplicate or unwanted shell history entries",
		Long: `Recheck configured shell histories and remove whole matching records,
including bash timestamps or fish metadata. Keeps the first occurrence of
each duplicate. --only selects duplicates (default), multiline, patterns,
or all. Ignore rules apply. Optional file paths limit the configured files.

The plan shows counts and locations without command text. --dry-run changes
nothing; otherwise confirm (or --yes). Each changed file gets a private
.NAME.audit-backup-* beside it before an atomic replacement. Refuses
symlinks, hard links, files owned by others, locked files, and files changed
since the preview. Close other shell sessions first: their in-memory
history can reintroduce entries when they later save. Backups contain the
original history, including any sensitive entries you removed.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if last {
				return a.lastHistory(c.Context(), asJSON)
			}
			o := core.NewHistory(a.cfg, a.env).Options
			if len(args) > 0 {
				var paths []string
				for _, arg := range args {
					path, err := filepath.Abs(a.env.Expand(arg))
					if err != nil {
						return err
					}
					if !slices.Contains(o.Files, path) {
						return fmt.Errorf("%s is not in shell_history.files", path)
					}
					paths = append(paths, path)
				}
				o.Files = paths
			}
			categories := splitList(only)
			if slices.Contains(categories, "all") {
				if len(categories) != 1 {
					return errors.New("--only all cannot be combined with other categories")
				}
				categories = slices.Clone(history.Categories)
			}
			if len(categories) == 0 {
				return errors.New("--only requires duplicates, multiline, patterns, or all")
			}
			plans, err := history.PlanPrune(c.Context(), o, categories, a.cfg.Ignore)
			if err != nil {
				return err
			}
			if asJSON && dryRun {
				if plans == nil {
					plans = []history.PrunePlan{}
				}
				return a.writeJSON(plans)
			}
			total := 0
			var rows [][]string
			for _, plan := range plans {
				total += plan.Remove
				locations := fmt.Sprint(plan.Lines[:min(len(plan.Lines), 20)])
				if len(plan.Lines) > 20 {
					locations += " ..."
				}
				rows = append(rows, []string{plan.Path, fmt.Sprint(plan.Remove), fmt.Sprint(plan.Keep), locations})
			}
			if !asJSON {
				a.printer().Table([]string{"HISTORY", "REMOVE", "KEEP", "START LINES"}, rows)
			}
			if total == 0 || dryRun {
				if !asJSON && total == 0 {
					sayln(a.out, "Nothing to prune.")
				}
				if asJSON {
					return a.writeJSON([]any{})
				}
				return nil
			}
			if !yes {
				if asJSON {
					return errors.New("--json requires --dry-run or --yes")
				}
				ok, err := a.confirm(fmt.Sprintf("Prune %d history entries (backups kept)?", total))
				if err != nil || !ok {
					return err
				}
			}
			type result struct {
				Path    string `json:"path"`
				Removed int    `json:"removed"`
				Backup  string `json:"backup,omitempty"`
				Error   string `json:"error,omitempty"`
			}
			results := []result{}
			var failures []error
			var outs []historyOutcome
			started := timeNow()
			for _, plan := range plans {
				t0 := time.Now()
				backup, err := history.ApplyPrune(c.Context(), plan)
				outs = append(outs, historyOutcome{action: "prune", path: plan.Path, backup: backup,
					before: plan.Remove + plan.Keep, after: plan.Keep, err: err, took: time.Since(t0)})
				r := result{Path: plan.Path, Backup: backup}
				if err != nil {
					r.Error = err.Error()
					failures = append(failures, fmt.Errorf("%s: %w", plan.Path, err))
				} else {
					r.Removed = plan.Remove
				}
				results = append(results, r)
				if !asJSON {
					say(a.out, "%s: %d entries removed; backup: %s\n", r.Path, r.Removed, backup)
				}
			}
			a.recordHistory(c.Context(), started, outs)
			a.retainBackups(o, !asJSON)
			// Reconcile findings and tasks even after a partial prune.
			_, err = a.engine.Execute(context.WithoutCancel(c.Context()), core.NewHistory(a.cfg, a.env), a.progress(!asJSON))
			if err != nil {
				failures = append(failures, fmt.Errorf("rescan after pruning: %w", err))
			}
			if asJSON {
				if err := a.writeJSON(results); err != nil {
					return err
				}
			}
			return errors.Join(failures...)
		},
	}
	c.Flags().StringSliceVarP(&only, "only", "O", []string{"duplicates"}, "remove duplicates, multiline, patterns, or all")
	c.Flags().BoolVarP(&dryRun, "dry-run", "N", false, "preview removals without changing history")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "prune without asking; keep backups")
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the preview or pruning results as JSON")
	c.Flags().BoolVarP(&last, "last", "L", false, "show the last recorded prune, sync or restore; change nothing")
	return c
}

func newHistoryRunsCmd(a *app) *cobra.Command {
	var (
		limit  int
		asJSON bool
	)
	c := &cobra.Command{
		Use:       "runs [COMMAND]",
		Short:     "List saved runs, newest first",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: core.Commands,
		RunE: func(c *cobra.Command, args []string) error {
			command := ""
			if len(args) == 1 {
				command = args[0]
				if !slices.Contains(core.Commands, command) {
					return fmt.Errorf("unknown command %q (want %s)", command, strings.Join(core.Commands, ", "))
				}
			}
			if err := a.load(); err != nil {
				return err
			}
			h, err := a.store.History(c.Context(), command, limit)
			if err != nil {
				return err
			}
			if asJSON {
				if h == nil {
					h = []store.RunInfo{}
				}
				return a.writeJSON(h)
			}
			a.printer().History(h)
			return nil
		},
	}
	c.Flags().IntVarP(&limit, "limit", "l", 20, "show at most this many runs (0 for all)")
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print runs as JSON")
	c.AddCommand(newHistoryRunsDiffCmd(a))
	return c
}

func newHistoryRunsDiffCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "diff A [B]",
		Short: "Show findings added, resolved and changed between two saved runs",
		Long: `Compare saved run A with run B (IDs from audit history runs), or with the
run of the same command and scope saved just before A when B is left out.
The older run is the baseline whatever the order given. Both runs must be
of the same command.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			ids := make([]int64, len(args))
			for i, s := range args {
				id, err := strconv.ParseInt(s, 10, 64)
				if err != nil || id <= 0 {
					return fmt.Errorf("%q is not a run ID; audit history runs lists them", s)
				}
				ids[i] = id
			}
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			runs := make([]*run.Run, len(ids))
			for i, id := range ids {
				r, err := a.store.GetRun(ctx, id)
				if err != nil {
					return err
				}
				if r == nil {
					return fmt.Errorf("no saved run %d; audit history runs lists the kept ones", id)
				}
				runs[i] = r
			}
			if len(runs) == 1 {
				return a.printDiff(ctx, runs[0], finding.Filter{}, asJSON)
			}
			from, to := runs[0], runs[1]
			if from.Command != to.Command {
				return fmt.Errorf("run %d is %s and run %d is %s; compare runs of one command", from.ID, from.Command, to.ID, to.Command)
			}
			if from.ID > to.ID {
				from, to = to, from
			}
			return a.showDiff(from, to, finding.Filter{}, asJSON)
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the difference as JSON")
	return c
}
