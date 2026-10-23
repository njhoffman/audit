package cmd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/history"
	"github.com/njhoffman/audit/internal/store"
)

func newHistoryCmd(a *app) *cobra.Command {
	c, _ := scanCommand(a, "history", "Check shell history for duplicates, large entries and configured patterns",
		`Read shell_history.files (zsh, bash and fish), reporting repeated entries,
entries with at least shell_history.max_lines logical lines, and matches of
case-sensitive literal substrings in shell_history.patterns. Missing files
are skipped; oversized or unreadable files are reported as scan errors.
Bash multiline entries require saved timestamps to recover their boundaries.
Only counts and file:line locations are saved, never command text or pattern
values. No history is changed. Use audit history runs to list saved audit runs.`,
		func() (core.Scanner, error) { return core.NewHistory(a.cfg, a.env), nil }, nil)
	c.AddCommand(newHistoryRunsCmd(a), newHistoryPruneCmd(a))
	return c
}

func newHistoryPruneCmd(a *app) *cobra.Command {
	var only []string
	var dryRun, yes, asJSON bool
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
				categories = []string{"duplicates", "multiline", "patterns"}
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
			for _, plan := range plans {
				backup, err := history.ApplyPrune(c.Context(), plan)
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
	return c
}
