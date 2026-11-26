package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/history"
	"github.com/njhoffman/audit/internal/run"
)

func newHistoryBackupsCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "backups",
		Short: "List the backups prune, sync and restore keep beside each history",
		Long: `List the .NAME.audit-backup-* files audit history prune, sync and restore
wrote beside each configured history, newest first, with their size and
record count. They hold the old commands, including any secrets you pruned.
Nothing is removed unless you run audit history backups clean, or set
shell_history.backup_max_age or shell_history.backup_keep, which then apply
after every prune, sync and restore.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			bs, err := history.ListBackups(core.NewHistory(a.cfg, a.env).Options)
			if err != nil {
				return err
			}
			if asJSON {
				if bs == nil {
					bs = []history.Backup{}
				}
				return a.writeJSON(bs)
			}
			if len(bs) == 0 {
				sayln(a.out, "No history backups.")
				return nil
			}
			a.printer().Table([]string{"BACKUP", "OF", "AGE", "SIZE", "RECORDS"}, backupRows(bs))
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the backups as JSON")
	c.AddCommand(newHistoryBackupsCleanCmd(a), newHistoryBackupsRestoreCmd(a))
	return c
}

func backupRows(bs []history.Backup) [][]string {
	rows := make([][]string, len(bs))
	for i, b := range bs {
		rows[i] = []string{b.Path, b.Of, run.HumanAge(timeNow().Sub(b.CreatedAt)), files.Human(b.Size), fmt.Sprint(b.Records)}
	}
	return rows
}

func newHistoryBackupsCleanCmd(a *app) *cobra.Command {
	var olderThan time.Duration
	var keep int
	var dryRun, yes, asJSON bool
	c := &cobra.Command{
		Use:   "clean",
		Short: "Remove history backups by age or count",
		Long: `Remove history backups older than --older-than, and per history all but
the newest --keep. At least one is required. The plan is listed, then
confirmed (or --yes); --dry-run changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if olderThan <= 0 && keep <= 0 {
				return errors.New("give --older-than, --keep or both")
			}
			if err := a.load(); err != nil {
				return err
			}
			bs, err := history.ListBackups(core.NewHistory(a.cfg, a.env).Options)
			if err != nil {
				return err
			}
			pick := history.SelectBackups(bs, olderThan, keep, timeNow())
			if pick == nil {
				pick = []history.Backup{}
			}
			if asJSON && dryRun {
				return a.writeJSON(pick)
			}
			if len(pick) == 0 {
				if asJSON {
					return a.writeJSON(pick)
				}
				sayln(a.out, "No backups to remove.")
				return nil
			}
			if !asJSON {
				a.printer().Table([]string{"BACKUP", "OF", "AGE", "SIZE", "RECORDS"}, backupRows(pick))
			}
			if dryRun {
				return nil
			}
			if !yes {
				if asJSON {
					return errors.New("--json requires --dry-run or --yes")
				}
				ok, err := a.confirm(fmt.Sprintf("Remove %d backup(s)? They cannot be recovered.", len(pick)))
				if err != nil || !ok {
					return err
				}
			}
			errs := history.RemoveBackups(pick)
			if asJSON {
				if err := a.writeJSON(struct {
					Removed int      `json:"removed"`
					Errors  []string `json:"errors"`
				}{len(pick) - len(errs), append([]string{}, errs...)}); err != nil {
					return err
				}
			} else {
				say(a.out, "Removed %d backup(s).\n", len(pick)-len(errs))
			}
			if len(errs) > 0 {
				return errors.New(strings.Join(errs, "\n"))
			}
			return nil
		},
	}
	fl := c.Flags()
	fl.DurationVarP(&olderThan, "older-than", "o", 0, "remove backups older than this (e.g. 720h)")
	fl.IntVarP(&keep, "keep", "k", 0, "keep only this many newest backups per history")
	fl.BoolVarP(&dryRun, "dry-run", "N", false, "list what would be removed")
	fl.BoolVarP(&yes, "yes", "y", false, "remove without asking")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the plan or result as JSON")
	return c
}

func newHistoryBackupsRestoreCmd(a *app) *cobra.Command {
	var dryRun, yes, asJSON bool
	c := &cobra.Command{
		Use:   "restore BACKUP",
		Short: "Put a history backup back over its history",
		Long: `Compare BACKUP with the history it was made of, by record counts only
(records that come back, records that go), then replace the history with it
under the same checks and locks as prune. The current history is backed up
first, so a restore can be undone the same way. Close other shell sessions
first: their in-memory history can write the old entries back.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			o := core.NewHistory(a.cfg, a.env).Options
			p, err := history.PlanRestore(o, a.env.Expand(args[0]))
			if err != nil {
				return err
			}
			if asJSON && dryRun {
				return a.writeJSON(p)
			}
			if !asJSON {
				say(a.out, "%s: %d records now, %d in the backup; restoring brings back %d and drops %d.\n",
					p.Path, p.Current, p.FromBackup, p.Missing, p.Extra)
			}
			if dryRun {
				return nil
			}
			if !yes {
				if asJSON {
					return errors.New("--json requires --dry-run or --yes")
				}
				ok, err := a.confirm("Replace " + p.Path + " with the backup (the current file is backed up)?")
				if err != nil || !ok {
					return err
				}
			}
			made, err := history.ApplyRestore(c.Context(), p)
			if err != nil {
				return err
			}
			if asJSON {
				if err := a.writeJSON(struct {
					history.RestorePlan
					NewBackup string `json:"new_backup"`
				}{p, made}); err != nil {
					return err
				}
			} else {
				say(a.out, "Restored %s; the replaced file is in %s.\n", p.Path, made)
			}
			a.retainBackups(o, !asJSON)
			_, err = a.engine.Execute(context.WithoutCancel(c.Context()), core.NewHistory(a.cfg, a.env), a.progress(!asJSON))
			return err
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&dryRun, "dry-run", "N", false, "show what restoring would change")
	fl.BoolVarP(&yes, "yes", "y", false, "restore without asking")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the plan or result as JSON")
	return c
}

// retainBackups applies shell_history.backup_max_age and backup_keep, when
// set, after a command wrote a backup. Failures are warnings: the history
// change itself went through.
func (a *app) retainBackups(o history.Options, show bool) {
	sh := a.cfg.ShellHistory
	if sh.BackupMaxAge <= 0 && sh.BackupKeep <= 0 {
		return
	}
	bs, err := history.ListBackups(o)
	if err != nil {
		a.log.Warn("list history backups", "err", err)
		return
	}
	pick := history.SelectBackups(bs, sh.BackupMaxAge, sh.BackupKeep, timeNow())
	errs := history.RemoveBackups(pick)
	for _, e := range errs {
		a.log.Warn("remove history backup", "err", e)
	}
	if n := len(pick) - len(errs); n > 0 && show {
		say(a.out, "Removed %d old backup(s) (shell_history.backup_max_age / backup_keep).\n", n)
	}
}
