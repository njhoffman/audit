package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/schedule"
)

func newScheduleCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "schedule",
		Short: "Show, install or remove the systemd user timer that rescans unattended",
		Long: `audit schedule install writes audit.service and audit.timer under
$XDG_CONFIG_HOME/systemd/user and enables the timer: on schedule.calendar
it runs audit -r -q -O <schedule.commands>, rescanning the stale ones, with
-A when schedule.ai is set (an AI review per rescanned command, which costs
money unless cached). Nothing needs sudo. audit schedule shows whether the
timer is installed and enabled, when it runs next and how the last run
ended; audit schedule remove disables it and deletes both files.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			st := a.scheduleStatus(c.Context())
			if asJSON {
				return a.writeJSON(st)
			}
			if !st.Installed {
				sayln(a.out, "Not installed; audit schedule install sets it up.")
				return nil
			}
			rows := [][]string{{"units", st.Dir}, {"runs", st.ExecStart}, {"enabled", st.Enabled}, {"active", st.Active}}
			for _, kv := range [][2]string{{"next run", st.Next}, {"last run", st.Last}, {"last result", st.Result}} {
				if kv[1] != "" {
					rows = append(rows, []string{kv[0], kv[1]})
				}
			}
			a.printer().Table([]string{"TIMER", "STATE"}, rows)
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the timer's state as JSON")
	c.AddCommand(newScheduleInstallCmd(a), newScheduleRemoveCmd(a))
	return c
}

func (a *app) scheduleOptions() (schedule.Options, error) {
	sc := a.cfg.Schedule
	for _, cmd := range sc.Commands {
		if !slices.Contains(core.Commands, cmd) {
			return schedule.Options{}, fmt.Errorf("schedule.commands: unknown command %q (want %s)", cmd, strings.Join(core.Commands, ", "))
		}
	}
	return schedule.Options{Exe: packages.SelfCommand, Calendar: sc.Calendar, Commands: sc.Commands, AI: sc.AI}, nil
}

func (a *app) unitDir() string { return schedule.Dir(a.env.XDG("XDG_CONFIG_HOME")) }

func (a *app) systemctl(ctx context.Context, args ...string) exec.Result {
	return a.env.Run(ctx, "systemctl", append([]string{"--user"}, args...), exec.Options{Timeout: 30 * time.Second})
}

func newScheduleInstallCmd(a *app) *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Write and enable the timer from the schedule settings",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			o, err := a.scheduleOptions()
			if err != nil {
				return err
			}
			if !filepath.IsAbs(o.Exe) {
				return fmt.Errorf("cannot tell where this audit binary is (%q); run it by its full path", o.Exe)
			}
			svc, tmr := schedule.Units(o)
			dir := a.unitDir()
			if dryRun {
				say(a.out, "# %s\n%s\n# %s\n%s", filepath.Join(dir, schedule.Service), svc, filepath.Join(dir, schedule.Timer), tmr)
				return nil
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			for name, body := range map[string]string{schedule.Service: svc, schedule.Timer: tmr} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					return err
				}
			}
			for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", schedule.Timer}} {
				if r := a.systemctl(c.Context(), args...); !r.OK() {
					return fmt.Errorf("systemctl --user %s: %s", strings.Join(args, " "), packages.LastLine(r.Stderr+"\n"+r.Stdout))
				}
			}
			say(a.out, "Installed %s (%s): audit %s.\n", schedule.Timer, o.Calendar, strings.Join(o.Args(), " "))
			if o.AI {
				sayln(a.out, "Each run adds AI reviews (schedule.ai), which cost money unless the results are unchanged.")
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&dryRun, "dry-run", "N", false, "print the unit files instead of installing them")
	return c
}

func newScheduleRemoveCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Disable the timer and delete its unit files",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			dir := a.unitDir()
			if _, err := os.Stat(filepath.Join(dir, schedule.Timer)); errors.Is(err, os.ErrNotExist) {
				sayln(a.out, "Not installed.")
				return nil
			}
			if r := a.systemctl(c.Context(), "disable", "--now", schedule.Timer); !r.OK() {
				a.log.Warn("disable the timer", "err", packages.LastLine(r.Stderr))
			}
			var errs []error
			for _, name := range []string{schedule.Timer, schedule.Service} {
				if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
			if r := a.systemctl(c.Context(), "daemon-reload"); !r.OK() {
				a.log.Warn("systemctl daemon-reload", "err", packages.LastLine(r.Stderr))
			}
			if err := errors.Join(errs...); err != nil {
				return err
			}
			sayln(a.out, "Removed "+schedule.Timer+" and "+schedule.Service+".")
			return nil
		},
	}
}

// scheduleState is what audit schedule reports.
type scheduleState struct {
	Installed bool   `json:"installed"`
	Dir       string `json:"dir"`
	ExecStart string `json:"exec_start,omitempty"`
	Enabled   string `json:"enabled,omitempty"`
	Active    string `json:"active,omitempty"`
	Next      string `json:"next,omitempty"`
	Last      string `json:"last,omitempty"`
	Result    string `json:"result,omitempty"`
}

func (a *app) scheduleStatus(ctx context.Context) scheduleState {
	st := scheduleState{Dir: a.unitDir()}
	svc, err := os.ReadFile(filepath.Join(st.Dir, schedule.Service)) // #nosec G304 -- our own unit file
	if _, terr := os.Stat(filepath.Join(st.Dir, schedule.Timer)); err != nil || terr != nil {
		return st
	}
	st.Installed = true
	for _, line := range strings.Split(string(svc), "\n") {
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			st.ExecStart = v
		}
	}
	word := func(args ...string) string {
		r := a.systemctl(ctx, args...)
		return strings.TrimSpace(r.Stdout)
	}
	st.Enabled = word("is-enabled", schedule.Timer)
	st.Active = word("is-active", schedule.Timer)
	props := func(unit string, names ...string) map[string]string {
		out := map[string]string{}
		args := []string{"show", unit}
		for _, n := range names {
			args = append(args, "-p", n)
		}
		for _, line := range strings.Split(word(args...), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				out[k] = strings.TrimSpace(v)
			}
		}
		return out
	}
	tp := props(schedule.Timer, "NextElapseUSecRealtime", "LastTriggerUSec")
	st.Next, st.Last = tp["NextElapseUSecRealtime"], tp["LastTriggerUSec"]
	if st.Last == "n/a" {
		st.Last = "never"
	}
	sp := props(schedule.Service, "Result", "ExecMainStatus")
	if r := sp["Result"]; r != "" && st.Last != "never" {
		st.Result = r
		if code := sp["ExecMainStatus"]; code != "" && code != "0" {
			st.Result += " (exit " + code + ")"
		}
	}
	return st
}
