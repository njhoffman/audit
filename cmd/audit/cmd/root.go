// Package cmd wires the audit command line.
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/version"
)

// timeNow is the clock; tests replace it.
var timeNow = time.Now

// Execute runs the root command and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if exe, err := os.Executable(); err == nil {
		packages.SelfCommand = exe
	}
	a := newApp(os.Stdout, os.Stderr)
	root := newRootCmd(a)
	err := root.ExecuteContext(ctx)
	a.close()
	if err != nil {
		sayln(os.Stderr, "audit: "+err.Error())
		return 1
	}
	return 0
}

func newRootCmd(a *app) *cobra.Command {
	var summary, html, open, useFzf bool
	root := &cobra.Command{
		Use:   "audit",
		Short: "Audit system health, shell environment and installed packages",
		Long: `audit scans this machine and keeps the results: system health (processes,
services, accounts, logs, program configs), the shell environment and its
startup scripts, and user-level packages. Every issue and suggestion becomes
a prioritized task you can track with "audit todo".

Scans are saved. Viewing a command again shows the saved results while they
are fresh and says how old they are; --rescan scans again.

Run without a command in a terminal for the interactive dashboard, or with
--summary for the same overview as text.`,
		Version:       version.String(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			a.close()
		},
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			if html || open {
				path, err := a.writeAllReports(ctx)
				if err != nil {
					return err
				}
				if open {
					if err := a.opener(path); err != nil {
						return err
					}
				}
				sayln(a.errOut, "report: "+path)
				if !summary {
					return nil
				}
			}
			if !summary && a.interactive() {
				if a.useFzf(c) {
					return runFzfDashboard(ctx, a)
				}
				return runDashboard(ctx, a)
			}
			st, err := a.statuses(ctx)
			if err != nil {
				return err
			}
			a.printer().Summary(st)
			return nil
		},
	}
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetVersionTemplate("audit {{.Version}}\n")

	pf := root.PersistentFlags()
	pf.StringVarP(&a.flags.config, "config", "c", "", "config file (default $XDG_CONFIG_HOME/audit.yaml)")
	pf.BoolVarP(&a.flags.noColor, "no-color", "n", false, "disable colors (also NO_COLOR or a redirected stdout)")
	pf.IntVarP(&a.flags.width, "width", "W", 0, "wrap output at this many columns (default terminal width)")
	pf.BoolVarP(&a.flags.verbose, "verbose", "v", false, "show more detail and info logs")
	pf.BoolVarP(&a.flags.debug, "debug", "D", false, "show debug logs")
	pf.BoolVarP(&a.flags.quiet, "quiet", "q", false, "only errors; no progress bars or notices")
	pf.StringVarP(&a.flags.aiProvider, "ai-provider", "I", "", "AI CLI for this run: claude or codex (default ai.provider)")
	root.MarkFlagsMutuallyExclusive("verbose", "quiet")
	root.MarkFlagsMutuallyExclusive("debug", "quiet")
	root.Flags().BoolP("version", "V", false, "print the version")

	fl := root.Flags()
	fl.BoolVarP(&summary, "summary", "s", false, "print the overview of saved results and open tasks")
	fl.BoolVarP(&html, "html", "H", false, "write the HTML index and every command's latest report")
	fl.BoolVarP(&open, "open", "o", false, "like --html, then open the index")
	fl.BoolVarP(&useFzf, "fzf", "F", false, "open the dashboard in fzf (default tui.interface; --fzf=false for the TUI)")

	root.AddCommand(newSystemCmd(a), newEnvironmentCmd(a), newPackagesCmd(a), newReposCmd(a), newFilesCmd(a), newConfigsCmd(a), newScriptsCmd(a), newAICmd(a),
		newTodoCmd(a), newHistoryCmd(a), newConfigCmd(a), newExportCmd(a), newAnalyzeCmd(a),
		newFzfHelperCmd(a))
	return root
}

// writeAllReports rewrites the HTML report of every command's latest run,
// the tasks page and the index, returning the index path.
func (a *app) writeAllReports(ctx context.Context) (string, error) {
	for _, c := range core.Commands {
		r, err := a.engine.Saved(ctx, c, "")
		if err != nil {
			return "", err
		}
		if r == nil {
			continue
		}
		if _, err := a.writeReport(ctx, r); err != nil {
			return "", err
		}
	}
	if _, err := a.writeTasksPage(ctx); err != nil {
		return "", err
	}
	return a.writeIndex(ctx)
}
