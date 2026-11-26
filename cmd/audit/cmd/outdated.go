package cmd

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newPackagesOutdatedCmd(a *app) *cobra.Command {
	var managers []string
	var force, system bool
	q := packages.Query{Outdated: true}
	f := &scanFlags{}
	c := &cobra.Command{
		Use:   "outdated",
		Short: "Check for updates and list outdated packages with installed and latest versions",
		Long: `Scan installed packages, refresh registry data subject to the configured
cache age, and list only packages behind their latest release. --force
ignores the registry cache age. System managers use their cached package
lists; this command does not refresh apt lists or install anything.

--list, --report, --summary and --json use saved results unless --rescan
or --force is given. Use audit packages update --dry-run to preview updates,
audit packages update to apply them after confirmation, or name individual
packages (manager:name when ambiguous). Printed update hints select only the
displayed packages and preserve --manager. Major releases need --major.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if !f.report && !f.summary && !f.list && !f.json {
				f.list, f.rescan = true, true
			}
			if force {
				f.rescan = true
			}
			if len(splitList(managers)) == 0 && !a.systemFlag(c, system) && f.rescan {
				if err := a.askSystem(f.json); err != nil {
					return err
				}
			}
			s, err := a.packagesScanner(splitList(managers))
			if err != nil {
				return err
			}
			s.Refresh = a.registryRefresh(nil, force)
			f.jsonExtra = func(ctx context.Context, r *run.Run) (any, error) { return a.annotated(ctx, r, q) }
			f.viewOnly, f.listHint = true, "audit packages -l"
			return a.runScan(c.Context(), s, f, func(ctx context.Context, p *render.Printer, r *run.Run) error {
				as, err := a.annotated(ctx, r, q)
				if err != nil {
					return fmt.Errorf("load outdated packages: %w", err)
				}
				all, err := a.annotated(ctx, r, packages.Query{Find: q.Find})
				if err != nil {
					return fmt.Errorf("load packages: %w", err)
				}
				cov := packages.CoverageOf(all)
				if len(as) == 0 {
					if cov.Unchecked+cov.Failed > 0 {
						say(a.out, "No outdated packages among the %d checked; the rest are not known to be current.\n", cov.Known)
					} else {
						sayln(a.out, "No outdated packages.")
					}
				} else {
					p.Packages(as)
					args := outdatedUpdateArgs(as, splitList(managers))
					sayln(a.out, "Preview updates: "+outdatedUpdateHint(append([]string{"--dry-run"}, args...))+"\nUpdate: "+outdatedUpdateHint(args)+" (add --major before -- for major releases)")
				}
				sayln(a.out, coverageLine(cov, timeNow()))
				if slices.ContainsFunc(all, func(x packages.Annotated) bool { return x.Manager == "apt" && x.Available }) {
					if age, stale, ok := packages.AptListsAge(timeNow()); ok && stale {
						say(a.out, "apt's package lists are %s old, so its updates may be missing; --force does not refresh them, `audit packages update -M apt` does (with sudo).\n", packages.Age(age))
					}
				}
				a.printSystemNote(r)
				return nil
			})
		},
	}
	f.register(c)
	c.Flags().StringSliceVarP(&managers, "manager", "M", nil, "check only these managers: "+strings.Join(packages.Names(), ", "))
	c.Flags().BoolVarP(&system, "system", "S", false, "include apt, snap and flatpak (--system=false leaves them out; default packages.system_managers)")
	c.Flags().BoolVarP(&force, "force", "F", false, "rescan and refresh registry versions regardless of cache age")
	c.Flags().StringVarP(&q.Find, "find", "f", "", "filter by package name, description or executable")
	return c
}

// coverageLine says how many packages the outdated view could place and
// how old the registry data is, with the command that looks up the rest.
func coverageLine(c packages.Coverage, now time.Time) string {
	line := fmt.Sprintf("Checked %d of %d packages", c.Known, c.Packages)
	if !c.OldestCheck.IsZero() {
		line += fmt.Sprintf("; registry data up to %s old", packages.Age(now.Sub(c.OldestCheck)))
	}
	var gaps []string
	if c.Unchecked > 0 {
		gaps = append(gaps, fmt.Sprintf("%d never looked up", c.Unchecked))
	}
	if c.Failed > 0 {
		gaps = append(gaps, fmt.Sprintf("%d failed lookups", c.Failed))
	}
	if c.Unknown > 0 {
		gaps = append(gaps, fmt.Sprintf("%d without comparable versions", c.Unknown))
	}
	if len(gaps) > 0 {
		line += " (" + strings.Join(gaps, ", ") + ")"
	}
	line += "."
	if c.Unchecked+c.Failed > 0 {
		line += " `audit packages outdated -F` looks them up again."
	}
	return line
}

// outdatedUpdateArgs selects the displayed items by name: registry IDs can
// cover multiple Go binaries, including binaries outside a text-filtered view.
func outdatedUpdateArgs(as []packages.Annotated, managers []string) []string {
	var args []string
	if len(managers) > 0 {
		args = append(args, "--manager", strings.Join(managers, ","))
	}
	args = append(args, "--")
	seen := map[string]bool{}
	for _, inv := range as {
		for _, item := range inv.Items {
			ref := item.Manager + ":" + item.Name
			if !seen[ref] {
				args = append(args, ref)
				seen[ref] = true
			}
		}
	}
	return args
}

var safeUpdateHintWord = regexp.MustCompile(`^[a-zA-Z0-9_@%+=:,./-]+$`)

func outdatedUpdateHint(args []string) string {
	words := []string{"audit", "packages", "update"}
	for _, arg := range args {
		if !safeUpdateHintWord.MatchString(arg) {
			arg = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
		}
		words = append(words, arg)
	}
	return strings.Join(words, " ")
}
