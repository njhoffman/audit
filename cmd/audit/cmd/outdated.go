package cmd

import (
	"context"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newPackagesOutdatedCmd(a *app) *cobra.Command {
	var managers []string
	var force bool
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
			s, err := a.packagesScanner(splitList(managers))
			if err != nil {
				return err
			}
			s.Refresh = a.registryRefresh(nil, force)
			if !f.report && !f.summary && !f.list && !f.json {
				f.list, f.rescan = true, true
			}
			if force {
				f.rescan = true
			}
			f.jsonExtra = func(ctx context.Context, r *run.Run) (any, error) { return a.annotated(ctx, r, q) }
			return a.runScan(c.Context(), s, f, func(ctx context.Context, p *render.Printer, r *run.Run) {
				as, err := a.annotated(ctx, r, q)
				if err != nil {
					a.log.Warn("load outdated packages", "err", err)
					return
				}
				if len(as) == 0 {
					sayln(a.out, "No known outdated packages. Use --force to recheck registry versions.")
					return
				}
				p.Packages(as)
				args := outdatedUpdateArgs(as, splitList(managers))
				sayln(a.out, "Preview updates: "+outdatedUpdateHint(append([]string{"--dry-run"}, args...))+"\nUpdate: "+outdatedUpdateHint(args)+" (add --major before -- for major releases)")
			})
		},
	}
	f.register(c)
	c.Flags().StringSliceVarP(&managers, "manager", "M", nil, "check only these managers: "+strings.Join(packages.Names(), ", "))
	c.Flags().BoolVarP(&force, "force", "F", false, "rescan and refresh registry versions regardless of cache age")
	c.Flags().StringVarP(&q.Find, "find", "f", "", "filter by package name, description or executable")
	return c
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
