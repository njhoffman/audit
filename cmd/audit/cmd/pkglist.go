package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/render"
)

// listFlags select the packages audit packages list and update --pick show.
type listFlags struct {
	managers []string
	gaps     []string
	outdated bool
	find     string
	tags     []string
}

func (f listFlags) query() (packages.Query, error) {
	gaps, err := packages.ParseGaps(splitList(f.gaps))
	if err != nil {
		return packages.Query{}, err
	}
	managers := splitList(f.managers)
	for _, m := range managers {
		if _, err := packages.Resolve([]string{m}); err != nil {
			return packages.Query{}, err
		}
	}
	return packages.Query{Managers: managers, Gaps: gaps, Outdated: f.outdated || len(gaps) > 0, Find: f.find, Tags: f.tags}, nil
}

// listItems are the packages of the saved full run that pass q, sorted by
// manager and name.
func (a *app) listItems(ctx context.Context, q packages.Query) ([]packages.Item, error) {
	r, err := a.engine.Saved(ctx, packages.Command, "")
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w for audit packages; run `audit packages -r` (or audit packages list -r) first", core.ErrNoSavedRun)
	}
	as, err := a.annotated(ctx, r, q)
	if err != nil {
		return nil, err
	}
	var items []packages.Item
	for _, an := range as {
		items = append(items, an.Items...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Manager != items[j].Manager {
			return items[i].Manager < items[j].Manager
		}
		return items[i].Name < items[j].Name
	})
	return items, nil
}

func newPackagesListCmd(a *app) *cobra.Command {
	var f listFlags
	var tsv, asJSON, rescan bool
	c := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List installed packages across managers, with their updates by level",
		Long: `List every package of the last full audit packages run in one aligned
table: manager, name, installed version and, for packages behind, the
latest one with how far behind (major red, minor yellow, patch cyan, a
system manager's update amber) and how long ago it was released.

--manager and --gap filter the list (--gap implies --outdated); --tsv prints
tab-separated lines for fzf, fzx and scripts: ref (manager:name), manager,
name, version, latest, gap, then the colored row. --rescan scans first.
audit packages update --pick picks from the same list in fzf.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			q, err := f.query()
			if err != nil {
				return err
			}
			ctx := c.Context()
			if rescan {
				if err := a.askSystem(asJSON || tsv); err != nil {
					return err
				}
				if _, err := a.scanOne(ctx, packages.Command, a.progress(!asJSON && !tsv), false); err != nil {
					return err
				}
			}
			items, err := a.listItems(ctx, q)
			if err != nil {
				return err
			}
			switch {
			case asJSON:
				if items == nil {
					items = []packages.Item{}
				}
				return a.writeJSON(items)
			case tsv:
				return writeLines(a.out, a.packageLines(items))
			}
			a.printer().PackageList(items)
			return nil
		},
	}
	f.register(c, "list")
	fl := c.Flags()
	fl.BoolVarP(&tsv, "tsv", "T", false, "print tab-separated lines: ref, manager, name, version, latest, gap, colored row")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the packages as JSON")
	fl.BoolVarP(&rescan, "rescan", "r", false, "scan the packages first")
	c.MarkFlagsMutuallyExclusive("tsv", "json")
	return c
}

// register adds the filter flags; verb says what the list is for.
func (f *listFlags) register(c *cobra.Command, verb string) {
	fl := c.Flags()
	fl.StringSliceVarP(&f.managers, "manager", "M", nil, verb+" only these managers' packages: "+strings.Join(packages.Names(), ", "))
	fl.StringSliceVarP(&f.gaps, "gap", "g", nil, verb+" only packages this far behind: patch, minor, major, update or all (implies --outdated)")
	if verb == "list" {
		fl.BoolVarP(&f.outdated, "outdated", "u", false, "list only packages behind their latest release")
		fl.StringVarP(&f.find, "find", "f", "", "list only packages whose name, description or executables contain this text")
		fl.StringSliceVarP(&f.tags, "tag", "t", nil, "list only packages with all of these tags")
	}
}

// packageLines are items as tab-separated lines, the last field the row as
// the list prints it (colored, columns aligned across the lines).
func (a *app) packageLines(items []packages.Item) []string {
	// Colored even through a pipe (fzf and fzx read these with --ansi),
	// unless colors are off by flag, NO_COLOR or no_color.
	var buf bytes.Buffer
	profile := termenv.ANSI256
	if a.flags.noColor || os.Getenv("NO_COLOR") != "" || (a.cfg != nil && a.cfg.NoColor) {
		profile = termenv.Ascii
	}
	p := render.NewProfile(&buf, profile, 0)
	p.Now = timeNow
	p.PackageList(items)
	rows := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	out := make([]string, 0, len(items))
	for i, it := range items {
		row := ""
		if i+1 < len(rows) {
			row = rows[i+1] // after the header
		}
		latest, _ := packages.LatestCells(it, timeNow())
		out = append(out, strings.Join([]string{it.Manager + ":" + it.Name, it.Manager, it.Name, it.VersionKey(),
			ansi.Strip(latest), string(it.Gap), row}, "\t"))
	}
	return out
}

// pickPackages lets the user choose among items in fzf (tab marks
// several) and returns the chosen refs; none when fzf is left with esc.
func (a *app) pickPackages(ctx context.Context, items []packages.Item) ([]packages.Ref, error) {
	if len(items) == 0 {
		return nil, errors.New("no package matches; audit packages list -u shows what is behind")
	}
	bin, err := osexec.LookPath("fzf")
	if err != nil {
		return nil, errors.New("--pick needs fzf on PATH")
	}
	lines := a.packageLines(items)
	header := "tab marks several, enter updates the marked (or the current) ones, esc cancels"
	args := []string{"--multi", "--ansi", "--no-sort", "--delimiter", "\t", "--with-nth", "7", "--header", header,
		"--bind", "ctrl-f:page-down,ctrl-b:page-up,ctrl-a:select-all",
		"--preview", fmt.Sprintf("%q packages info {1}", packages.SelfCommand), "--preview-window", "down,40%,wrap"}
	cmd := osexec.CommandContext(ctx, bin, args...) // #nosec G204 -- fzf from PATH with fixed arguments
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var ee *osexec.ExitError
		if errors.As(err, &ee) && (ee.ExitCode() == 1 || ee.ExitCode() == 130) {
			return nil, nil // nothing chosen, or esc
		}
		return nil, fmt.Errorf("fzf: %w", err)
	}
	var refs []packages.Ref
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if ref, _, ok := strings.Cut(line, "\t"); ok && ref != "" {
			refs = append(refs, packages.ParseRef(ref))
		}
	}
	return refs, nil
}
