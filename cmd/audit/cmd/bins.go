package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/registry"
)

func newBinsCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "bins",
		Short: "List loose binaries and where they come from",
		Long: `List the regular executable files in packages.scan_dirs (symlinks belong to
the managers that made them): their kind (elf or script), the GitHub repo
they are tracked from, the installed release and the latest one from the
registry cache. Nothing is scanned or downloaded.

Track a binary with audit packages bins track NAME OWNER/REPO, and audit
packages update (or bins install) keeps it at the latest release.
Untracked compiled binaries are reported by the bins.untracked check.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			items, err := a.binItems(c.Context())
			if err != nil {
				return err
			}
			if asJSON {
				return a.writeJSON(items)
			}
			rows := make([][]string, len(items))
			for i, it := range items {
				latest := ""
				if it.Meta != nil {
					latest = it.Meta.Latest
				}
				rows[i] = []string{it.Name, it.Kind, it.Ident, it.Version, latest, it.Location}
			}
			a.printer().Table([]string{"NAME", "KIND", "TRACKED FROM", "VERSION", "LATEST", "PATH"}, rows)
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the binaries as JSON")
	c.AddCommand(newBinsTrackCmd(a), newBinsUntrackCmd(a), newBinsInstallCmd(a))
	return c
}

// binItems collects the loose binaries now, joined with the registry cache.
func (a *app) binItems(ctx context.Context) ([]packages.Item, error) {
	tracked, err := a.store.TrackedBins(ctx)
	if err != nil {
		return nil, err
	}
	b := packages.Bins{Dirs: a.scanDirs(), Tracked: func() (map[string]packages.TrackedBin, error) { return tracked, nil }}
	pkgs, err := b.Collect(ctx, a.env)
	if err != nil {
		return nil, err
	}
	metas, err := a.store.PackageMeta(ctx)
	if err != nil {
		return nil, err
	}
	as := packages.Annotate([]packages.Inventory{{Manager: packages.BinsManager, Available: true, Packages: pkgs}}, metas, nil, "")
	return as[0].Items, nil
}

func (a *app) scanDirs() []string {
	out := make([]string, len(a.cfg.Packages.ScanDirs))
	for i, d := range a.cfg.Packages.ScanDirs {
		out[i] = a.env.Expand(d)
	}
	return out
}

func newBinsTrackCmd(a *app) *cobra.Command {
	var installed string
	c := &cobra.Command{
		Use:   "track NAME OWNER/REPO[:ASSET-GLOB]",
		Short: "Record which GitHub repo's releases a loose binary comes from",
		Long: `Record that the loose binary NAME comes from the releases of OWNER/REPO. The
optional glob picks the release asset when the automatic choice (built for
this OS and architecture, glibc over musl, tar.gz over zip over a bare file)
is ambiguous or wrong, for example sharkdp/bat:*x86_64-unknown-linux-musl*.

The installed version is taken from --installed, or read from the first
version in the output of NAME --version (the binary is run for this). The
repo's latest release is looked up right away; audit packages update then
plans the binary like any other package.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			return a.trackBin(c.Context(), args[0], args[1], installed)
		},
	}
	c.Flags().StringVarP(&installed, "installed", "s", "", "the installed release, instead of asking NAME --version")
	return c
}

func (a *app) trackBin(ctx context.Context, name, spec, installed string) error {
	repo, asset, err := packages.ParseTrackSpec(spec)
	if err != nil {
		return err
	}
	path := a.findBin(name)
	if path == "" {
		return fmt.Errorf("no loose binary %s in %s", name, strings.Join(a.scanDirs(), ", "))
	}
	if installed == "" {
		r := a.env.Run(ctx, path, []string{"--version"}, exec.Options{Timeout: 5 * time.Second})
		installed = packages.FirstVersion(r.Stdout + "\n" + r.Stderr)
	}
	t := packages.TrackedBin{Name: name, Repo: repo, Asset: asset, Version: installed}
	if err := a.store.SaveTrackedBin(ctx, t); err != nil {
		return err
	}
	p := packages.Package{Manager: packages.BinsManager, Name: name, Ident: repo, Source: "github:" + repo, Version: installed}
	rr := a.registryRefresh(nil, true)
	looker := rr.Looker
	if looker == nil {
		looker = registry.NewClient(a.env, rr.UserAgent, rr.Options.Timeout)
	}
	m, _, lerr := looker.Lookup(ctx, p, nil, true)
	m.Manager, m.ID, m.Registry, m.Installed, m.CheckedAt = packages.BinsManager, repo, packages.RegistryGitHub, installed, timeNow()
	if lerr != nil {
		m.Error = lerr.Error()
	}
	if err := a.store.SavePackageMeta(ctx, []packages.Meta{m}); err != nil {
		return err
	}
	ver := installed
	if ver == "" {
		ver = "an unknown version"
	}
	say(a.out, "Tracking %s (%s) from %s", name, ver, repo)
	switch {
	case lerr != nil:
		say(a.out, "; looking up its releases failed: %v\n", lerr)
	case m.Latest == "":
		say(a.out, "; the repo has no releases\n")
	default:
		say(a.out, "; latest release %s.\n", m.Latest)
	}
	return nil
}

func (a *app) findBin(name string) string {
	for _, d := range a.scanDirs() {
		p := filepath.Join(d, name)
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func newBinsUntrackCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "untrack NAME",
		Short: "Forget where a loose binary comes from",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ok, err := a.store.DeleteTrackedBin(c.Context(), args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%s is not tracked", args[0])
			}
			say(a.out, "No longer tracking %s; the file is left in place.\n", args[0])
			return nil
		},
	}
}

func newBinsInstallCmd(a *app) *cobra.Command {
	var release string
	var skipChecksum, force bool
	c := &cobra.Command{
		Use:   "install NAME",
		Short: "Install a tracked binary's latest (or a given) GitHub release",
		Long: `Download the release asset of a tracked binary with gh release download,
check its sha256 against GitHub's asset digest or the release's checksum
file, unpack it (tar archives through tar, zip and gzip in process) and
replace the binary atomically. The previous file is kept under
<data_dir>/bins/. A release that publishes no checksum is refused unless
--skip-checksum is given. audit packages update runs this for tracked
binaries behind their latest release.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			return a.installBin(c.Context(), args[0], release, skipChecksum, force)
		},
	}
	fl := c.Flags()
	fl.StringVarP(&release, "release", "r", "", "install this release tag instead of the latest")
	fl.BoolVarP(&skipChecksum, "skip-checksum", "k", false, "install even when the release publishes no sha256")
	fl.BoolVarP(&force, "force", "F", false, "install even when the tracked version is already that release")
	return c
}

func (a *app) installBin(ctx context.Context, name, tag string, skipChecksum, force bool) error {
	tracked, err := a.store.TrackedBins(ctx)
	if err != nil {
		return err
	}
	t, ok := tracked[name]
	if !ok {
		return fmt.Errorf("%s is not tracked; run audit packages bins track %s OWNER/REPO first", name, name)
	}
	rel, err := packages.FetchRelease(ctx, a.env, t.Repo, tag)
	if err != nil {
		return err
	}
	dest := a.findBin(name)
	if dest == "" {
		// A link would be replaced by a file (or shadowed by a second copy)
		// while its target stays behind; which file to update is the
		// user's call.
		for _, d := range a.scanDirs() {
			p := filepath.Join(d, name)
			if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
				target, _ := os.Readlink(p)
				return fmt.Errorf("%s is a symlink to %s; audit does not replace links: remove it, or install over the file it points to yourself", p, target)
			}
		}
		dirs := a.scanDirs()
		if len(dirs) == 0 {
			return errors.New("packages.scan_dirs is empty; nowhere to install to")
		}
		dest = filepath.Join(dirs[0], name)
	}
	if t.Version == rel.Tag && !force {
		if _, err := os.Stat(dest); err == nil {
			say(a.out, "%s is already at %s.\n", name, rel.Tag)
			return nil
		}
	}
	got, err := packages.InstallRelease(ctx, a.env, packages.InstallSpec{
		Repo: t.Repo, Name: name, Release: rel, AssetGlob: t.Asset,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		Dest: dest, BackupDir: filepath.Join(a.cfg.DataDir, "bins"), OldVersion: t.Version,
		SkipChecksum: skipChecksum, Timeout: a.cfg.Packages.Update.Timeout,
	})
	if err != nil {
		return err
	}
	t.Version, t.SHA256, t.InstalledAt = rel.Tag, got.SHA256, timeNow()
	if err := a.store.SaveTrackedBin(ctx, t); err != nil {
		return err
	}
	verified := "sha256 checked"
	if !got.Verified {
		verified = "no checksum published"
	}
	say(a.out, "Installed %s %s from %s (%s) at %s.\n", name, rel.Tag, got.Asset, verified, dest)
	if w := a.env.Which(name); w != "" && w != dest {
		say(a.out, "Note: %s runs %s first on PATH, not the one installed.\n", name, w)
	}
	return nil
}
