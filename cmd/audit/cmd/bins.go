package cmd

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// maxBinary bounds what an archive member may unpack to.
const maxBinary = 1 << 30

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
	rel, err := a.ghRelease(ctx, t.Repo, tag)
	if err != nil {
		return err
	}
	dest := a.findBin(name)
	if dest == "" {
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
	asset, err := packages.SelectAsset(rel.Assets, t.Asset, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "audit-bin-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	file, err := a.ghDownload(ctx, t.Repo, rel.Tag, asset.Name, tmp)
	if err != nil {
		return err
	}
	want, ok, err := packages.AssetSHA256(asset, rel.Assets, func(ra packages.ReleaseAsset) (string, error) {
		p, err := a.ghDownload(ctx, t.Repo, rel.Tag, ra.Name, filepath.Join(tmp, "sums"))
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- our temp download
		return string(b), err
	})
	if err != nil {
		return err
	}
	got, err := fileSHA256(file)
	if err != nil {
		return err
	}
	switch {
	case !ok && !skipChecksum:
		return fmt.Errorf("%w (%s %s); pass --skip-checksum to install it anyway", packages.ErrNoChecksum, t.Repo, asset.Name)
	case ok && got != want:
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset.Name, got, want)
	}
	bin, err := a.unpack(ctx, file, name, filepath.Join(tmp, "x"))
	if err != nil {
		return err
	}
	if err := a.replaceBin(dest, bin, name, t.Version); err != nil {
		return err
	}
	t.Version, t.SHA256, t.InstalledAt = rel.Tag, got, timeNow()
	if err := a.store.SaveTrackedBin(ctx, t); err != nil {
		return err
	}
	verified := "sha256 checked"
	if !ok {
		verified = "no checksum published"
	}
	say(a.out, "Installed %s %s from %s (%s) at %s.\n", name, rel.Tag, asset.Name, verified, dest)
	return nil
}

func (a *app) ghRelease(ctx context.Context, repo, tag string) (packages.Release, error) {
	path := "repos/" + repo + "/releases/latest"
	if tag != "" {
		path = "repos/" + repo + "/releases/tags/" + tag
	}
	r := a.env.Run(ctx, "gh", []string{"api", path}, exec.Options{Timeout: time.Minute})
	var rel packages.Release
	if !r.OK() {
		return rel, fmt.Errorf("gh api %s: %s", path, packages.LastLine(r.Stderr+"\n"+r.Stdout))
	}
	if err := json.Unmarshal([]byte(r.Stdout), &rel); err != nil {
		return rel, fmt.Errorf("unexpected answer from gh api %s: %w", path, err)
	}
	return rel, nil
}

func (a *app) ghDownload(ctx context.Context, repo, tag, asset, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(dir, filepath.Base(asset))
	r := a.env.Run(ctx, "gh", []string{"release", "download", tag, "-R", repo, "-p", asset, "-O", out, "--clobber"},
		exec.Options{Timeout: a.cfg.Packages.Update.Timeout})
	if !r.OK() {
		return "", fmt.Errorf("gh release download %s %s: %s", repo, asset, packages.LastLine(r.Stderr+"\n"+r.Stdout))
	}
	if _, err := os.Stat(out); err != nil {
		return "", fmt.Errorf("gh release download left no %s", asset)
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- our temp download
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unpack extracts file into dir and returns the binary called name in it,
// or the only executable file; a bare asset is the binary itself.
func (a *app) unpack(ctx context.Context, file, name, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	lower := strings.ToLower(file)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		if err := unzip(file, dir); err != nil {
			return "", err
		}
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar.bz2"),
		strings.HasSuffix(lower, ".tar"):
		if err := untar(file, dir); err != nil {
			return "", fmt.Errorf("unpack %s: %w", filepath.Base(file), err)
		}
	case strings.Contains(lower, ".tar."):
		// xz and zstd have no decoder in the standard library.
		r := a.env.Run(ctx, "tar", []string{"-xf", file, "-C", dir, "--no-same-owner"}, exec.Options{Timeout: 5 * time.Minute})
		if !r.OK() {
			return "", fmt.Errorf("tar -xf %s: %s", filepath.Base(file), packages.LastLine(r.Stderr))
		}
	case strings.HasSuffix(lower, ".gz"):
		out := filepath.Join(dir, name)
		if err := gunzip(file, out); err != nil {
			return "", err
		}
		return out, nil
	default:
		return file, nil
	}
	var exact, execs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		if d.Name() == name {
			exact = append(exact, p)
		}
		if st, err := d.Info(); err == nil && st.Mode().Perm()&0o111 != 0 {
			execs = append(execs, p)
		}
		return nil
	})
	switch {
	case err != nil:
		return "", err
	case len(exact) == 1:
		return exact[0], nil
	case len(exact) == 0 && len(execs) == 1:
		return execs[0], nil
	}
	return "", fmt.Errorf("the archive holds no single %s (found %d by name, %d executables)", name, len(exact), len(execs))
}

// untar extracts the regular files of a plain, gzip or bzip2 tar archive,
// keeping every path inside dir.
func untar(file, dir string) error {
	f, err := os.Open(file) // #nosec G304 -- our temp download
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	switch lower := strings.ToLower(file); {
	case strings.HasSuffix(lower, ".bz2"):
		r = bzip2.NewReader(f)
	case strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tgz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		p := filepath.Join(dir, filepath.Clean("/"+h.Name)) // #nosec G305 -- cleaned against a rooted path
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode).Perm()|0o600) // #nosec G115 G304 -- inside our temp dir
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(tr, maxBinary))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}

func unzip(file, dir string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		p := filepath.Join(dir, filepath.Clean("/"+f.Name)) // #nosec G305 -- cleaned against a rooted path
		if f.FileInfo().IsDir() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o600) // #nosec G304 -- inside our temp dir
		if err == nil {
			_, err = io.Copy(out, io.LimitReader(rc, maxBinary))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func gunzip(file, out string) error {
	in, err := os.Open(file) // #nosec G304 -- our temp download
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700) // #nosec G302 G304 -- an executable in our temp dir
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.LimitReader(zr, maxBinary))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// replaceBin installs src at dest through a temporary file in dest's
// directory, so the swap is a rename, after copying the old file to
// <data_dir>/bins/NAME-VERSION.
func (a *app) replaceBin(dest, src, name, oldVersion string) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		if oldVersion == "" {
			oldVersion = "previous"
		}
		backup := filepath.Join(a.cfg.DataDir, "bins", name+"-"+oldVersion)
		if err := copyFile(dest, backup, 0o700); err != nil {
			return fmt.Errorf("back up %s: %w", dest, err)
		}
	}
	tmp := filepath.Join(dir, "."+name+".audit-new")
	if err := copyFile(src, tmp, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- paths audit chose
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G302 G304 -- installing an executable
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
