package packages

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

// BinsManager is the manager name of loose binaries.
const BinsManager = "bins"

// SelfCommand is how update plans invoke audit itself (to install tracked
// binaries); the CLI sets it to its own executable.
var SelfCommand = "audit"

// TrackedBin is a loose binary whose origin the user registered.
type TrackedBin struct {
	Name string `json:"name"`
	// Repo is the GitHub owner/repo whose releases provide it.
	Repo string `json:"repo"`
	// Asset is a glob picking the release asset; "" picks by OS and arch.
	Asset string `json:"asset,omitempty"`
	// Version is the release tag audit installed (or the user recorded).
	Version     string    `json:"version,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	InstalledAt time.Time `json:"installed_at,omitzero"`
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ParseTrackSpec reads "owner/repo" or "owner/repo:asset-glob".
func ParseTrackSpec(spec string) (repo, asset string, err error) {
	spec = strings.TrimPrefix(strings.TrimSpace(spec), "https://github.com/")
	repo, asset, _ = strings.Cut(spec, ":")
	repo = strings.TrimSuffix(repo, ".git")
	if !repoRe.MatchString(repo) {
		return "", "", fmt.Errorf("%q is not a GitHub owner/repo", repo)
	}
	if asset != "" {
		if _, err := path.Match(asset, ""); err != nil {
			return "", "", fmt.Errorf("bad asset glob %q: %w", asset, err)
		}
	}
	return repo, asset, nil
}

// Bins inventories the regular executable files in Dirs (packages.scan_dirs);
// symlinks belong to the managers that made them. Tracked binaries carry
// their GitHub repo, so the registry refresh looks their releases up.
type Bins struct {
	Dirs []string
	// Tracked loads the tracked binaries when Collect runs, so a rescan
	// after an install sees the new version; nil tracks nothing.
	Tracked func() (map[string]TrackedBin, error)
}

// Name implements Manager.
func (Bins) Name() string { return BinsManager }

// Binary implements Manager; there is no binary, so Collect decides.
func (Bins) Binary() string { return "" }

// Runtime implements Manager.
func (Bins) Runtime(context.Context, *exec.Env) *Runtime { return nil }

// ManagerVersion implements Manager.
func (Bins) ManagerVersion(context.Context, *exec.Env) string { return "" }

// BinDirs implements Manager. Loose files do not make a directory managed,
// so the shadowing checks keep treating them as unmanaged.
func (Bins) BinDirs(context.Context, *exec.Env) []string { return nil }

// Collect implements Manager.
func (b Bins) Collect(_ context.Context, _ *exec.Env) ([]Package, error) {
	tracked := map[string]TrackedBin{}
	if b.Tracked != nil {
		var err error
		if tracked, err = b.Tracked(); err != nil {
			return nil, fmt.Errorf("load tracked binaries: %w", err)
		}
	}
	var out []Package
	seen := map[string]bool{}
	for _, dir := range b.Dirs {
		es, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range es {
			p := filepath.Join(dir, e.Name())
			if e.Type()&os.ModeSymlink != 0 || seen[e.Name()] || !exec.IsExecutable(p) {
				continue
			}
			seen[e.Name()] = true
			pkg := Package{Manager: BinsManager, Name: e.Name(), Location: p, Executables: []string{e.Name()},
				Kind: binKind(p)}
			if t, ok := tracked[e.Name()]; ok {
				pkg.Ident, pkg.Source, pkg.Version = t.Repo, "github:"+t.Repo, t.Version
			}
			out = append(out, pkg)
		}
	}
	return out, nil
}

// binKind is "elf" for a compiled binary and "script" otherwise.
func binKind(p string) string {
	if strings.HasPrefix(readHead(p, 4), "\x7fELF") {
		return "elf"
	}
	return "script"
}

// ReleaseAsset is one file of a GitHub release.
type ReleaseAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	URL    string `json:"browser_download_url"`
}

// Release is a GitHub release with its assets.
type Release struct {
	Tag    string         `json:"tag_name"`
	Assets []ReleaseAsset `json:"assets"`
}

var (
	// notBinary are assets that are never the program: packages for other
	// installers, checksums, signatures, metadata.
	notBinary = regexp.MustCompile(`(?i)(\.(deb|rpm|apk|pkg|msi|exe|dmg|sha256|sha512|sha256sum|md5|sig|asc|pem|sbom|spdx|json|txt|yml|yaml)$|checksums|sha256sums|\.intoto)`)
	archAlias = map[string][]string{
		"amd64": {"amd64", "x86_64", "x64", "64bit", "linux64"},
		"arm64": {"arm64", "aarch64"},
		"386":   {"386", "i386", "i686", "x86"},
	}
)

// SelectAsset picks the asset for name: the glob when one was given,
// otherwise the one built for goos and goarch, preferring glibc builds over
// musl and archives in the order tar.gz, zip, then a bare binary. An
// ambiguous or empty choice is an error naming the candidates.
func SelectAsset(assets []ReleaseAsset, glob, goos, goarch string) (ReleaseAsset, error) {
	var cands []ReleaseAsset
	if glob != "" {
		for _, a := range assets {
			if ok, _ := path.Match(glob, a.Name); ok {
				cands = append(cands, a)
			}
		}
		if len(cands) == 1 {
			return cands[0], nil
		}
		return ReleaseAsset{}, assetErr(glob, cands, assets)
	}
	aliases := archAlias[goarch]
	if len(aliases) == 0 {
		aliases = []string{goarch}
	}
	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if notBinary.MatchString(n) || !strings.Contains(n, goos) {
			continue
		}
		for _, al := range aliases {
			if strings.Contains(n, al) {
				cands = append(cands, a)
				break
			}
		}
	}
	if len(cands) > 1 {
		cands = preferred(cands)
	}
	if len(cands) == 1 {
		return cands[0], nil
	}
	return ReleaseAsset{}, assetErr(goos+"/"+goarch, cands, assets)
}

// preferred narrows candidates: glibc over musl, then the best archive kind.
func preferred(cands []ReleaseAsset) []ReleaseAsset {
	var nonMusl []ReleaseAsset
	for _, a := range cands {
		if !strings.Contains(strings.ToLower(a.Name), "musl") {
			nonMusl = append(nonMusl, a)
		}
	}
	if len(nonMusl) > 0 {
		cands = nonMusl
	}
	rank := func(n string) int {
		n = strings.ToLower(n)
		switch {
		case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"):
			return 0
		case strings.HasSuffix(n, ".tar.xz"), strings.HasSuffix(n, ".tar.bz2"), strings.HasSuffix(n, ".tar.zst"):
			return 1
		case strings.HasSuffix(n, ".zip"):
			return 2
		case strings.HasSuffix(n, ".gz"):
			return 3
		}
		return 4
	}
	best := 5
	for _, a := range cands {
		best = min(best, rank(a.Name))
	}
	var out []ReleaseAsset
	for _, a := range cands {
		if rank(a.Name) == best {
			out = append(out, a)
		}
	}
	return out
}

func assetErr(what string, cands, all []ReleaseAsset) error {
	list := func(as []ReleaseAsset) string {
		names := make([]string, len(as))
		for i, a := range as {
			names[i] = a.Name
		}
		return strings.Join(names, ", ")
	}
	if len(cands) == 0 {
		return fmt.Errorf("no release asset matches %s; assets: %s; track it as owner/repo:GLOB", what, list(all))
	}
	return fmt.Errorf("%d release assets match %s (%s); track it as owner/repo:GLOB to pick one", len(cands), what, list(cands))
}

// AssetSHA256 finds the expected sha256 of asset: GitHub's digest, or a line
// of a checksum file among the assets (fetched with fetch). ok is false
// when the release publishes none.
func AssetSHA256(asset ReleaseAsset, assets []ReleaseAsset, fetch func(ReleaseAsset) (string, error)) (sum string, ok bool, err error) {
	if d, found := strings.CutPrefix(asset.Digest, "sha256:"); found && len(d) == 64 {
		return strings.ToLower(d), true, nil
	}
	for _, a := range assets {
		n := strings.ToLower(a.Name)
		if !strings.Contains(n, "checksums") && !strings.Contains(n, "sha256sums") && n != strings.ToLower(asset.Name)+".sha256" {
			continue
		}
		text, err := fetch(a)
		if err != nil {
			return "", false, fmt.Errorf("read %s: %w", a.Name, err)
		}
		if s := checksumLine(text, asset.Name); s != "" {
			return s, true, nil
		}
	}
	return "", false, nil
}

// checksumLine finds name's sum in sha256sum output ("SUM  name" or
// "SUM *name"), or a bare sum when the file holds only one.
func checksumLine(text, name string) string {
	sc := bufio.NewScanner(strings.NewReader(text))
	var only []string
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || len(f[0]) != 64 {
			continue
		}
		only = append(only, f[0])
		if len(f) >= 2 && strings.TrimPrefix(f[len(f)-1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	if len(only) == 1 {
		return strings.ToLower(only[0])
	}
	return ""
}

// ErrNoChecksum means a release publishes no sha256 for its asset.
var ErrNoChecksum = errors.New("the release publishes no sha256 for this asset")

func binsUntracked(s *State) []finding.Finding {
	inv := s.inv(BinsManager)
	if inv == nil {
		return nil
	}
	var out []finding.Finding
	for _, p := range inv.Packages {
		if p.Ident != "" || p.Kind != "elf" {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: p.Location,
			Message: p.Name + " is a loose binary with no recorded origin, so nothing keeps it up to date",
			Hint:    "`audit packages bins track " + p.Name + " OWNER/REPO` if it comes from GitHub releases; otherwise ignore it.",
			Group: &finding.Group{ID: "untracked", Title: "Record where the loose binaries come from",
				Hint: "audit packages bins track NAME OWNER/REPO[:ASSET-GLOB], or ignore packages:bins.untracked"},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}
