package files

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

// KindClean marks cleanup results in the saved update history.
const KindClean = "clean"

// Cleanup categories.
const (
	CatCache      = "cache"
	CatBuild      = "build"
	CatCores      = "cores"
	CatOrphaned   = "orphaned"
	CatDownloads  = "downloads"
	CatDuplicates = "duplicates"
	CatTrash      = "trash"
)

// Categories lists every cleanup category; DefaultCategories are the ones
// planned without --categories: regenerable or junk, never the user's own
// data.
var (
	Categories        = []string{CatCache, CatBuild, CatCores, CatOrphaned, CatDownloads, CatDuplicates, CatTrash}
	DefaultCategories = []string{CatCache, CatBuild, CatCores}
)

// CleanOptions select what PlanClean covers.
type CleanOptions struct {
	Categories []string
	// Paths limit the plan to these targets (or anything below them).
	Paths []string
	Home  string
	// Roots are the scanned roots; deletions must stay inside them.
	Roots []string
	// CacheMinMB skips small caches, as the scan does.
	CacheMinMB int64
}

func (o CleanOptions) wants(cat string) bool { return slices.Contains(o.Categories, cat) }

// Safe reports whether p may be deleted or trashed: it exists, lies inside a
// root once symlinks in its parent directories are resolved, and is neither
// a root nor home itself. The target itself is not followed: removing a
// symlink removes the link.
func (o CleanOptions) Safe(p string) bool {
	p = filepath.Clean(p)
	if p == "/" || p == filepath.Clean(o.Home) {
		return false
	}
	if _, err := os.Lstat(p); err != nil {
		return false
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return false
	}
	real := filepath.Join(parent, filepath.Base(p))
	if home, err := filepath.EvalSymlinks(o.Home); err == nil && real == home {
		return false
	}
	for _, r := range o.Roots {
		r = filepath.Clean(r)
		if rr, err := filepath.EvalSymlinks(r); err == nil {
			r = rr
		}
		if real != r && strings.HasPrefix(real, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// changedSince reports why the directory at p no longer looks like the scan
// saw it, "" when it does: a build directory whose mtime moved has had
// entries added or removed (a new install or build) and is in use again.
func changedSince(p string, scanned time.Time) string {
	if scanned.IsZero() {
		return ""
	}
	info, err := os.Lstat(p)
	if err != nil {
		return ""
	}
	if info.ModTime().After(scanned) {
		return "changed since the scan (in use again); rescan to include it"
	}
	return ""
}

// dupMismatch reports why target is no longer a copy of keep with the
// scanned size, "" when it still is. Both are hashed, so a kept copy that
// was edited or removed since the scan never leaves the others trashed.
func dupMismatch(keep, target string, size int64) string {
	sum := func(p string) ([sha256.Size]byte, string) {
		var zero [sha256.Size]byte
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() {
			return zero, "gone or no longer a regular file"
		}
		if info.Size() != size {
			return zero, "size changed since the scan"
		}
		f, err := os.Open(p) // #nosec G304 -- a path from the user's own files scan
		if err != nil {
			return zero, "unreadable: " + err.Error()
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return zero, "unreadable: " + err.Error()
		}
		var out [sha256.Size]byte
		copy(out[:], h.Sum(nil))
		return out, ""
	}
	k, why := sum(keep)
	if why != "" {
		return "the kept copy " + keep + " is " + why
	}
	t, why := sum(target)
	if why != "" {
		return why
	}
	if k != t {
		return "no longer identical to " + keep
	}
	return ""
}

func (o CleanOptions) named(p string) bool {
	if len(o.Paths) == 0 {
		return true
	}
	for _, n := range o.Paths {
		n = filepath.Clean(n)
		if p == n || strings.HasPrefix(p, n+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func item(cat, target string, bytes int64, argv ...string) packages.Planned {
	return packages.Planned{Kind: KindClean, Package: packages.Package{Manager: cat, Name: target, Ident: target, Version: Human(bytes)},
		Latest: "removed", Command: argv}
}

// PlanClean plans the cleanup of a files run. Caches with a cleaner run it
// (with sudo -n for system ones); other caches, build directories and core
// dumps are deleted, since moving them to the trash on the same disk frees
// nothing; the user's own files (orphaned data, old downloads, extra copies
// of duplicates) go to the trash; the trash category empties it. Targets
// that vanished or fall outside the roots are skipped with the reason.
func PlanClean(d Data, o CleanOptions) packages.Plan {
	var plan packages.Plan
	del := func(cat, p string, bytes int64) {
		if !o.named(p) {
			return
		}
		it := item(cat, p, bytes, "rm", "-rf", "--", p)
		if !o.Safe(p) {
			it.Skip = "gone, or outside files.roots"
		}
		plan.Items = append(plan.Items, it)
	}
	trash := func(cat, p string, bytes int64) {
		if !o.named(p) {
			return
		}
		it := item(cat, p, bytes, "gio", "trash", "--", p)
		it.Latest = "in the trash"
		if !o.Safe(p) {
			it.Skip = "gone, or outside files.roots"
		}
		plan.Items = append(plan.Items, it)
	}
	// The trash is emptied first: steps run in order, and emptying it after
	// the orphaned, downloads and duplicates steps moved files into it would
	// delete those for good. First, it empties what the scan measured.
	if o.wants(CatTrash) && d.Trash > 0 && len(o.Paths) == 0 {
		it := item(CatTrash, d.TrashPath, d.Trash, "gio", "trash", "--empty")
		it.Latest = "emptied"
		plan.Items = append(plan.Items, it)
	}
	if o.wants(CatCache) {
		for _, c := range d.Caches {
			if c.Bytes < o.CacheMinMB*mb {
				continue
			}
			target := c.Path
			if target == "" {
				target = c.Name
			}
			switch {
			case len(c.Command) > 0:
				if len(o.Paths) > 0 && !o.named(c.Path) {
					continue
				}
				argv := c.Command
				if c.Root {
					argv = append([]string{"sudo", "-n"}, argv...)
				}
				it := item(CatCache, target, c.Bytes, argv...)
				it.Latest = "cleared by " + c.Command[0]
				plan.Items = append(plan.Items, it)
			default:
				del(CatCache, c.Path, c.Bytes)
			}
		}
	}
	if o.wants(CatBuild) {
		for _, b := range d.Build {
			n := len(plan.Items)
			del(CatBuild, b.Path, b.Bytes)
			if len(plan.Items) > n && plan.Items[n].Skip == "" {
				plan.Items[n].Skip = changedSince(b.Path, b.ModTime)
			}
		}
	}
	if o.wants(CatCores) {
		for _, c := range d.Cores {
			del(CatCores, c.Path, c.Bytes)
		}
	}
	if o.wants(CatOrphaned) {
		for _, x := range d.Orphans {
			trash(CatOrphaned, x.Path, x.Bytes)
		}
	}
	if o.wants(CatDownloads) {
		for _, f := range d.Downloads {
			trash(CatDownloads, f.Path, f.Bytes)
		}
	}
	if o.wants(CatDuplicates) {
		for _, x := range d.Dups {
			// The first copy (in sorted order) stays.
			for _, p := range x.Paths[1:] {
				n := len(plan.Items)
				trash(CatDuplicates, p, x.Bytes)
				if len(plan.Items) > n && plan.Items[n].Skip == "" {
					plan.Items[n].Skip = dupMismatch(x.Paths[0], p, x.Bytes)
				}
			}
		}
	}
	return plan
}

// VerifyClean checks that each deleted or trashed target is gone. Cleaner
// commands are trusted on their exit status.
func VerifyClean(results []packages.UpdateResult) {
	for i := range results {
		r := &results[i]
		if r.Status != packages.UpdateOK || r.Kind != KindClean {
			continue
		}
		if strings.HasPrefix(r.Command, "rm -rf -- ") || strings.HasPrefix(r.Command, "gio trash -- ") {
			if _, err := os.Lstat(r.ID); err == nil {
				r.Status, r.Reason = packages.UpdateFailed, "still there after "+strings.Fields(r.Command)[0]
				continue
			}
		}
		r.To = r.Latest
	}
}

// ParseCategories validates a --categories list; "all" selects every one.
func ParseCategories(list []string) ([]string, error) {
	if len(list) == 0 {
		return DefaultCategories, nil
	}
	var out []string
	for _, c := range list {
		c = strings.TrimSpace(strings.ToLower(c))
		switch {
		case c == "all":
			return Categories, nil
		case slices.Contains(Categories, c):
			out = append(out, c)
		default:
			return nil, fmt.Errorf("unknown cleanup category %q (want %s or all)", c, strings.Join(Categories, ", "))
		}
	}
	return out, nil
}
