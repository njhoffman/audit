package packages

import (
	"path/filepath"
	"slices"
	"strings"
)

// ProgramCopy is one executable of a program found on PATH and what owns
// it. Manager is set when a manager owns the path even if the package is
// unknown (Item nil); both are empty when nothing does.
type ProgramCopy struct {
	Path    string `json:"path"`
	Manager string `json:"manager,omitempty"`
	Item    *Item  `json:"item,omitempty"`
}

// ProgramPackages is a program's executables in PATH order: Copies[0] is
// the one that runs, the rest are shadowed by it.
type ProgramPackages struct {
	Program string        `json:"program"`
	Copies  []ProgramCopy `json:"copies"`
}

// Shadowed reports the copies after the first that a manager owns.
func (pp ProgramPackages) Shadowed() []ProgramCopy {
	if len(pp.Copies) < 2 {
		return nil
	}
	return pp.Copies[1:]
}

// ResolveProgram finds the executables of a program (exes, in preference
// order) with which, which lists every match on PATH in order, and the
// owner of each. Paths reached through a symlink to one already seen count
// once.
func ResolveProgram(program string, exes []string, which func(string) []string, resolve func(string) string,
	owner func(path string) (string, *Item)) ProgramPackages {
	pp := ProgramPackages{Program: program, Copies: []ProgramCopy{}}
	seen := map[string]bool{}
	for _, exe := range exes {
		for _, p := range which(exe) {
			real := resolve(p)
			if seen[real] {
				continue
			}
			seen[real] = true
			c := ProgramCopy{Path: p}
			c.Manager, c.Item = owner(real)
			if c.Manager == "" && real != p {
				c.Manager, c.Item = owner(p)
			}
			pp.Copies = append(pp.Copies, c)
		}
	}
	return pp
}

// OwnerOf finds the package path belongs to among the annotated
// inventories: dpkg (which may be nil) names apt's package for a path, a
// /snap/bin entry is its snap, and another manager owns a path it records
// as a package location, or one in its bin directories named like one of
// its packages' executables (the manager alone when no package matches).
func OwnerOf(path string, as []Annotated, dpkg func(string) string) (string, *Item) {
	find := func(manager string, match func(Item) bool) *Item {
		for i := range as {
			if as[i].Manager != manager {
				continue
			}
			for j := range as[i].Items {
				if match(as[i].Items[j]) {
					return &as[i].Items[j]
				}
			}
		}
		return nil
	}
	has := func(manager string) bool {
		return slices.ContainsFunc(as, func(a Annotated) bool { return a.Manager == manager })
	}
	if dpkg != nil && has("apt") {
		if name := dpkg(path); name != "" {
			name, _, _ = strings.Cut(name, ":") // the arch qualifier: libc6:amd64
			return "apt", find("apt", func(it Item) bool { return it.Name == name })
		}
	}
	if rest, ok := strings.CutPrefix(path, "/snap/bin/"); ok && has("snap") {
		name, _, _ := strings.Cut(rest, ".")
		return "snap", find("snap", func(it Item) bool { return it.Name == name })
	}
	base, dir := filepath.Base(path), filepath.Dir(path)
	for _, a := range as {
		if IsSystem(a.Manager) {
			continue
		}
		if it := find(a.Manager, func(it Item) bool { return it.Location == path }); it != nil {
			return a.Manager, it
		}
		if !slices.Contains(a.BinDirs, dir) {
			continue
		}
		if it := find(a.Manager, func(it Item) bool { return slices.Contains(it.Executables, base) }); it != nil {
			return a.Manager, it
		}
		return a.Manager, nil
	}
	return "", nil
}

// UpstreamVersion strips what makes versions of one program incomparable
// across managers: a leading v, an apt epoch (1:) and a Debian revision
// (-3ubuntu1).
func UpstreamVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	if i := strings.LastIndex(v, "-"); i > 0 {
		v = v[:i]
	}
	return v
}

// NewerShadowed is the first shadowed copy whose package is a newer
// version than the one that runs, or nil.
func (pp ProgramPackages) NewerShadowed() *ProgramCopy {
	if len(pp.Copies) == 0 || pp.Copies[0].Item == nil {
		return nil
	}
	runs := UpstreamVersion(pp.Copies[0].Item.Version)
	for i, c := range pp.Shadowed() {
		if c.Item == nil {
			continue
		}
		if n, ok := CompareVersions("", UpstreamVersion(c.Item.Version), runs); ok && n > 0 {
			return &pp.Shadowed()[i]
		}
	}
	return nil
}
