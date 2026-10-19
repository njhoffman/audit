package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

// System managers report their own available updates, need root to apply
// them, and have no registry audit looks up.
var systemManagers = map[string]bool{"apt": true, "snap": true, "flatpak": true}

// IsSystem reports whether manager is apt, snap or flatpak.
func IsSystem(manager string) bool { return systemManagers[manager] }

// LocalMeta returns metas with an entry for every package of a system
// manager, built from the version the manager itself offers (Package.Latest
// in the inventory). These entries are never saved; they let the outdated
// checks, the inventory and update plans treat system packages like the
// others.
func LocalMeta(invs []Inventory, metas map[string]Meta, now time.Time) map[string]Meta {
	out := make(map[string]Meta, len(metas))
	for k, v := range metas {
		out[k] = v
	}
	for _, inv := range invs {
		if !IsSystem(inv.Manager) {
			continue
		}
		for _, p := range inv.Packages {
			latest := p.Available
			if latest == "" {
				latest = p.Version
			}
			out[p.Key()] = Meta{Manager: p.Manager, ID: p.ID(), Registry: p.Manager, Latest: latest,
				Installed: p.Version, CheckedAt: now, Local: true}
		}
	}
	return out
}

// Apt inventories manually installed Debian packages plus any package with
// an upgrade pending, from dpkg and apt's cached lists. It never refreshes
// the lists: that needs root and is left to `audit packages update`.
type Apt struct{}

// Name implements Manager.
func (Apt) Name() string { return "apt" }

// Binary implements Manager.
func (Apt) Binary() string { return "apt-get" }

// Runtime implements Manager.
func (Apt) Runtime(context.Context, *exec.Env) *Runtime { return nil }

// ManagerVersion implements Manager.
func (Apt) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "apt-get")
}

// BinDirs implements Manager.
func (Apt) BinDirs(context.Context, *exec.Env) []string { return nil }

// Collect implements Manager.
func (Apt) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	opts := exec.Options{Timeout: time.Minute}
	r := env.Run(ctx, "dpkg-query", []string{"-W", "-f", `${Package}\t${Version}\t${db:Status-Abbrev}\n`}, opts)
	if !r.OK() {
		return nil, errors.New("dpkg-query failed: " + truncate(r.Stderr, 300))
	}
	installed := ParseDpkgQuery(r.Stdout)
	manual := map[string]bool{}
	if r := env.Run(ctx, "apt-mark", []string{"showmanual"}, opts); r.OK() {
		for _, n := range strings.Fields(r.Stdout) {
			manual[n] = true
		}
	}
	held := map[string]bool{}
	if r := env.Run(ctx, "apt-mark", []string{"showhold"}, opts); r.OK() {
		for _, n := range strings.Fields(r.Stdout) {
			held[n] = true
		}
	}
	upgradable := map[string]string{}
	if r := env.Run(ctx, "apt", []string{"list", "--upgradable"}, opts); r.OK() {
		upgradable = ParseAptUpgradable(r.Stdout)
	}
	var out []Package
	for name, version := range installed {
		latest, up := upgradable[name]
		if !manual[name] && !up {
			continue
		}
		p := Package{Manager: "apt", Name: name, Version: version, Source: "apt", Held: held[name]}
		if up {
			p.Available = latest
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseDpkgQuery reads `dpkg-query -W -f '${Package}\t${Version}\t${db:Status-Abbrev}\n'`
// and keeps installed packages ("ii", "hi").
func ParseDpkgQuery(out string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 || len(f[2]) < 2 || f[2][1] != 'i' {
			continue
		}
		m[strings.SplitN(f[0], ":", 2)[0]] = f[1]
	}
	return m
}

// ParseAptUpgradable reads `apt list --upgradable`: "name/suite version
// arch [upgradable from: old]".
func ParseAptUpgradable(out string) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, "[upgradable from:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, _, _ := strings.Cut(f[0], "/")
		m[name] = f[1]
	}
	return m
}

// Snap inventories installed snaps and the refreshes snapd has pending.
type Snap struct{}

// Name implements Manager.
func (Snap) Name() string { return "snap" }

// Binary implements Manager.
func (Snap) Binary() string { return "snap" }

// Runtime implements Manager.
func (Snap) Runtime(context.Context, *exec.Env) *Runtime { return nil }

// ManagerVersion implements Manager.
func (Snap) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "snap")
}

// BinDirs implements Manager.
func (Snap) BinDirs(context.Context, *exec.Env) []string { return []string{"/snap/bin"} }

// Collect implements Manager.
func (Snap) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	opts := exec.Options{Timeout: time.Minute}
	r := env.Run(ctx, "snap", []string{"list"}, opts)
	if !r.OK() {
		return nil, errors.New("snap list failed: " + truncate(r.Stderr, 300))
	}
	var pkgs []Package
	for _, e := range ParseSnapList(r.Stdout) {
		pkgs = append(pkgs, Package{Manager: "snap", Name: e.Name, Version: e.Version, Source: "snap"})
	}
	if r := env.Run(ctx, "snap", []string{"refresh", "--list"}, opts); r.OK() {
		pending := map[string]SnapEntry{}
		for _, e := range ParseSnapList(r.Stdout) {
			pending[e.Name] = e
		}
		for i := range pkgs {
			up, ok := pending[pkgs[i].Name]
			if !ok {
				continue
			}
			pkgs[i].Available = up.Version
			if up.Version == pkgs[i].Version {
				// A new revision of the same version.
				pkgs[i].Available = up.Version + " (rev " + up.Rev + ")"
			}
		}
	}
	return pkgs, nil
}

// SnapEntry is one row of `snap list` or `snap refresh --list`.
type SnapEntry struct{ Name, Version, Rev string }

// ParseSnapList reads `snap list` or `snap refresh --list`: a header, then
// Name Version Rev ... per line. "All snaps up to date." yields nothing.
func ParseSnapList(out string) []SnapEntry {
	var es []SnapEntry
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || f[0] == "Name" {
			continue
		}
		es = append(es, SnapEntry{Name: f[0], Version: f[1], Rev: f[2]})
	}
	return es
}

// Flatpak inventories apps and runtimes of the system and user
// installations, with the updates their remotes offer.
type Flatpak struct{}

// Name implements Manager.
func (Flatpak) Name() string { return "flatpak" }

// Binary implements Manager.
func (Flatpak) Binary() string { return "flatpak" }

// Runtime implements Manager.
func (Flatpak) Runtime(context.Context, *exec.Env) *Runtime { return nil }

// ManagerVersion implements Manager.
func (Flatpak) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "flatpak")
}

// BinDirs implements Manager.
func (Flatpak) BinDirs(context.Context, *exec.Env) []string { return nil }

// Collect implements Manager.
func (Flatpak) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	opts := exec.Options{Timeout: 2 * time.Minute}
	r := env.Run(ctx, "flatpak", []string{"list", "--columns=application,version,branch,installation,ref"}, opts)
	if !r.OK() {
		return nil, errors.New("flatpak list failed: " + truncate(r.Stderr, 300))
	}
	pkgs := ParseFlatpakList(r.Stdout)
	for _, inst := range []string{"system", "user"} {
		r := env.Run(ctx, "flatpak", []string{"remote-ls", "--updates", "--" + inst, "--columns=ref,version"}, opts)
		if !r.OK() {
			continue
		}
		ups := map[string]string{}
		for line := range strings.SplitSeq(r.Stdout, "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 1 || strings.TrimSpace(f[0]) == "" {
				continue
			}
			v := ""
			if len(f) > 1 {
				v = strings.TrimSpace(f[1])
			}
			ups[strings.TrimSpace(f[0])] = v
		}
		for i := range pkgs {
			if pkgs[i].Location != inst {
				continue
			}
			ref := strings.TrimPrefix(strings.TrimPrefix(pkgs[i].Ident, "app/"), "runtime/")
			for _, k := range []string{pkgs[i].Ident, ref, "app/" + ref, "runtime/" + ref} {
				if v, ok := ups[k]; ok {
					if v == "" || v == pkgs[i].Version {
						v = "newer build"
						if pkgs[i].Version != "" {
							v = pkgs[i].Version + " (newer build)"
						}
					}
					pkgs[i].Available = v
					break
				}
			}
		}
	}
	return pkgs, nil
}

// ParseFlatpakList reads `flatpak list --columns=application,version,branch,installation,ref`.
func ParseFlatpakList(out string) []Package {
	var pkgs []Package
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || f[0] == "" || f[0] == "Application ID" {
			continue
		}
		pkgs = append(pkgs, Package{Manager: "flatpak", Name: f[0], Version: f[1], Ident: f[4], Location: f[3], Source: "flatpak"})
	}
	sort.SliceStable(pkgs, func(i, j int) bool { return pkgs[i].Ident < pkgs[j].Ident })
	return pkgs
}

// Batch merges the runnable apt, snap and flatpak items of a plan into one
// command per manager (and flatpak installation), since each is
// transactional and holds a lock. Every merged item gets the same command
// and Batch key; RunUpdates runs a batch once.
func Batch(plan Plan) Plan {
	names := map[string][]string{}
	var order []string
	for _, it := range plan.Items {
		key := batchKey(it.Package)
		if key == "" || it.Skip != "" {
			continue
		}
		if _, ok := names[key]; !ok {
			order = append(order, key)
		}
		target := it.Name
		if it.Manager == "flatpak" {
			target = it.Ident
		}
		names[key] = append(names[key], target)
	}
	cmds := map[string][]string{}
	for _, key := range order {
		cmds[key] = batchCommand(key, names[key])
	}
	for i, it := range plan.Items {
		if key := batchKey(it.Package); key != "" && it.Skip == "" {
			plan.Items[i].Batch, plan.Items[i].Command = key, cmds[key]
		}
	}
	return plan
}

func batchKey(p Package) string {
	switch p.Manager {
	case "apt", "snap":
		return p.Manager
	case "flatpak":
		if p.Location == "user" {
			return "flatpak:user"
		}
		return "flatpak:system"
	}
	return ""
}

// AptUpgradeArgs keep apt from prompting: no debconf questions, and existing
// config files kept when a package ships a new default.
var AptUpgradeArgs = []string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--only-upgrade",
	"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

func batchCommand(key string, targets []string) []string {
	switch key {
	case "apt":
		return append(append([]string{"sudo", "-n"}, AptUpgradeArgs...), targets...)
	case "snap":
		return append([]string{"sudo", "-n", "snap", "refresh"}, targets...)
	case "flatpak:user":
		return append([]string{"flatpak", "update", "--user", "-y", "--noninteractive"}, targets...)
	}
	return append([]string{"sudo", "-n", "flatpak", "update", "--system", "-y", "--noninteractive"}, targets...)
}

// NeedsRoot reports whether any runnable item runs through sudo.
func (p Plan) NeedsRoot() bool {
	for _, it := range p.Runnable() {
		if len(it.Command) > 0 && it.Command[0] == "sudo" {
			return true
		}
	}
	return false
}

// AptListsStamp is where apt records its last successful list update.
const AptListsStamp = "/var/lib/apt/periodic/update-success-stamp"

// aptStaleAfter is how old apt's lists may get before scans say upgrades
// may be missing.
const aptStaleAfter = 7 * 24 * time.Hour

func aptStaleLists(s *State) []finding.Finding {
	if s.inv("apt") == nil {
		return nil
	}
	stamp := s.AptStamp
	if stamp == "" {
		stamp = AptListsStamp
	}
	st, err := os.Stat(stamp)
	if err != nil {
		return nil
	}
	age := s.Now.Sub(st.ModTime())
	if age < aptStaleAfter {
		return nil
	}
	return []finding.Finding{{
		Severity: finding.Notice, Subject: "apt",
		Message: fmt.Sprintf("apt's package lists were last refreshed %s ago (%s); upgrades may be missing",
			Age(age), st.ModTime().UTC().Format(time.DateOnly)),
		Hint: "`audit packages update -M apt` refreshes them first (it asks for sudo).",
	}}
}

func aptHeld(s *State) []finding.Finding {
	inv := s.inv("apt")
	if inv == nil {
		return nil
	}
	var held []string
	for _, p := range inv.Packages {
		if p.Held && p.Available != "" {
			held = append(held, fmt.Sprintf("%s %s -> %s", p.Name, p.Version, p.Available))
		}
	}
	if len(held) == 0 {
		return nil
	}
	sort.Strings(held)
	return []finding.Finding{{
		Severity: finding.Info, Subject: "apt", Details: held,
		Message: fmt.Sprintf("%d held apt package(s) have upgrades waiting", len(held)),
		Hint:    "audit never upgrades held packages; `sudo apt-mark unhold NAME` releases one.",
	}}
}
