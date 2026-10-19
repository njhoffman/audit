package packages

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

// Command is the audit command name packages findings are filed under.
const Command = "packages"

// ManagerBinaries legitimately exist in several places, so several distinct
// installs of one are worth flagging.
var ManagerBinaries = []string{"uv", "pnpm", "npm", "node", "cargo", "rustc", "go", "gem", "ruby", "gh"}

// State is what the package checks inspect.
type State struct {
	Ctx         context.Context
	Env         *exec.Env
	Inventories []Inventory
	// ScanDirs are extra directories inspected for broken links and scripts
	// (packages.scan_dirs in the config).
	ScanDirs []string
	// Meta is cached registry data by Package.Key. Packages without an entry
	// are skipped by the registry checks.
	Meta map[string]Meta
	// UnmaintainedAfter is the age of a latest release past which a package
	// counts as unmaintained; 0 turns the check off.
	UnmaintainedAfter time.Duration
	// Now dates release ages.
	Now time.Time
	// UpdateFailures holds each package's last update attempt, by Key, when
	// it failed; the outdated findings mention it.
	UpdateFailures map[string]UpdateFailure
	// Runtimes are the runtime statuses built from the runtime cache.
	Runtimes []RuntimeStatus
	// NodeMajor is the node major the pnpm globals were last installed
	// under; "" when unknown.
	NodeMajor string
	// AptStamp is apt's last-successful-update stamp file; "" uses
	// AptListsStamp.
	AptStamp string
}

func (s *State) inv(manager string) *Inventory {
	for i := range s.Inventories {
		if s.Inventories[i].Manager == manager && s.Inventories[i].Available {
			return &s.Inventories[i]
		}
	}
	return nil
}

func (s *State) onPath() map[string]bool {
	m := map[string]bool{}
	for _, p := range s.Env.Path() {
		if p != "" {
			m[filepath.Clean(p)] = true
		}
	}
	return m
}

// Checks lists the package checks in run order.
var Checks = []finding.Check[*State]{
	{ID: "manager.error", Fn: managerError},
	{ID: "manager.bin_not_on_path", Fn: binNotOnPath},
	{ID: "manager.multiple_installs", Fn: multipleInstalls},
	{ID: "exe.shadowed", Fn: exeShadowed},
	{ID: "exe.broken", Fn: exeBroken},
	{ID: "pnpm.legacy_shim", Fn: pnpmLegacyShim},
	{ID: "runtime.drift", Fn: runtimeDrift},
	{ID: "runtime.outdated", Fn: runtimeOutdated},
	{ID: "runtime.stale_dirs", Fn: staleDirs},
	{ID: "npm.stray_globals", Fn: npmStrayGlobals},
	{ID: "apt.stale_lists", Fn: aptStaleLists},
	{ID: "apt.held", Fn: aptHeld},
	{ID: "bins.untracked", Fn: binsUntracked},
}

// Analyze runs every package check, including the registry checks.
func Analyze(s *State) []finding.Finding {
	return finding.RunChecks(Command, s, append(slices.Clone(Checks), RegistryChecks...))
}

func under(path string, dirs ...string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, d+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func managerError(s *State) []finding.Finding {
	var out []finding.Finding
	for _, inv := range s.Inventories {
		if inv.Error != "" {
			out = append(out, finding.Finding{
				Severity: finding.Error, Subject: inv.Manager,
				Message: fmt.Sprintf("collecting %s failed: %s", inv.Manager, inv.Error),
			})
		}
	}
	return out
}

func binNotOnPath(s *State) []finding.Finding {
	on := s.onPath()
	var out []finding.Finding
	for _, inv := range s.Inventories {
		for _, d := range inv.BinDirs {
			if on[filepath.Clean(d)] {
				continue
			}
			out = append(out, finding.Finding{
				Severity: finding.Error, Subject: inv.Manager,
				Message: fmt.Sprintf("%s installs executables into %s, which is not on PATH", inv.Manager, d),
				Hint:    fmt.Sprintf("Add %s to PATH (in ~/.shell: add_path in env/paths.sh).", d),
			})
		}
	}
	return out
}

func multipleInstalls(s *State) []finding.Finding {
	var out []finding.Finding
	for _, name := range ManagerBinaries {
		// Keep the first PATH spelling of each distinct real file, so /bin
		// and /usr/bin on a merged-usr system count once.
		seen := map[string]bool{}
		var hits []string
		for _, hit := range s.Env.WhichAll(name) {
			real, err := filepath.EvalSymlinks(hit)
			if err != nil {
				real = hit
			}
			if !seen[real] {
				seen[real] = true
				hits = append(hits, hit)
			}
		}
		if len(hits) > 1 {
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: name, Details: hits,
				Message: fmt.Sprintf("%d different `%s` installs on PATH; %s wins", len(hits), name, hits[0]),
				Hint:    "Remove the ones you no longer use so updates land on the one you run.",
			})
		}
	}
	return out
}

type provider struct {
	manager, pkg, dir string
}

// providers maps each executable to the packages declaring it, for managers
// whose bin dir is on PATH.
func (s *State) providers() map[string][]provider {
	on := s.onPath()
	out := map[string][]provider{}
	for _, inv := range s.Inventories {
		if !inv.Available || inv.Manager == "gh" {
			continue
		}
		var dir string
		for _, d := range inv.BinDirs {
			if on[filepath.Clean(d)] {
				dir = d
				break
			}
		}
		if dir == "" {
			continue
		}
		for _, p := range inv.Packages {
			for _, exe := range p.Executables {
				out[exe] = append(out[exe], provider{inv.Manager, p.Name, dir})
			}
		}
	}
	return out
}

// exeShadowed reports executables a manager installed that are not what PATH
// resolves: exe.missing when nothing resolves, exe.conflict when another
// managed package wins, exe.shadowed when an unmanaged file wins.
func exeShadowed(s *State) []finding.Finding {
	provs := s.providers()
	exes := make([]string, 0, len(provs))
	for e := range provs {
		exes = append(exes, e)
	}
	sort.Strings(exes)
	var out []finding.Finding
	for _, exe := range exes {
		ps := provs[exe]
		resolved := s.Env.Which(exe)
		if resolved == "" {
			for _, p := range ps {
				out = append(out, finding.Finding{
					Check: "exe.missing", Severity: finding.Warning, Subject: p.manager + ":" + exe,
					Message: fmt.Sprintf("%s package %s declares `%s` but it is not on PATH (expected in %s)",
						p.manager, p.pkg, exe, p.dir),
					Hint: "Its link was removed; reinstall the package to restore it.",
				})
			}
			continue
		}
		var winners, losers []string
		for _, p := range ps {
			if under(resolved, p.dir) {
				winners = append(winners, p.manager+":"+p.pkg)
			} else {
				losers = append(losers, p.manager+":"+p.pkg)
			}
		}
		if len(losers) == 0 {
			if len(winners) > 1 {
				out = append(out, finding.Finding{
					Check: "exe.conflict", Severity: finding.Warning, Subject: exe,
					Message: fmt.Sprintf("`%s` is provided by %d packages (%s); the last one installed owns the link",
						exe, len(winners), strings.Join(winners, ", ")),
					Hint: "Uninstall the one you don't need.",
				})
			}
			continue
		}
		if owner := s.ownerOf(resolved); owner != "" {
			running := owner
			if len(winners) > 0 {
				running = winners[0]
			}
			out = append(out, finding.Finding{
				Check: "exe.conflict", Severity: finding.Warning, Subject: exe, Details: []string{resolved},
				Message: fmt.Sprintf("`%s` is installed by %s and %s; PATH runs %s",
					exe, strings.Join(losers, ", "), running, running),
				Hint: "Uninstall the copy you don't use, or it will drift out of date.",
			})
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: exe,
			Message: fmt.Sprintf("`%s` from %s is shadowed by %s", exe, strings.Join(losers, ", "), resolved),
			Hint:    "An earlier PATH entry wins. Remove the other copy or reorder PATH.",
		})
	}
	return out
}

func (s *State) ownerOf(path string) string {
	for _, inv := range s.Inventories {
		if under(path, inv.BinDirs...) {
			return inv.Manager
		}
	}
	return ""
}

var shebangRe = regexp.MustCompile(`^#!\s*(\S+)(?:[ \t]+(\S+))?`)

func (s *State) scanDirs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		d = filepath.Clean(d)
		if !seen[d] && isDir(d) {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, inv := range s.Inventories {
		for _, d := range inv.BinDirs {
			add(d)
		}
	}
	for _, d := range s.ScanDirs {
		add(s.Env.Expand(d))
	}
	return out
}

func exeBroken(s *State) []finding.Finding {
	var out []finding.Finding
	for _, dir := range s.scanDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if e.Type()&os.ModeSymlink != 0 {
				if _, err := os.Stat(path); err != nil {
					target, _ := os.Readlink(path)
					out = append(out, finding.Finding{
						Severity: finding.Error, Subject: path,
						Message: fmt.Sprintf("dangling symlink %s -> %s", path, target),
						Hint:    "Delete it or reinstall its package.",
					})
					continue
				}
			}
			if !isFile(path) {
				continue
			}
			if interp := missingInterpreter(s.Env, path); interp != "" {
				out = append(out, finding.Finding{
					Severity: finding.Error, Subject: path,
					Message: fmt.Sprintf("%s runs %s, which does not exist", path, interp),
					Hint:    "Reinstall whatever provides it, or delete it if it is not meant to run from here.",
				})
			}
		}
	}
	return out
}

// missingInterpreter returns the shebang interpreter of path when it does not
// exist, or "".
func missingInterpreter(env *exec.Env, path string) string {
	line, _, _ := strings.Cut(readHead(path, 256), "\n")
	m := shebangRe.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	interp := m[1]
	if strings.HasSuffix(interp, "/env") && m[2] != "" {
		if strings.HasPrefix(m[2], "-") || env.Which(m[2]) != "" {
			return ""
		}
		return m[2] + " (via env)"
	}
	if _, err := os.Stat(interp); err == nil {
		return ""
	}
	return interp
}

// pnpmShimNode matches the interpreter line of a pnpm shim.
var pnpmShimNode = regexp.MustCompile(`(?m)^"(\$basedir/node|/[^"]*/node)"`)

// pnpmLegacyShim reports shims pnpm < 11 left in the $PNPM_HOME root; pnpm
// 11 and later link into bin/.
func pnpmLegacyShim(s *State) []finding.Finding {
	home := s.Env.Get("PNPM_HOME")
	if s.inv("pnpm") == nil || home == "" || !isDir(home) {
		return nil
	}
	binDir := filepath.Join(home, "bin")
	current := map[string]bool{}
	if es, err := os.ReadDir(binDir); err == nil {
		for _, e := range es {
			current[e.Name()] = true
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil
	}
	var stale, broken []string
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(home, name)
		ext := filepath.Ext(name)
		if !isFile(path) || name == "pnpm" || name == "pnpx" || ext == ".ps1" || ext == ".cmd" {
			continue
		}
		text := readHead(path, 2048)
		if !strings.Contains(text, "$basedir") {
			continue
		}
		if current[name] {
			stale = append(stale, name)
			continue
		}
		if m := pnpmShimNode.FindStringSubmatch(text); m != nil {
			target := strings.ReplaceAll(m[1], "$basedir", home)
			if _, err := os.Stat(target); err != nil {
				broken = append(broken, name)
			}
		}
	}
	var out []finding.Finding
	if len(stale) > 0 {
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: "stale", Details: stale,
			Message: fmt.Sprintf("%d old pnpm shim(s) in %s are superseded by %s", len(stale), home, binDir),
			Hint:    fmt.Sprintf("pnpm no longer uses them; delete the listed files from %s.", home),
		})
	}
	for _, name := range broken {
		out = append(out, finding.Finding{
			Severity: finding.Error, Subject: name,
			Message: fmt.Sprintf("%s runs %s, which does not exist", filepath.Join(home, name), filepath.Join(home, "node")),
			Hint:    fmt.Sprintf("Reinstall with `pnpm add -g` so it is linked into %s.", binDir),
		})
	}
	return out
}

func readHead(path string, n int) string {
	f, err := os.Open(path) // #nosec G304 -- scanning bin dirs
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	m, _ := io.ReadFull(f, buf)
	return string(buf[:m])
}

var driftHints = map[string]string{
	"uv": "uv tools keep the exact interpreter they were installed with. `audit packages runtimes migrate python` " +
		"reinstalls them on the default one; add a tool to packages.update.exclude to keep it pinned.",
	"pnpm":  "Native addons are built for one node major. `audit packages runtimes migrate node` reinstalls the globals.",
	"cargo": "Harmless unless a crate needs newer std; `audit packages runtimes migrate --rebuild rust` rebuilds them.",
	"go":    "Harmless; `audit packages runtimes migrate --rebuild go` rebuilds them with the current toolchain.",
}

// runtimeDrift reports packages built or installed against a runtime other
// than the current one. uv and pnpm drift is a notice, since the old
// runtime can go away under them; cargo and go binaries are self-contained
// and only informational.
func runtimeDrift(s *State) []finding.Finding {
	var out []finding.Finding
	for _, rt := range []string{RuntimePython, RuntimeNode, RuntimeRust, RuntimeGo} {
		manager := runtimeManagers[rt]
		inv := s.inv(manager)
		if inv == nil || inv.Runtime == nil || inv.Runtime.Version == "" {
			continue
		}
		drifted := Drifted(*inv, rt, s.NodeMajor)
		if len(drifted) == 0 {
			continue
		}
		current := inv.Runtime.Version
		sev := finding.Info
		if rt == RuntimePython || rt == RuntimeNode {
			sev = finding.Notice
		}
		if rt == RuntimeNode {
			names := make([]string, len(drifted))
			for i, p := range drifted {
				names[i] = p.Name
			}
			sort.Strings(names)
			out = append(out, finding.Finding{
				Severity: sev, Subject: manager, Details: names,
				Message: fmt.Sprintf("%d pnpm global(s) were installed under node %s; node is now %s",
					len(drifted), s.NodeMajor, current),
				Hint: driftHints[manager],
			})
			continue
		}
		byVersion := map[string][]string{}
		for _, p := range drifted {
			byVersion[p.RuntimeVersion] = append(byVersion[p.RuntimeVersion], p.Name)
		}
		versions := make([]string, 0, len(byVersion))
		for v := range byVersion {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		details := make([]string, 0, len(versions))
		for _, v := range versions {
			names := byVersion[v]
			sort.Strings(names)
			details = append(details, v+": "+strings.Join(names, ", "))
		}
		out = append(out, finding.Finding{
			Severity: sev, Subject: manager, Details: details,
			Message: fmt.Sprintf("%d %s package(s) built with a %s other than %s",
				len(drifted), manager, inv.Runtime.Name, current),
			Hint: driftHints[manager],
		})
	}
	return out
}

// runtimeOutdated reports runtimes behind a release, from the runtime cache:
// a newer release of the installed line is a notice when audit can update
// it, a new line (python minor, node LTS major, go minor) is info.
func runtimeOutdated(s *State) []finding.Finding {
	var out []finding.Finding
	for _, st := range s.Runtimes {
		if st.Error != "" || st.CheckedAt.IsZero() {
			continue
		}
		managed := st.Owner != OwnerSystem && st.Owner != OwnerManual
		var details []string
		for _, l := range st.Lines {
			if l.Behind() {
				details = append(details, fmt.Sprintf("%s: %s -> %s", l.Name, l.Version, l.Latest))
			}
		}
		behind, newLine := st.Behind(), st.NewerLine()
		if !behind && !newLine {
			continue
		}
		f := finding.Finding{Severity: finding.Info, Subject: st.Name, Details: details}
		switch {
		case behind && len(st.Lines) > 0:
			f.Message = fmt.Sprintf("%s: %d install(s) have a newer release", st.Name, len(details))
		case behind:
			f.Message = fmt.Sprintf("%s %s -> %s is available", st.Name, st.Version, st.Latest)
		default:
			f.Message = fmt.Sprintf("%s %s is available (%s installed)", st.Name, st.Newest, st.Version)
		}
		if behind && newLine {
			f.Message += fmt.Sprintf("; %s %s is the newest", st.Name, st.Newest)
		}
		switch {
		case !managed:
			f.Hint = fmt.Sprintf("%s comes from %s (%s); update it there.", st.Name, ownerLabel(st.Owner), st.Path)
		case behind:
			f.Severity = finding.Notice
			f.Hint = "`audit packages runtimes update " + st.Name + "`."
		default:
			f.Hint = "`audit packages runtimes update --major " + st.Name + "`, then `audit packages runtimes migrate " + st.Name + "`."
		}
		out = append(out, f)
	}
	return out
}

func ownerLabel(owner string) string {
	if owner == OwnerSystem {
		return "the system package manager"
	}
	return "a manual install"
}

func staleDirs(s *State) []finding.Finding {
	var out []finding.Finding
	if gem := s.inv("gem"); gem != nil && len(gem.BinDirs) > 0 {
		userDir := filepath.Dir(filepath.Clean(gem.BinDirs[0]))
		parent := filepath.Dir(userDir)
		if es, err := os.ReadDir(parent); err == nil {
			for _, e := range es {
				d := filepath.Join(parent, e.Name())
				if !isDir(d) || e.Name() == filepath.Base(userDir) {
					continue
				}
				out = append(out, finding.Finding{
					Severity: finding.Warning, Subject: d,
					Message: "gem directory for another ruby ABI: " + d,
					Hint:    fmt.Sprintf("Current ruby uses %s; delete %s if unused.", filepath.Base(userDir), d),
				})
			}
		}
	}
	lib := filepath.Join(s.Env.Home, ".local", "lib")
	matches, _ := filepath.Glob(filepath.Join(lib, "python3.*"))
	sort.Strings(matches)
	for _, d := range matches {
		if !isDir(d) || s.Env.Which(filepath.Base(d)) != "" {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: d,
			Message: fmt.Sprintf("user site-packages for %s, which is not installed: %s", filepath.Base(d), d),
			Hint:    fmt.Sprintf("Delete %s.", d),
		})
	}
	return out
}

func npmStrayGlobals(s *State) []finding.Finding {
	if s.Env.Which("npm") == "" {
		return nil
	}
	r := s.Env.Run(s.Ctx, "npm", []string{"config", "get", "prefix"}, exec.Options{Timeout: 15 * time.Second})
	prefix := strings.TrimSpace(r.Stdout)
	if !r.OK() || prefix == "" {
		return nil
	}
	modules := filepath.Join(prefix, "lib", "node_modules")
	entries, err := os.ReadDir(modules)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, "@") && isDir(filepath.Join(modules, name)):
			subs, _ := os.ReadDir(filepath.Join(modules, name))
			for _, sub := range subs {
				names = append(names, name+"/"+sub.Name())
			}
		case strings.HasPrefix(name, "."), name == "npm", name == "corepack":
		default:
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return []finding.Finding{{
		Severity: finding.Warning, Subject: "npm", Details: names,
		Message: fmt.Sprintf("%d package(s) installed with `npm install -g` into %s", len(names), prefix),
		Hint:    "pnpm owns globals here. Reinstall with `pnpm add -g` and remove with `npm uninstall -g`.",
	}}
}
