package packages

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Runtime names, as Runtime.Name reports them.
const (
	RuntimePython = "python"
	RuntimeNode   = "node"
	RuntimeRust   = "rust"
	RuntimeGo     = "go"
	RuntimeRuby   = "ruby"
)

// RuntimeNames lists the runtimes audit tracks, in display order.
var RuntimeNames = []string{RuntimePython, RuntimeNode, RuntimeRust, RuntimeGo, RuntimeRuby}

// runtimeManagers maps each runtime to the manager whose packages run on it.
var runtimeManagers = map[string]string{
	RuntimePython: "uv", RuntimeNode: "pnpm", RuntimeRust: "cargo", RuntimeGo: "go", RuntimeRuby: "gem",
}

// Runtime owners: what installed the runtime, and so what can update it.
const (
	OwnerUv     = "uv"
	OwnerPnpm   = "pnpm"
	OwnerRustup = "rustup"
	OwnerSystem = "system"
	OwnerManual = "manual"
)

// Update item kinds.
const (
	KindPackage   = "package"
	KindRuntime   = "runtime"
	KindMigration = "migration"
)

// RuntimeMeta is the cached lookup of a runtime's releases.
type RuntimeMeta struct {
	Name string `json:"name"`
	// Lines maps each release line to its newest stable release: python
	// minors ("3.14"), node majors ("24"), go minors ("1.27") and rustup
	// toolchains ("stable-x86_64-unknown-linux-gnu").
	Lines map[string]string `json:"lines,omitempty"`
	// Newest is where an update across lines goes: the newest stable python,
	// the newest node LTS, the newest go.
	Newest string `json:"newest,omitempty"`
	// Installs lists the python interpreters uv sees (python only).
	Installs []PythonInstall `json:"installs,omitempty"`
	// PythonDir is where uv keeps the interpreters it manages.
	PythonDir string `json:"python_dir,omitempty"`
	// Toolchains are rustup's installed toolchains (rust only).
	Toolchains []Toolchain `json:"toolchains,omitempty"`
	CheckedAt  time.Time   `json:"checked_at"`
	Error      string      `json:"error,omitempty"`
}

// PythonInstall is one interpreter uv found.
type PythonInstall struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	// Managed means uv installed it, so uv can upgrade it.
	Managed bool `json:"managed,omitempty"`
}

// Toolchain is a rustup toolchain with the release rustup offers for it.
type Toolchain struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Latest    string `json:"latest,omitempty"`
}

// Short drops the host triple: "stable-x86_64-unknown-linux-gnu" is
// "stable".
func (t Toolchain) Short() string {
	if i := strings.Index(t.Name, "-x86_64-"); i > 0 {
		return t.Name[:i]
	}
	if i := strings.Index(t.Name, "-aarch64-"); i > 0 {
		return t.Name[:i]
	}
	return t.Name
}

// Behind reports whether rustup offers a newer release of the toolchain.
func (t Toolchain) Behind() bool { return t.Latest != "" && t.Latest != t.Installed }

// stableRe matches a final release, with no alpha, beta or rc part.
var stableRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ParseUvPythonList reads `uv python list --output-format json`: the newest
// stable CPython of each minor uv can download, and the interpreters already
// on disk. Interpreters under dir count as managed. uv prints paths under
// its working directory relative to it, so they are resolved against cwd.
func ParseUvPythonList(out, dir, cwd string) (lines map[string]string, installs []PythonInstall, err error) {
	var entries []struct {
		Version        string  `json:"version"`
		Path           *string `json:"path"`
		Implementation string  `json:"implementation"`
		Variant        string  `json:"variant"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, nil, fmt.Errorf("read uv python list: %w", err)
	}
	lines = map[string]string{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Implementation != "cpython" || (e.Variant != "" && e.Variant != "default") || !stableRe.MatchString(e.Version) {
			continue
		}
		minor := VersionLine(RuntimePython, e.Version)
		if cur, ok := lines[minor]; !ok || newer(e.Version, cur) {
			lines[minor] = e.Version
		}
		if e.Path == nil {
			continue
		}
		path := *e.Path
		if !filepath.IsAbs(path) && cwd != "" {
			path = filepath.Join(cwd, path)
		}
		real := path
		if r, err := filepath.EvalSymlinks(path); err == nil {
			real = r
		}
		if seen[e.Version+"\x00"+real] {
			continue
		}
		seen[e.Version+"\x00"+real] = true
		installs = append(installs, PythonInstall{Version: e.Version, Path: path,
			Managed: dir != "" && strings.HasPrefix(real, filepath.Clean(dir)+string(filepath.Separator))})
	}
	return lines, installs, nil
}

// ParseNodeIndex reads nodejs.org/dist/index.json: the newest release of
// each major, and the newest LTS release.
func ParseNodeIndex(body []byte) (lines map[string]string, lts string, err error) {
	var entries []struct {
		Version string          `json:"version"`
		LTS     json.RawMessage `json:"lts"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, "", fmt.Errorf("read node release index: %w", err)
	}
	lines = map[string]string{}
	for _, e := range entries {
		v := strings.TrimPrefix(e.Version, "v")
		if !stableRe.MatchString(v) {
			continue
		}
		major := VersionLine(RuntimeNode, v)
		if cur, ok := lines[major]; !ok || newer(v, cur) {
			lines[major] = v
		}
		if string(e.LTS) != "false" && len(e.LTS) > 0 && (lts == "" || newer(v, lts)) {
			lts = v
		}
	}
	return lines, lts, nil
}

// ParseGoReleases reads go.dev/dl/?mode=json: the newest stable release of
// each minor, and the newest overall.
func ParseGoReleases(body []byte) (lines map[string]string, newest string, err error) {
	var entries []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, "", fmt.Errorf("read go release list: %w", err)
	}
	lines = map[string]string{}
	for _, e := range entries {
		v := strings.TrimPrefix(e.Version, "go")
		if !e.Stable {
			continue
		}
		line := VersionLine(RuntimeGo, v)
		if cur, ok := lines[line]; !ok || newer(v, cur) {
			lines[line] = v
		}
		if newest == "" || newer(v, newest) {
			newest = v
		}
	}
	return lines, newest, nil
}

var rustupCheckRe = regexp.MustCompile(`^(\S+) - (up to date|update available): (.+?)(?: -> (.+))?$`)

// ParseRustupCheck reads `rustup check`: each toolchain with its installed
// release and, when rustup offers one, the newer release. rustup's own line
// is left out.
func ParseRustupCheck(out string) []Toolchain {
	var tcs []Toolchain
	for line := range strings.SplitSeq(out, "\n") {
		m := rustupCheckRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] == "rustup" {
			continue
		}
		tc := Toolchain{Name: m[1], Installed: strings.TrimSpace(m[3])}
		if m[2] == "update available" {
			tc.Latest = strings.TrimSpace(m[4])
		}
		tcs = append(tcs, tc)
	}
	return tcs
}

// VersionLine is the release line a version belongs to: the minor for
// python and go, the major for node, the version itself otherwise.
func VersionLine(runtime, v string) string {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	switch runtime {
	case RuntimePython, RuntimeGo:
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
	case RuntimeNode:
		return parts[0]
	}
	return v
}

func newer(a, b string) bool {
	c, ok := CompareVersions("", a, b)
	return ok && c > 0
}

// RuntimeStatus is one runtime: what is installed, who owns it and what is
// newer.
type RuntimeStatus struct {
	Name string `json:"name"`
	// Manager installs packages against the runtime.
	Manager string `json:"manager"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	Owner   string `json:"owner"`
	// Latest is the newest release in Version's line; Newest is the newest
	// release a cross-line update moves to.
	Latest string `json:"latest,omitempty"`
	Newest string `json:"newest,omitempty"`
	// Lines are the uv-managed interpreters (python) or rustup toolchains
	// (rust) that update one by one.
	Lines []RuntimeLine `json:"lines,omitempty"`
	// Drifted counts packages installed against another version.
	Drifted   int       `json:"drifted"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// RuntimeLine is one separately updated install of a runtime.
type RuntimeLine struct {
	// Name is the plan name: "python3.12", "rust stable".
	Name string `json:"name"`
	// Target is what the update command takes: "3.12", the full toolchain.
	Target  string `json:"target"`
	Version string `json:"version"`
	Latest  string `json:"latest,omitempty"`
	Default bool   `json:"default,omitempty"`
}

// Behind reports whether the runtime's own line has a newer release.
func (r RuntimeStatus) Behind() bool {
	if len(r.Lines) > 0 {
		return slices.ContainsFunc(r.Lines, RuntimeLine.Behind)
	}
	return r.Latest != "" && newer(r.Latest, r.Version)
}

// NewerLine reports whether a release line past the installed one exists.
func (r RuntimeStatus) NewerLine() bool {
	return r.Newest != "" && r.Version != "" && newer(r.Newest, r.Version) &&
		VersionLine(r.Name, r.Newest) != VersionLine(r.Name, r.Version)
}

// RuntimeContext is what RuntimeStatuses reads besides the inventory.
type RuntimeContext struct {
	Env  *exec.Env
	Meta map[string]RuntimeMeta
	// NodeMajor is the node major the pnpm globals were last installed
	// under; "" when unknown.
	NodeMajor string
}

// RuntimeStatuses describes each tracked runtime whose manager was
// collected.
func RuntimeStatuses(invs []Inventory, rc RuntimeContext) []RuntimeStatus {
	var out []RuntimeStatus
	for _, name := range RuntimeNames {
		manager := runtimeManagers[name]
		var inv *Inventory
		for i := range invs {
			if invs[i].Manager == manager && invs[i].Available {
				inv = &invs[i]
			}
		}
		if inv == nil || inv.Runtime == nil || inv.Runtime.Version == "" {
			continue
		}
		rt := inv.Runtime
		st := RuntimeStatus{Name: name, Manager: manager, Version: rt.Version, Path: rt.Path,
			Owner: runtimeOwner(rc.Env, name, rt.Path, rc.Meta[name])}
		if m, ok := rc.Meta[name]; ok {
			st.CheckedAt, st.Error, st.Newest = m.CheckedAt, m.Error, m.Newest
			st.Latest = m.Lines[VersionLine(name, rt.Version)]
			switch name {
			case RuntimePython:
				st.Lines = pythonLines(m, rt.Version)
			case RuntimeRust:
				st.Newest = ""
				for _, tc := range m.Toolchains {
					st.Lines = append(st.Lines, RuntimeLine{Name: "rust " + tc.Short(), Target: tc.Name,
						Version: tc.Installed, Latest: tc.Latest, Default: strings.Contains(tc.Installed, rt.Version)})
				}
			}
		}
		st.Drifted = len(Drifted(*inv, name, rc.NodeMajor))
		out = append(out, st)
	}
	return out
}

// pythonLines lists the newest uv-managed interpreter of each minor.
func pythonLines(m RuntimeMeta, current string) []RuntimeLine {
	best := map[string]string{}
	for _, in := range m.Installs {
		if !in.Managed {
			continue
		}
		minor := VersionLine(RuntimePython, in.Version)
		if cur, ok := best[minor]; !ok || newer(in.Version, cur) {
			best[minor] = in.Version
		}
	}
	minors := make([]string, 0, len(best))
	for k := range best {
		minors = append(minors, k)
	}
	sort.Slice(minors, func(i, j int) bool { return newer(minors[i]+".0", minors[j]+".0") })
	out := make([]RuntimeLine, 0, len(minors))
	for _, minor := range minors {
		out = append(out, RuntimeLine{Name: "python" + minor, Target: minor, Version: best[minor],
			Latest: m.Lines[minor], Default: minor == VersionLine(RuntimePython, current)})
	}
	return out
}

func runtimeOwner(env *exec.Env, name, path string, m RuntimeMeta) string {
	under := func(dir string) bool {
		return dir != "" && strings.HasPrefix(filepath.Clean(path), filepath.Clean(dir)+string(filepath.Separator))
	}
	switch {
	case path == "":
		return OwnerManual
	case name == RuntimePython && m.PythonDir != "" && under(m.PythonDir):
		return OwnerUv
	case name == RuntimeNode && env != nil && under(env.Get("PNPM_HOME")):
		return OwnerPnpm
	case name == RuntimeRust && env != nil && env.Which("rustup") != "" &&
		(under(env.Get("CARGO_HOME")) || under(filepath.Join(env.Home, ".cargo"))):
		return OwnerRustup
	case strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/bin/"):
		return OwnerSystem
	}
	return OwnerManual
}

// Drifted lists the packages of inv installed against a version of runtime
// other than the current one. pnpm records no node version per package, so
// node drift compares nodeMajor, the major its globals were last installed
// under, and then covers every global.
func Drifted(inv Inventory, runtime, nodeMajor string) []Package {
	if inv.Runtime == nil || inv.Runtime.Version == "" {
		return nil
	}
	current := inv.Runtime.Version
	var out []Package
	if runtime == RuntimeNode {
		if nodeMajor == "" || nodeMajor == VersionLine(RuntimeNode, current) {
			return nil
		}
		return append(out, inv.Packages...)
	}
	for _, p := range inv.Packages {
		if p.RuntimeVersion != "" && p.RuntimeVersion != current {
			out = append(out, p)
		}
	}
	return out
}

// RuntimePlanOptions select what a runtime update or migration covers.
type RuntimePlanOptions struct {
	// Names limits the plan to these runtimes; empty means all.
	Names []string
	// Major allows a new python minor or node major.
	Major bool
	// Rebuild adds the opt-in cargo and go rebuilds to a migration.
	Rebuild bool
	// Exclude lists packages never migrated (packages.update.exclude).
	Exclude []Ref
}

func (o RuntimePlanOptions) wants(name string) bool {
	return len(o.Names) == 0 || slices.Contains(o.Names, name)
}

// UnknownRuntimes returns the names that are not tracked runtimes.
func UnknownRuntimes(names []string) []string {
	var out []string
	for _, n := range names {
		if !slices.Contains(RuntimeNames, n) {
			out = append(out, n)
		}
	}
	return out
}

// PlanRuntimeUpdates plans updates of the runtimes themselves. A runtime's
// own line updates by default; a new python minor or node LTS major needs
// Major. rustup toolchains follow their channel and update one toolchain at
// a time. Runtimes owned by the system or installed by hand are listed with
// the reason they are skipped when they are behind or named.
func PlanRuntimeUpdates(sts []RuntimeStatus, o RuntimePlanOptions) Plan {
	var plan Plan
	for _, st := range sts {
		if !o.wants(st.Name) {
			continue
		}
		named := len(o.Names) > 0
		base := Planned{Kind: KindRuntime, Package: Package{Manager: st.Owner, Name: st.Name, Version: st.Version}}
		skip := func(reason string) {
			it := base
			it.Latest, it.Skip = firstNonEmpty(st.Newest, st.Latest), reason
			plan.Items = append(plan.Items, it)
		}
		switch {
		case st.Owner == OwnerSystem || st.Owner == OwnerManual:
			if named || st.Behind() || st.NewerLine() {
				if st.Owner == OwnerSystem {
					skip(fmt.Sprintf("installed by the system package manager (%s)", st.Path))
				} else {
					skip(fmt.Sprintf("installed outside a version manager audit knows (%s)", st.Path))
				}
			}
			continue
		case st.Error != "":
			skip("lookup failed: " + st.Error)
			continue
		case st.CheckedAt.IsZero():
			skip("latest version unknown; run audit packages runtimes")
			continue
		}
		before := len(plan.Items)
		switch st.Name {
		case RuntimePython:
			plan.Items = append(plan.Items, planPython(st, o)...)
		case RuntimeNode:
			if it, ok := planNode(st, o); ok {
				plan.Items = append(plan.Items, it)
			}
		case RuntimeRust:
			for _, l := range st.Lines {
				if !l.Behind() {
					continue
				}
				plan.Items = append(plan.Items, Planned{Kind: KindRuntime, Gap: GapUnknown,
					Package: Package{Manager: OwnerRustup, Name: l.Name, Version: l.Version},
					Latest:  l.Latest, Command: []string{"rustup", "update", l.Target}})
			}
		}
		if named && len(plan.Items) == before {
			skip("already at the latest release")
		}
	}
	return plan
}

// Behind reports whether the line has a newer release.
func (l RuntimeLine) Behind() bool {
	if l.Latest == "" {
		return false
	}
	if strings.HasPrefix(l.Name, "rust ") {
		return l.Latest != l.Version
	}
	return newer(l.Latest, l.Version)
}

func planPython(st RuntimeStatus, o RuntimePlanOptions) []Planned {
	var out []Planned
	for _, l := range st.Lines {
		if !l.Behind() {
			continue
		}
		out = append(out, Planned{Kind: KindRuntime, Gap: GapPatch,
			Package: Package{Manager: OwnerUv, Name: l.Name, Version: l.Version},
			Latest:  l.Latest, Command: []string{"uv", "python", "upgrade", l.Target}})
	}
	if !st.NewerLine() {
		return out
	}
	minor := VersionLine(RuntimePython, st.Newest)
	if slices.ContainsFunc(st.Lines, func(l RuntimeLine) bool { return l.Target == minor }) {
		return out
	}
	it := Planned{Kind: KindRuntime, Gap: GapMinor, Package: Package{Manager: OwnerUv, Name: "python" + minor},
		Latest: st.Newest, Command: []string{"uv", "python", "install", minor}}
	if !o.Major {
		it.Skip = "new minor release; pass --major to install it"
	}
	return append(out, it)
}

func planNode(st RuntimeStatus, o RuntimePlanOptions) (Planned, bool) {
	it := Planned{Kind: KindRuntime, Package: Package{Manager: OwnerPnpm, Name: RuntimeNode, Version: st.Version}}
	target := ""
	switch {
	case st.NewerLine() && o.Major:
		target, it.Gap = st.Newest, GapMajor
	case st.Behind():
		target, it.Gap = st.Latest, VersionGap("", st.Version, st.Latest)
	case st.NewerLine():
		it.Latest, it.Gap, it.Skip = st.Newest, GapMajor, "new LTS major; pass --major to switch to it"
		return it, true
	default:
		return it, false
	}
	it.Latest = target
	it.Command = []string{"pnpm", "runtime", "set", "node", target, "-g"}
	return it, true
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// PlanMigrations plans moving packages onto the current runtimes: uv tools
// reinstalled on the default python, pnpm globals reinstalled after a node
// major change, user gems reinstalled from another ruby's gem directory, and
// with Rebuild, cargo and go binaries rebuilt by the current toolchain.
// Latest holds the runtime version each package moves to.
func PlanMigrations(invs []Inventory, sts []RuntimeStatus, nodeMajor string, o RuntimePlanOptions) Plan {
	var plan Plan
	inv := func(manager string) *Inventory {
		for i := range invs {
			if invs[i].Manager == manager && invs[i].Available {
				return &invs[i]
			}
		}
		return nil
	}
	excluded := func(p Package) bool {
		return slices.ContainsFunc(o.Exclude, func(r Ref) bool { return r.Matches(p) })
	}
	for _, st := range sts {
		if !o.wants(st.Name) {
			continue
		}
		in := inv(st.Manager)
		if in == nil {
			continue
		}
		if st.Name == RuntimeRuby {
			plan.Items = append(plan.Items, planGemMigration(*in, st.Version)...)
			continue
		}
		rebuild := st.Name == RuntimeRust || st.Name == RuntimeGo
		seen := map[string]bool{}
		for _, p := range Drifted(*in, st.Name, nodeMajor) {
			it := Planned{Kind: KindMigration, Package: p, Latest: st.Version}
			if st.Name == RuntimeNode {
				it.Version = nodeMajor
			} else {
				it.Version = p.RuntimeVersion
			}
			it.Command = MigrateCommand(p, st.Version)
			if it.Command != nil {
				if seen[strings.Join(it.Command, " ")] {
					continue
				}
				seen[strings.Join(it.Command, " ")] = true
			}
			switch {
			case rebuild && !o.Rebuild:
				plan.Rebuildable++
				continue
			case excluded(p):
				it.Skip = "excluded by packages.update.exclude"
			case p.Manager == "go" && p.Version == "(devel)":
				it.Skip = "built from a local checkout (devel); rebuild it there"
			case p.Manager != "uv" && p.Registry() == "":
				it.Skip = fmt.Sprintf("installed from %s; reinstall it by hand", sourceOr(p.Source, "an unknown source"))
			case it.Command == nil:
				it.Skip = "no migration command for " + p.Manager
			}
			plan.Items = append(plan.Items, it)
		}
	}
	return plan
}

// MigrateCommand is the argv that reinstalls p on the runtime at version,
// nil when p's manager has none.
func MigrateCommand(p Package, version string) []string {
	switch p.Manager {
	case "uv":
		return []string{"uv", "tool", "upgrade", "--reinstall", "--python", VersionLine(RuntimePython, version), p.Name}
	case "pnpm":
		return []string{"pnpm", "add", "-g", "--force", p.Name + "@" + p.Version}
	case "cargo":
		return []string{"cargo", "install", "--locked", "--force", p.Name + "@" + p.Version}
	case "go":
		pkg := p.Source
		if pkg == "" {
			pkg = p.Ident
		}
		return []string{"go", "install", pkg + "@" + p.Version}
	case "gem":
		return []string{"gem", "install", "--user-install", p.Name, "-v", p.Version}
	}
	return nil
}

var gemspecRe = regexp.MustCompile(`^(.+)-(\d[^-]*)\.gemspec$`)

// OldGemDirs lists the user gem directories of other ruby ABIs next to the
// current one.
func OldGemDirs(inv Inventory) []string {
	if len(inv.BinDirs) == 0 {
		return nil
	}
	userDir := filepath.Dir(filepath.Clean(inv.BinDirs[0]))
	parent := filepath.Dir(userDir)
	es, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		d := filepath.Join(parent, e.Name())
		if e.Name() != filepath.Base(userDir) && isDir(d) {
			out = append(out, d)
		}
	}
	return out
}

// planGemMigration reinstalls the gems of old ABI directories that the
// current ruby does not have.
func planGemMigration(inv Inventory, rubyVersion string) []Planned {
	have := map[string]bool{}
	for _, p := range inv.Packages {
		have[p.Name] = true
	}
	var out []Planned
	for _, dir := range OldGemDirs(inv) {
		specs, _ := filepath.Glob(filepath.Join(dir, "specifications", "*.gemspec"))
		sort.Strings(specs)
		for _, spec := range specs {
			m := gemspecRe.FindStringSubmatch(filepath.Base(spec))
			if m == nil || have[m[1]] {
				continue
			}
			have[m[1]] = true
			p := Package{Manager: "gem", Name: m[1], Version: m[2], Runtime: RuntimeRuby, Source: "rubygems", Location: dir}
			it := Planned{Kind: KindMigration, Package: p, Latest: rubyVersion, Command: MigrateCommand(p, rubyVersion)}
			// The migration goes from the old ABI directory to the current ruby.
			it.Version = filepath.Base(dir)
			out = append(out, it)
		}
	}
	return out
}

// RuntimeVersions maps each updatable runtime install to its version, by
// owner and plan name, for verifying runtime updates.
func RuntimeVersions(sts []RuntimeStatus) map[string]string {
	out := map[string]string{}
	for _, st := range sts {
		out[st.Owner+"\x00"+st.Name] = st.Version
		for _, l := range st.Lines {
			out[st.Owner+"\x00"+l.Name] = l.Version
		}
	}
	return out
}

// VerifyRuntimes checks runtime updates against the runtimes after them,
// the way Verify checks packages.
func VerifyRuntimes(results []UpdateResult, after []RuntimeStatus) {
	now := RuntimeVersions(after)
	for i := range results {
		r := &results[i]
		if r.Status != UpdateOK || r.Kind != KindRuntime {
			continue
		}
		v, ok := now[r.Manager+"\x00"+r.Name]
		switch {
		case !ok:
			r.Status, r.Reason = UpdateFailed, "not installed after the update"
		case v == r.From:
			r.Status, r.Reason = UpdateFailed, "the command succeeded but the version is still "+r.From
		default:
			r.To = v
		}
	}
}

// VerifyMigrations checks migrations against an inventory taken after
// them: each package must still be installed, and a uv tool, cargo crate or
// go binary must now report the runtime it moved to.
func VerifyMigrations(results []UpdateResult, invs []Inventory) {
	now := map[string]Package{}
	for _, inv := range invs {
		for _, p := range inv.Packages {
			now[p.Manager+"\x00"+p.Name] = p
		}
	}
	for i := range results {
		r := &results[i]
		if r.Status != UpdateOK || r.Kind != KindMigration {
			continue
		}
		p, ok := now[r.Manager+"\x00"+r.Name]
		switch {
		case !ok:
			r.Status, r.Reason = UpdateFailed, "no longer installed after the migration"
		case p.RuntimeVersion != "" && r.Manager != "pnpm" && r.Manager != "gem" && p.RuntimeVersion != r.Latest:
			r.Status, r.Reason = UpdateFailed, "the command succeeded but it still runs on "+p.RuntimeVersion
		default:
			r.To = r.Latest
		}
	}
}

// SupersededPythons lists uv-managed interpreters that a newer patch of the
// same minor replaces and that no uv tool runs on.
func SupersededPythons(m RuntimeMeta, uvInv *Inventory) []string {
	used := map[string]bool{}
	if uvInv != nil {
		for _, p := range uvInv.Packages {
			used[p.RuntimeVersion] = true
		}
	}
	best := map[string]string{}
	for _, in := range m.Installs {
		if in.Managed {
			minor := VersionLine(RuntimePython, in.Version)
			if cur, ok := best[minor]; !ok || newer(in.Version, cur) {
				best[minor] = in.Version
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, in := range m.Installs {
		if !in.Managed || seen[in.Version] || used[in.Version] || best[VersionLine(RuntimePython, in.Version)] == in.Version {
			continue
		}
		seen[in.Version] = true
		out = append(out, in.Version)
	}
	sort.Strings(out)
	return out
}
