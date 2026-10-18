package packages

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

func TestParseUvPythonList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uv", "python")
	managed := filepath.Join(dir, "cpython-3.14.8-linux-x86_64-gnu", "bin", "python3.14")
	makeExe(t, managed, "")
	link := filepath.Join(t.TempDir(), "python3.14")
	if err := os.Symlink(managed, link); err != nil {
		t.Fatal(err)
	}
	out := `[
 {"version":"3.16.0a1","path":null,"implementation":"cpython","variant":"default"},
 {"version":"3.15.0","path":null,"implementation":"cpython","variant":"default"},
 {"version":"3.15.0","path":null,"implementation":"cpython","variant":"freethreaded"},
 {"version":"3.14.8","path":"` + link + `","implementation":"cpython","variant":"default"},
 {"version":"3.14.8","path":"` + managed + `","implementation":"cpython","variant":"default"},
 {"version":"3.13.16","path":null,"implementation":"cpython","variant":"default"},
 {"version":"3.13.7","path":"/usr/bin/python3.13","implementation":"cpython","variant":"default"},
 {"version":"3.11.10","path":null,"implementation":"pypy","variant":"default"}
]`
	lines, installs, err := ParseUvPythonList(out, dir, "/home/u")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines, map[string]string{"3.15": "3.15.0", "3.14": "3.14.8", "3.13": "3.13.16"}) {
		t.Errorf("lines skip prereleases, other variants and other implementations: %v", lines)
	}
	want := []PythonInstall{{Version: "3.14.8", Path: link, Managed: true}, {Version: "3.13.7", Path: "/usr/bin/python3.13"}}
	if !reflect.DeepEqual(installs, want) {
		t.Errorf("installs (a symlink to the same interpreter counts once):\n got %+v\nwant %+v", installs, want)
	}
	rel := `[{"version":"3.14.8","path":".local/bin/python3.14","implementation":"cpython","variant":"default"}]`
	if _, installs, _ := ParseUvPythonList(rel, "/home/u/.local", "/home/u"); len(installs) != 1 ||
		installs[0].Path != "/home/u/.local/bin/python3.14" || !installs[0].Managed {
		t.Errorf("a relative path is resolved against uv's working directory: %+v", installs)
	}
	if _, _, err := ParseUvPythonList("not json", dir, ""); err == nil {
		t.Error("bad output must fail")
	}
}

func TestParseReleaseLists(t *testing.T) {
	lines, lts, err := ParseNodeIndex([]byte(`[
		{"version":"v26.12.0","lts":false},{"version":"v26.11.1","lts":false},
		{"version":"v24.22.0","lts":"Krypton"},{"version":"v24.21.0","lts":"Krypton"},
		{"version":"v22.20.0","lts":"Jod"},{"version":"v27.0.0-rc.1","lts":false}]`))
	if err != nil || lts != "24.22.0" || !reflect.DeepEqual(lines, map[string]string{"26": "26.12.0", "24": "24.22.0", "22": "22.20.0"}) {
		t.Errorf("node: %v %q %v", lines, lts, err)
	}
	glines, newest, err := ParseGoReleases([]byte(`[{"version":"go1.27.2","stable":true},{"version":"go1.26.9","stable":true},
		{"version":"go1.28rc1","stable":false}]`))
	if err != nil || newest != "1.27.2" || !reflect.DeepEqual(glines, map[string]string{"1.27": "1.27.2", "1.26": "1.26.9"}) {
		t.Errorf("go: %v %q %v", glines, newest, err)
	}
	if _, _, err := ParseNodeIndex([]byte("<html>")); err == nil {
		t.Error("bad node index must fail")
	}
	if _, _, err := ParseGoReleases([]byte("{")); err == nil {
		t.Error("bad go list must fail")
	}
}

const rustupCheck = `stable-x86_64-unknown-linux-gnu - up to date: 1.99.1 (58cf8f9c3 2026-10-13)
nightly-x86_64-unknown-linux-gnu - update available: 1.101.0-nightly (7df81381d 2026-10-14) -> 1.101.0-nightly (8006091eb 2026-10-17)
1.90-x86_64-unknown-linux-gnu - up to date: 1.90.0 (1159e78c4 2025-09-14)
rustup - up to date : 1.29.1
`

func TestParseRustupCheck(t *testing.T) {
	tcs := ParseRustupCheck(rustupCheck)
	if len(tcs) != 3 {
		t.Fatalf("toolchains: %+v", tcs)
	}
	if tcs[0].Short() != "stable" || tcs[0].Behind() || tcs[0].Installed != "1.99.1 (58cf8f9c3 2026-10-13)" {
		t.Errorf("stable: %+v", tcs[0])
	}
	if tcs[1].Short() != "nightly" || !tcs[1].Behind() || tcs[1].Latest != "1.101.0-nightly (8006091eb 2026-10-17)" {
		t.Errorf("nightly: %+v", tcs[1])
	}
	if tcs[2].Short() != "1.90" {
		t.Errorf("pinned: %+v", tcs[2])
	}
}

func TestVersionLine(t *testing.T) {
	for _, c := range []struct{ rt, v, want string }{
		{RuntimePython, "3.14.8", "3.14"}, {RuntimeGo, "1.25.7", "1.25"}, {RuntimeNode, "v24.22.0", "24"}, {RuntimeRust, "1.99.1", "1.99.1"},
	} {
		if got := VersionLine(c.rt, c.v); got != c.want {
			t.Errorf("VersionLine(%s, %s) = %q", c.rt, c.v, got)
		}
	}
}

// runtimeFixture is a workstation with uv, pnpm, rustup, a system go and a
// system ruby.
func runtimeFixture(t *testing.T) ([]Inventory, RuntimeContext) {
	env, _, home := testEnv(t)
	pyDir := filepath.Join(home, ".local/share/uv/python")
	env.Vars["PNPM_HOME"] = filepath.Join(home, ".local/share/pnpm")
	makeExe(t, filepath.Join(home, "bin", "rustup"), "")
	setPath(env, filepath.Join(home, "bin"))
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	invs := []Inventory{
		{Manager: "uv", Available: true, Runtime: &Runtime{Name: "python", Version: "3.14.8",
			Path: filepath.Join(pyDir, "cpython-3.14-linux-x86_64-gnu/bin/python3.14")},
			Packages: []Package{
				{Manager: "uv", Name: "black", Version: "26.1", RuntimeVersion: "3.14.8", Source: "pypi"},
				{Manager: "uv", Name: "old", Version: "1.0", RuntimeVersion: "3.12.11", Source: "pypi"},
				{Manager: "uv", Name: "pinned", Version: "1.0", RuntimeVersion: "3.11.17", Source: "pypi"},
				{Manager: "uv", Name: "mine", Version: "0.1", RuntimeVersion: "3.12.11", Source: "path:/src/mine"},
			}},
		{Manager: "pnpm", Available: true, Runtime: &Runtime{Name: "node", Version: "24.22.0",
			Path: filepath.Join(home, ".local/share/pnpm/bin/node")},
			Packages: []Package{
				{Manager: "pnpm", Name: "eslint", Version: "9.0.0", Source: "npm"},
				{Manager: "pnpm", Name: "forked", Version: "1.0.0", Source: "git+https://x/y"},
			}},
		{Manager: "cargo", Available: true, Runtime: &Runtime{Name: "rust", Version: "1.99.1",
			Path: filepath.Join(home, ".cargo/bin/rustc")},
			Packages: []Package{
				{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", RuntimeVersion: "1.90.0", Source: "crates.io"},
			}},
		{Manager: "go", Available: true, Runtime: &Runtime{Name: "go", Version: "1.25.7", Path: "/usr/bin/go"},
			Packages: []Package{
				{Manager: "go", Name: "gopls", Version: "v0.20.0", RuntimeVersion: "1.24.0", Ident: "golang.org/x/tools/gopls",
					Source: "golang.org/x/tools/gopls"},
				{Manager: "go", Name: "dev", Version: "(devel)", RuntimeVersion: "1.24.0", Source: "example.com/dev"},
			}},
		{Manager: "gem", Available: true, Runtime: &Runtime{Name: "ruby", Version: "3.3.8", Path: "/usr/bin/ruby"}},
	}
	metas := map[string]RuntimeMeta{
		RuntimePython: {Name: RuntimePython, CheckedAt: now, PythonDir: pyDir, Newest: "3.15.0",
			Lines: map[string]string{"3.15": "3.15.0", "3.14": "3.14.8", "3.12": "3.12.15", "3.11": "3.11.17"},
			Installs: []PythonInstall{
				{Version: "3.14.8", Path: filepath.Join(pyDir, "cpython-3.14.8/bin/python3.14"), Managed: true},
				{Version: "3.12.11", Path: filepath.Join(pyDir, "cpython-3.12.11/bin/python3.12"), Managed: true},
				{Version: "3.11.17", Path: filepath.Join(pyDir, "cpython-3.11.17/bin/python3.11"), Managed: true},
				{Version: "3.13.7", Path: "/usr/bin/python3.13"},
			}},
		RuntimeNode: {Name: RuntimeNode, CheckedAt: now, Newest: "24.22.0", Lines: map[string]string{"24": "24.22.0", "26": "26.12.0"}},
		RuntimeRust: {Name: RuntimeRust, CheckedAt: now, Toolchains: ParseRustupCheck(rustupCheck)},
		RuntimeGo:   {Name: RuntimeGo, CheckedAt: now, Newest: "1.27.2", Lines: map[string]string{"1.25": "1.25.9", "1.27": "1.27.2"}},
	}
	return invs, RuntimeContext{Env: env, Meta: metas, NodeMajor: "24"}
}

func statusByName(sts []RuntimeStatus) map[string]RuntimeStatus {
	out := map[string]RuntimeStatus{}
	for _, st := range sts {
		out[st.Name] = st
	}
	return out
}

func TestRuntimeStatuses(t *testing.T) {
	invs, rc := runtimeFixture(t)
	sts := statusByName(RuntimeStatuses(invs, rc))
	if len(sts) != 5 {
		t.Fatalf("statuses: %+v", sts)
	}
	py := sts[RuntimePython]
	if py.Owner != OwnerUv || py.Latest != "3.14.8" || py.Newest != "3.15.0" || py.Drifted != 3 || !py.Behind() || !py.NewerLine() {
		t.Errorf("python: %+v", py)
	}
	wantLines := []RuntimeLine{
		{Name: "python3.14", Target: "3.14", Version: "3.14.8", Latest: "3.14.8", Default: true},
		{Name: "python3.12", Target: "3.12", Version: "3.12.11", Latest: "3.12.15"},
		{Name: "python3.11", Target: "3.11", Version: "3.11.17", Latest: "3.11.17"},
	}
	if !reflect.DeepEqual(py.Lines, wantLines) {
		t.Errorf("python lines (managed only, newest minor first):\n got %+v\nwant %+v", py.Lines, wantLines)
	}
	if n := sts[RuntimeNode]; n.Owner != OwnerPnpm || n.Drifted != 0 || n.Behind() || n.NewerLine() {
		t.Errorf("node at the newest LTS: %+v", n)
	}
	rs := sts[RuntimeRust]
	if rs.Owner != OwnerRustup || len(rs.Lines) != 3 || !rs.Lines[0].Default || rs.Lines[1].Default || !rs.Behind() || rs.Drifted != 1 {
		t.Errorf("rust: %+v", rs)
	}
	if g := sts[RuntimeGo]; g.Owner != OwnerSystem || g.Latest != "1.25.9" || !g.Behind() || !g.NewerLine() || g.Drifted != 2 {
		t.Errorf("go: %+v", g)
	}
	if r := sts[RuntimeRuby]; r.Owner != OwnerSystem || !r.CheckedAt.IsZero() {
		t.Errorf("ruby has no lookup: %+v", r)
	}

	rc.NodeMajor = "22"
	if n := statusByName(RuntimeStatuses(invs, rc))[RuntimeNode]; n.Drifted != 2 {
		t.Errorf("every global drifts after a node major change: %+v", n)
	}
	rc.Env.Vars["PNPM_HOME"] = "/elsewhere"
	if n := statusByName(RuntimeStatuses(invs, rc))[RuntimeNode]; n.Owner != OwnerManual {
		t.Errorf("node outside PNPM_HOME: %+v", n)
	}
}

func TestPlanRuntimeUpdates(t *testing.T) {
	invs, rc := runtimeFixture(t)
	sts := RuntimeStatuses(invs, rc)
	plan := PlanRuntimeUpdates(sts, RuntimePlanOptions{})
	want := map[string]string{
		"uv:python3.12":       "run",
		"uv:python3.15":       "new minor release; pass --major to install it",
		"rustup:rust nightly": "run",
		"system:go":           "installed by the system package manager (/usr/bin/go)",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v\nwant %v", got, want)
	}
	cmds := map[string]string{}
	for _, it := range plan.Items {
		cmds[it.Name] = strings.Join(it.Command, " ")
		if it.Kind != KindRuntime {
			t.Errorf("kind: %+v", it)
		}
	}
	if cmds["python3.12"] != "uv python upgrade 3.12" || cmds["rust nightly"] != "rustup update nightly-x86_64-unknown-linux-gnu" {
		t.Errorf("commands: %v", cmds)
	}

	plan = PlanRuntimeUpdates(sts, RuntimePlanOptions{Major: true, Names: []string{"python", "node", "ruby"}})
	want = map[string]string{
		"uv:python3.12": "run",
		"uv:python3.15": "run",
		"pnpm:node":     "already at the latest release",
		"system:ruby":   "installed by the system package manager (/usr/bin/ruby)",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("named with --major = %v\nwant %v", got, want)
	}
	for _, it := range plan.Items {
		if it.Name == "python3.15" && strings.Join(it.Command, " ") != "uv python install 3.15" {
			t.Errorf("new minor: %v", it.Command)
		}
	}
}

func TestPlanNodeUpdates(t *testing.T) {
	st := RuntimeStatus{Name: RuntimeNode, Owner: OwnerPnpm, Version: "24.20.0", Latest: "24.22.0", Newest: "26.2.0",
		CheckedAt: time.Now()}
	plan := PlanRuntimeUpdates([]RuntimeStatus{st}, RuntimePlanOptions{})
	if len(plan.Items) != 1 || strings.Join(plan.Items[0].Command, " ") != "pnpm runtime set node 24.22.0 -g" || plan.Items[0].Gap != GapMinor {
		t.Errorf("same major by default: %+v", plan.Items)
	}
	plan = PlanRuntimeUpdates([]RuntimeStatus{st}, RuntimePlanOptions{Major: true})
	if len(plan.Items) != 1 || strings.Join(plan.Items[0].Command, " ") != "pnpm runtime set node 26.2.0 -g" {
		t.Errorf("--major moves to the LTS: %+v", plan.Items)
	}
	st.Latest = st.Version
	plan = PlanRuntimeUpdates([]RuntimeStatus{st}, RuntimePlanOptions{})
	if len(plan.Items) != 1 || plan.Items[0].Skip != "new LTS major; pass --major to switch to it" {
		t.Errorf("current major, newer LTS: %+v", plan.Items)
	}
	for _, c := range []struct {
		st   RuntimeStatus
		skip string
	}{
		{RuntimeStatus{Name: RuntimeNode, Owner: OwnerPnpm, Version: "24.0.0", Error: "HTTP 503"}, "lookup failed: HTTP 503"},
		{RuntimeStatus{Name: RuntimeNode, Owner: OwnerPnpm, Version: "24.0.0"}, "latest version unknown; run audit packages runtimes"},
	} {
		plan := PlanRuntimeUpdates([]RuntimeStatus{c.st}, RuntimePlanOptions{})
		if len(plan.Items) != 1 || plan.Items[0].Skip != c.skip {
			t.Errorf("%+v: %+v", c.st, plan.Items)
		}
	}
	if plan := PlanRuntimeUpdates([]RuntimeStatus{{Name: RuntimeGo, Owner: OwnerSystem, Version: "1.25.7"}}, RuntimePlanOptions{}); len(plan.Items) != 0 {
		t.Errorf("a current system runtime is not listed unless named: %+v", plan.Items)
	}
}

func TestPlanMigrations(t *testing.T) {
	invs, rc := runtimeFixture(t)
	sts := RuntimeStatuses(invs, rc)
	plan := PlanMigrations(invs, sts, rc.NodeMajor, RuntimePlanOptions{Exclude: []Ref{ParseRef("uv:pinned")}})
	want := map[string]string{
		"uv:old":    "run",
		"uv:pinned": "excluded by packages.update.exclude",
		"uv:mine":   "run",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %v\nwant %v", got, want)
	}
	if plan.Rebuildable != 3 {
		t.Errorf("rebuildable = %d", plan.Rebuildable)
	}
	for _, it := range plan.Items {
		if it.Name == "old" && (strings.Join(it.Command, " ") != "uv tool upgrade --reinstall --python 3.14 old" ||
			it.Version != "3.12.11" || it.Latest != "3.14.8" || it.Kind != KindMigration) {
			t.Errorf("uv migration: %+v", it)
		}
	}

	plan = PlanMigrations(invs, sts, "22", RuntimePlanOptions{Names: []string{"node", "rust", "go"}, Rebuild: true})
	want = map[string]string{
		"pnpm:eslint":   "run",
		"pnpm:forked":   "installed from git+https://x/y; reinstall it by hand",
		"cargo:ripgrep": "run",
		"go:gopls":      "run",
		"go:dev":        "built from a local checkout (devel); rebuild it there",
	}
	if got := planSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("node major change with --rebuild = %v\nwant %v", got, want)
	}
	cmds := map[string]string{}
	for _, it := range plan.Items {
		cmds[it.Name] = strings.Join(it.Command, " ")
	}
	if cmds["eslint"] != "pnpm add -g --force eslint@9.0.0" || cmds["ripgrep"] != "cargo install --locked --force ripgrep@14.1.0" ||
		cmds["gopls"] != "go install golang.org/x/tools/gopls@v0.20.0" {
		t.Errorf("commands: %v", cmds)
	}
}

func TestPlanGemMigration(t *testing.T) {
	_, _, home := testEnv(t)
	root := filepath.Join(home, ".local/share/gem/ruby")
	writeFile(t, filepath.Join(root, "3.1.0/specifications/rubocop-1.60.0.gemspec"), "")
	writeFile(t, filepath.Join(root, "3.1.0/specifications/net-http-persistent-4.0.2.gemspec"), "")
	writeFile(t, filepath.Join(root, "3.1.0/specifications/have-1.0.gemspec"), "")
	mkdir(t, filepath.Join(root, "3.3.0/bin"))
	inv := Inventory{Manager: "gem", Available: true, BinDirs: []string{filepath.Join(root, "3.3.0/bin")},
		Runtime:  &Runtime{Name: "ruby", Version: "3.3.8", Path: "/usr/bin/ruby"},
		Packages: []Package{{Manager: "gem", Name: "have", Version: "1.0"}}}
	if got := OldGemDirs(inv); !reflect.DeepEqual(got, []string{filepath.Join(root, "3.1.0")}) {
		t.Errorf("old gem dirs: %v", got)
	}
	plan := PlanMigrations([]Inventory{inv}, []RuntimeStatus{{Name: RuntimeRuby, Manager: "gem", Version: "3.3.8"}}, "", RuntimePlanOptions{})
	if len(plan.Items) != 2 {
		t.Fatalf("items: %+v", plan.Items)
	}
	it := plan.Items[0]
	if it.Name != "net-http-persistent" || it.Version != "3.1.0" || it.Latest != "3.3.8" ||
		strings.Join(it.Command, " ") != "gem install --user-install net-http-persistent -v 4.0.2" {
		t.Errorf("gem migration: %+v", it)
	}
}

func TestVerifyRuntimesAndMigrations(t *testing.T) {
	rs := []UpdateResult{
		{Kind: KindRuntime, Manager: "uv", Name: "python3.12", From: "3.12.11", Status: UpdateOK},
		{Kind: KindRuntime, Manager: "uv", Name: "python3.15", Status: UpdateOK},
		{Kind: KindRuntime, Manager: "pnpm", Name: "node", From: "24.20.0", Status: UpdateOK},
		{Kind: KindRuntime, Manager: "rustup", Name: "rust nightly", From: "a", Status: UpdateFailed, Reason: "exit status 1"},
	}
	VerifyRuntimes(rs, []RuntimeStatus{
		{Name: RuntimePython, Owner: OwnerUv, Version: "3.14.8", Lines: []RuntimeLine{{Name: "python3.12", Version: "3.12.15"}}},
		{Name: RuntimeNode, Owner: OwnerPnpm, Version: "24.20.0"},
	})
	if rs[0].Status != UpdateOK || rs[0].To != "3.12.15" {
		t.Errorf("patched: %+v", rs[0])
	}
	if rs[1].Status != UpdateFailed || rs[1].Reason != "not installed after the update" {
		t.Errorf("missing install: %+v", rs[1])
	}
	if rs[2].Status != UpdateFailed || rs[2].Reason != "the command succeeded but the version is still 24.20.0" {
		t.Errorf("unchanged: %+v", rs[2])
	}
	if rs[3].Reason != "exit status 1" {
		t.Errorf("failures are left alone: %+v", rs[3])
	}

	ms := []UpdateResult{
		{Kind: KindMigration, Manager: "uv", Name: "moved", From: "3.12.11", Latest: "3.14.8", Status: UpdateOK},
		{Kind: KindMigration, Manager: "uv", Name: "stuck", From: "3.12.11", Latest: "3.14.8", Status: UpdateOK},
		{Kind: KindMigration, Manager: "pnpm", Name: "eslint", From: "22", Latest: "24.22.0", Status: UpdateOK},
		{Kind: KindMigration, Manager: "pnpm", Name: "gone", From: "22", Latest: "24.22.0", Status: UpdateOK},
	}
	VerifyMigrations(ms, []Inventory{
		{Manager: "uv", Packages: []Package{{Manager: "uv", Name: "moved", RuntimeVersion: "3.14.8"},
			{Manager: "uv", Name: "stuck", RuntimeVersion: "3.12.11"}}},
		{Manager: "pnpm", Packages: []Package{{Manager: "pnpm", Name: "eslint", RuntimeVersion: "24.22.0"}}},
	})
	if ms[0].Status != UpdateOK || ms[0].To != "3.14.8" {
		t.Errorf("moved: %+v", ms[0])
	}
	if ms[1].Status != UpdateFailed || ms[1].Reason != "the command succeeded but it still runs on 3.12.11" {
		t.Errorf("stuck: %+v", ms[1])
	}
	if ms[2].Status != UpdateOK || ms[3].Status != UpdateFailed || ms[3].Reason != "no longer installed after the migration" {
		t.Errorf("pnpm: %+v %+v", ms[2], ms[3])
	}
}

func TestSupersededPythons(t *testing.T) {
	m := RuntimeMeta{Installs: []PythonInstall{
		{Version: "3.14.9", Managed: true}, {Version: "3.14.8", Managed: true}, {Version: "3.14.7", Managed: true},
		{Version: "3.12.11", Managed: true}, {Version: "3.13.6", Path: "/usr/bin/python3.13"}, {Version: "3.13.5"},
	}}
	uv := &Inventory{Packages: []Package{{RuntimeVersion: "3.14.7"}}}
	if got := SupersededPythons(m, uv); !reflect.DeepEqual(got, []string{"3.14.8"}) {
		t.Errorf("superseded = %v", got)
	}
}

func TestRuntimeChecks(t *testing.T) {
	invs, rc := runtimeFixture(t)
	sts := RuntimeStatuses(invs, rc)
	s := &State{Ctx: ctx, Env: rc.Env, Inventories: invs, Runtimes: sts, NodeMajor: "22"}
	drift := map[string]finding.Finding{}
	for _, f := range finding.RunChecks(Command, s, Checks) {
		if f.Check == "runtime.drift" {
			drift[f.Subject] = f
		}
	}
	if f := drift["uv"]; f.Severity != finding.Notice || !strings.Contains(f.Hint, "audit packages runtimes migrate python") ||
		!reflect.DeepEqual(f.Details, []string{"3.11.17: pinned", "3.12.11: mine, old"}) {
		t.Errorf("uv drift: %+v", f)
	}
	if f := drift["pnpm"]; f.Severity != finding.Notice || f.Message != "2 pnpm global(s) were installed under node 22; node is now 24.22.0" {
		t.Errorf("pnpm drift: %+v", f)
	}
	if drift["cargo"].Severity != finding.Info || drift["go"].Severity != finding.Info {
		t.Errorf("cargo and go drift stay info: %+v %+v", drift["cargo"], drift["go"])
	}

	out := map[string]finding.Finding{}
	for _, f := range finding.RunChecks(Command, s, []finding.Check[*State]{{ID: "runtime.outdated", Fn: runtimeOutdated}}) {
		out[f.Subject] = f
	}
	if f := out["python"]; f.Severity != finding.Notice || f.Message != "python: 1 install(s) have a newer release; python 3.15.0 is the newest" ||
		!reflect.DeepEqual(f.Details, []string{"python3.12: 3.12.11 -> 3.12.15"}) {
		t.Errorf("python outdated: %+v", f)
	}
	if f := out["go"]; f.Severity != finding.Info || !strings.Contains(f.Hint, "the system package manager") ||
		f.Message != "go 1.25.7 -> 1.25.9 is available; go 1.27.2 is the newest" {
		t.Errorf("system go: %+v", f)
	}
	if f := out["rust"]; f.Severity != finding.Notice || len(f.Details) != 1 {
		t.Errorf("rust: %+v", f)
	}
	if _, ok := out["node"]; ok {
		t.Errorf("node is current: %+v", out["node"])
	}
	if _, ok := out["ruby"]; ok {
		t.Error("ruby has no release data")
	}
}
