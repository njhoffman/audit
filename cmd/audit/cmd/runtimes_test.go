package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// fakeUv plays uv for a scan, runtime updates and migrations: tools live in
// a real tool directory (the scan reads their pyvenv.cfg), interpreters in
// a table.
type fakeUv struct {
	mu      sync.Mutex
	toolDir string
	pyDir   string
	// pythons maps each installed minor to its patch version.
	pythons map[string]string
	// tools maps each tool to the python version it runs on.
	tools map[string]string
	calls []string
	fail  map[string]bool
}

func (f *fakeUv) python(minor string) string {
	return filepath.Join(f.pyDir, "cpython-"+minor+"-linux-x86_64-gnu", "bin", "python"+minor)
}

func (f *fakeUv) defaultMinor() string {
	best := ""
	for m := range f.pythons {
		if best == "" || packages.VersionGap("", best+".0", m+".0") == packages.GapMinor {
			best = m
		}
	}
	return best
}

func (f *fakeUv) writeTool(name, version string) error {
	dir := filepath.Join(f.toolDir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte("version_info = "+version+"\n"), 0o600)
}

func (f *fakeUv) Run(_ context.Context, name string, args []string, _ exec.Options) exec.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := filepath.Base(name) + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.fail[cmd] {
		return exec.Result{Code: 1, Stderr: "error: " + cmd + " failed\n"}
	}
	switch {
	case cmd == "uv --version":
		return exec.Result{Stdout: "uv 0.13.1\n"}
	case cmd == "uv tool dir":
		return exec.Result{Stdout: f.toolDir + "\n"}
	case cmd == "uv tool dir --bin":
		return exec.Result{Stdout: filepath.Join(f.toolDir, "bin") + "\n"}
	case cmd == "uv python find --no-project":
		return exec.Result{Stdout: f.python(f.defaultMinor()) + "\n"}
	case strings.HasPrefix(filepath.Base(name), "python") && cmd == filepath.Base(name)+" --version":
		minor := strings.TrimPrefix(filepath.Base(name), "python")
		return exec.Result{Stdout: "Python " + f.pythons[minor] + "\n"}
	case cmd == "uv tool list":
		names := make([]string, 0, len(f.tools))
		for n := range f.tools {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			fmt.Fprintf(&b, "%s v1.0\n- %s\n", n, n)
		}
		return exec.Result{Stdout: b.String()}
	case strings.HasPrefix(cmd, "uv python upgrade "):
		minor := args[2]
		f.pythons[minor] = minor + ".99"
		return exec.Result{}
	case strings.HasPrefix(cmd, "gio trash "):
		if err := os.RemoveAll(args[1]); err != nil {
			return exec.Result{Code: 1, Stderr: err.Error()}
		}
		return exec.Result{}
	case strings.HasPrefix(cmd, "uv python uninstall "):
		return exec.Result{}
	case strings.HasPrefix(cmd, "uv python install "):
		f.pythons[args[2]] = args[2] + ".0"
		return exec.Result{}
	case strings.HasPrefix(cmd, "uv tool upgrade --reinstall --python "):
		minor, tool := args[4], args[5]
		f.tools[tool] = f.pythons[minor]
		if err := f.writeTool(tool, f.pythons[minor]); err != nil {
			return exec.Result{Code: 1, Stderr: err.Error()}
		}
		return exec.Result{}
	}
	return exec.Result{Code: exec.ExitNotFound, Stderr: name + ": command not found"}
}

// LookupRuntime answers python from the fake's table; uv offers 3.12.99
// for 3.12 and 3.15.0 as the newest minor.
func (f *fakeUv) LookupRuntime(_ context.Context, name string) (packages.RuntimeMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != packages.RuntimePython {
		return packages.RuntimeMeta{Name: name, Lines: map[string]string{}}, nil
	}
	m := packages.RuntimeMeta{Name: name, PythonDir: f.pyDir, Newest: "3.15.0",
		Lines: map[string]string{"3.15": "3.15.0", "3.14": "3.14.8", "3.12": "3.12.99"}}
	for minor, v := range f.pythons {
		m.Installs = append(m.Installs, packages.PythonInstall{Version: v, Path: f.python(minor), Managed: true})
	}
	return m, nil
}

// uvEnv configures a uv-only, process-environment scan over fakeUv: the
// default python is 3.14.8, black runs on it, old on 3.12.11.
func uvEnv(t *testing.T) *fakeUv {
	t.Helper()
	cfgHome, _ := env(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "uv"), []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	// The stale-directory checks look under $HOME.
	t.Setenv("HOME", t.TempDir())
	cfg := "packages: {env: process, managers: [uv], scan_dirs: []}\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	f := &fakeUv{toolDir: filepath.Join(root, "tools"), pyDir: filepath.Join(root, "python"),
		pythons: map[string]string{"3.14": "3.14.8", "3.12": "3.12.11"},
		tools:   map[string]string{"black": "3.14.8", "old": "3.12.11"}, fail: map[string]bool{}}
	for n, v := range f.tools {
		if err := f.writeTool(n, v); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func runRuntimes(t *testing.T, uv *fakeUv, interactive bool, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return interactive }
	a.in = strings.NewReader(stdin)
	a.runner, a.rtLooker = uv, uv
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	a.close()
	return result{out.String(), errOut.String(), e, a}
}

func TestRuntimesList(t *testing.T) {
	uv := uvEnv(t)
	r := runRuntimes(t, uv, false, "", "packages", "runtimes")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"python", "3.14.8", "uv", "3.15.0", "1 uv package(s) on another version", "python3.12", "3.12.99", "default"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("list missing %q:\n%s", want, r.out)
		}
	}
	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "-j")
	var sts []packages.RuntimeStatus
	if r.e != nil || json.Unmarshal([]byte(r.out), &sts) != nil || len(sts) != 1 || sts[0].Drifted != 1 {
		t.Errorf("json: %v %q", r.e, r.out)
	}
	// The saved packages run carries the runtimes and their tasks.
	r = runRuntimes(t, uv, false, "", "packages", "-l")
	if !strings.Contains(r.out, "runtime.outdated") || !strings.Contains(r.out, "runtime.drift") {
		t.Errorf("packages report should show runtime findings:\n%s", r.out)
	}
	if r := runRuntimes(t, uv, false, "", "packages", "runtimes", "update", "-N", "perl"); r.e == nil ||
		!strings.Contains(r.e.Error(), "unknown runtime perl") {
		t.Errorf("unknown runtime: %v", r.e)
	}
}

func TestRuntimesUpdate(t *testing.T) {
	uv := uvEnv(t)
	r := runRuntimes(t, uv, false, "", "packages", "runtimes", "update", "-N")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"uv:python3.12", "uv python upgrade 3.12", "uv:python3.15",
		"skip: new minor release; pass --major to install it", "1 to update, 1 skipped."} {
		if !strings.Contains(r.out, want) {
			t.Errorf("dry run missing %q:\n%s", want, r.out)
		}
	}
	if r := runRuntimes(t, uv, false, "", "packages", "runtimes", "update"); r.e == nil ||
		!strings.Contains(r.e.Error(), "refusing to update without --yes") {
		t.Errorf("no terminal: %v", r.e)
	}

	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "update", "-y", "-m")
	if r.e != nil {
		t.Fatal(r.e, r.out, r.err)
	}
	if !strings.Contains(r.out, "2 updated, 0 failed, 0 skipped") ||
		!strings.Contains(r.out, "`audit packages runtimes migrate python` moves them") {
		t.Errorf("update with --major:\n%s", r.out)
	}
	if uv.pythons["3.12"] != "3.12.99" || uv.pythons["3.15"] != "3.15.0" {
		t.Errorf("pythons: %v", uv.pythons)
	}

	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "update", "-L", "-j")
	var u packages.Update
	if r.e != nil || json.Unmarshal([]byte(r.out), &u) != nil || len(u.Items) != 2 || u.Items[0].Kind != packages.KindRuntime ||
		u.Items[0].To != "3.12.99" {
		t.Errorf("--last: %v %q", r.e, r.out)
	}
	if r := runRuntimes(t, uv, false, "", "packages", "update", "-L"); !strings.Contains(r.out, "Nothing has been updated yet.") {
		t.Errorf("packages update --last ignores runtime updates:\n%s", r.out)
	}
}

func TestRuntimesUpdateVerifies(t *testing.T) {
	uv := uvEnv(t)
	uv.fail["uv python upgrade 3.12"] = true
	r := runRuntimes(t, uv, false, "", "packages", "runtimes", "update", "-y")
	if r.e == nil || r.e.Error() != "1 runtime update(s) failed" ||
		!strings.Contains(r.out, "FAILED uv:python3.12 3.12.11 -> 3.12.99: exit status 1: error: uv python upgrade 3.12 failed") {
		t.Errorf("failed update: %v\n%s", r.e, r.out)
	}
}

func TestRuntimesMigrate(t *testing.T) {
	uv := uvEnv(t)
	r := runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-N")
	if r.e != nil || !strings.Contains(r.out, "uv tool upgrade --reinstall --python 3.14 old") || strings.Contains(r.out, "uv:black") ||
		!strings.Contains(r.out, "MOVES TO") {
		t.Fatalf("dry run: %v\n%s", r.e, r.out)
	}
	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-y")
	if r.e != nil || !strings.Contains(r.out, "1 updated, 0 failed, 0 skipped") || uv.tools["old"] != "3.14.8" {
		t.Fatalf("migrate: %v %v\n%s\n%s", r.e, uv.tools, r.out, r.err)
	}
	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-N")
	if r.e != nil || !strings.Contains(r.out, "Nothing to migrate.") {
		t.Errorf("after migrating: %v\n%s", r.e, r.out)
	}

	// A new patch of 3.14 leaves 3.14.8 unused once the tools move.
	uv.pythons["3.14"] = "3.14.9"
	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-y")
	if r.e != nil || uv.tools["black"] != "3.14.9" {
		t.Fatalf("patch migration: %v %v\n%s", r.e, uv.tools, r.out)
	}
}

func TestRuntimesMigrateCleanup(t *testing.T) {
	uv := uvEnv(t)
	looker := &supersededLooker{fakeUv: uv, extra: packages.PythonInstall{Version: "3.14.8", Managed: true}}
	uv.pythons["3.14"] = "3.14.9"
	uv.tools["black"], uv.tools["old"] = "3.14.9", "3.14.9"
	for n, v := range uv.tools {
		if err := uv.writeTool(n, v); err != nil {
			t.Fatal(err)
		}
	}
	run := func(interactive bool, stdin string, args ...string) result {
		t.Helper()
		var out, errOut bytes.Buffer
		a := newApp(&out, &errOut)
		a.interactive = func() bool { return interactive }
		a.in = strings.NewReader(stdin)
		a.runner, a.rtLooker = uv, looker
		root := newRootCmd(a)
		root.SetArgs(args)
		e := root.ExecuteContext(context.Background())
		a.close()
		return result{out.String(), errOut.String(), e, a}
	}
	r := run(false, "", "packages", "runtimes", "migrate", "-y")
	if r.e != nil || !strings.Contains(r.out, "uv python uninstall 3.14.8") || !strings.Contains(r.out, "Kept 1 item(s); pass --prune") {
		t.Errorf("--yes keeps leftovers: %v\n%s", r.e, r.out)
	}
	r = run(true, "n\n", "packages", "runtimes", "migrate")
	if r.e != nil || !strings.Contains(r.err, "Remove 1 item(s)? [y/N]") || looker.removed {
		t.Errorf("declined: %v %q", r.e, r.err)
	}
	r = run(false, "", "packages", "runtimes", "migrate", "-y", "-P")
	if r.e != nil || !looker.removed || !strings.Contains(r.out, "1 updated, 0 failed, 0 skipped") {
		t.Errorf("--prune: %v %v\n%s", r.e, uv.calls, r.out)
	}
}

// supersededLooker reports an extra interpreter until uv uninstalls it.
type supersededLooker struct {
	*fakeUv
	extra   packages.PythonInstall
	removed bool
}

func (l *supersededLooker) LookupRuntime(ctx context.Context, name string) (packages.RuntimeMeta, error) {
	m, err := l.fakeUv.LookupRuntime(ctx, name)
	l.mu.Lock()
	for _, c := range l.calls {
		if c == "uv python uninstall "+l.extra.Version {
			l.removed = true
		}
	}
	l.mu.Unlock()
	if name == packages.RuntimePython && !l.removed {
		m.Installs = append(m.Installs, l.extra)
	}
	return m, err
}

func TestNodeMajorRemembered(t *testing.T) {
	uvEnv(t)
	a, _, _ := loadedApp(t)
	ctx := context.Background()
	s, err := a.packagesScanner(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.engine.Execute(ctx, s, a.progress(false)); err != nil {
		t.Fatal(err)
	}
	if v, _ := a.store.Setting(ctx, core.NodeMajorSetting); v != "" {
		t.Errorf("no pnpm, nothing remembered: %q", v)
	}
	u := &packages.Update{Items: []packages.UpdateResult{
		{Kind: packages.KindMigration, Manager: "pnpm", Name: "eslint", Status: packages.UpdateOK}}}
	a.rememberNodeMajor(ctx, u, packages.Data{Runtimes: []packages.RuntimeStatus{{Name: "node", Version: "26.1.0"}}})
	if v, _ := a.store.Setting(ctx, core.NodeMajorSetting); v != "26" {
		t.Errorf("after a clean node migration: %q", v)
	}
	u.Items = append(u.Items, packages.UpdateResult{Kind: packages.KindMigration, Manager: "pnpm", Name: "bad", Status: packages.UpdateFailed})
	a.rememberNodeMajor(ctx, u, packages.Data{Runtimes: []packages.RuntimeStatus{{Name: "node", Version: "28.0.0"}}})
	if v, _ := a.store.Setting(ctx, core.NodeMajorSetting); v != "26" {
		t.Errorf("a failed global keeps the old major: %q", v)
	}
}

func TestRuntimesMigrateTrash(t *testing.T) {
	uv := uvEnv(t)
	uv.tools["old"] = "3.14.8"
	if err := uv.writeTool("old", "3.14.8"); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(os.Getenv("HOME"), ".local", "lib", "python3.10")
	if err := os.MkdirAll(stale, 0o750); err != nil {
		t.Fatal(err)
	}
	gio := filepath.Join(os.Getenv("PATH"), "gio")
	if err := os.WriteFile(gio, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	r := runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-y")
	if r.e != nil || !strings.Contains(r.out, "gio trash "+stale) || !strings.Contains(r.out, "Kept 1 item(s)") {
		t.Fatalf("listed and kept: %v\n%s", r.e, r.out)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("kept without --prune")
	}
	r = runRuntimes(t, uv, false, "", "packages", "runtimes", "migrate", "-y", "-P")
	if _, err := os.Stat(stale); r.e != nil || !os.IsNotExist(err) || !strings.Contains(r.out, "1 updated, 0 failed") {
		t.Errorf("--prune trashes it: %v %v\n%s", r.e, err, r.out)
	}
}
