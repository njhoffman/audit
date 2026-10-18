package packages

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

func analyze(env *exec.Env, invs []Inventory, scanDirs ...string) []finding.Finding {
	return Analyze(&State{Ctx: ctx, Env: env, Inventories: invs, ScanDirs: scanDirs})
}

func byCheck(fs []finding.Finding, check string) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func subjects(fs []finding.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Subject)
	}
	sort.Strings(out)
	return out
}

func inv(manager, binDir string, pkgs ...[2]string) Inventory {
	i := Inventory{Manager: manager, Available: true, BinDirs: []string{binDir}}
	for _, p := range pkgs {
		i.Packages = append(i.Packages, Package{Manager: manager, Name: p[0], Version: "1", Executables: strings.Fields(p[1])})
	}
	return i
}

func TestFindingsAreFiledAndSorted(t *testing.T) {
	env, _, home := testEnv(t)
	setPath(env, filepath.Join(home, "bin"))
	fs := analyze(env, []Inventory{
		{Manager: "uv", Available: true, Error: "boom"},
		{Manager: "cargo", Available: true, Runtime: &Runtime{Name: "rust", Version: "2"},
			Packages: []Package{{Name: "a", RuntimeVersion: "1"}}},
	})
	if len(fs) != 2 || fs[0].Check != "manager.error" || fs[1].Check != "runtime.drift" {
		t.Fatalf("got %+v", fs)
	}
	for _, f := range fs {
		if f.Command != Command || f.Kind != finding.Issue {
			t.Errorf("not filed: %+v", f)
		}
	}
	if fs[0].Message != "collecting uv failed: boom" {
		t.Errorf("message %q", fs[0].Message)
	}
}

func TestBinNotOnPath(t *testing.T) {
	env, _, home := testEnv(t)
	fs := byCheck(analyze(env, []Inventory{inv("gem", filepath.Join(home, "gems/bin"))}), "manager.bin_not_on_path")
	if len(fs) != 1 || fs[0].Subject != "gem" || fs[0].Severity != finding.Error {
		t.Errorf("got %+v", fs)
	}
	setPath(env, filepath.Join(home, "gems/bin/"))
	if fs := byCheck(analyze(env, []Inventory{inv("gem", filepath.Join(home, "gems/bin"))}), "manager.bin_not_on_path"); len(fs) != 0 {
		t.Errorf("trailing slash not normalized: %+v", fs)
	}
}

func TestMultipleInstallsDedupesSymlinkedDirs(t *testing.T) {
	env, _, home := testEnv(t)
	real := filepath.Join(home, "usr/bin")
	makeExe(t, filepath.Join(real, "node"), "")
	if err := os.Symlink(real, filepath.Join(home, "bin")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(home, "other")
	makeExe(t, filepath.Join(other, "node"), "")
	setPath(env, filepath.Join(home, "bin"), real)
	if fs := byCheck(analyze(env, nil), "manager.multiple_installs"); len(fs) != 0 {
		t.Errorf("got %+v", fs)
	}
	setPath(env, filepath.Join(home, "bin"), real, other)
	fs := byCheck(analyze(env, nil), "manager.multiple_installs")
	if len(fs) != 1 || fs[0].Subject != "node" ||
		!reflect.DeepEqual(fs[0].Details, []string{filepath.Join(home, "bin/node"), filepath.Join(other, "node")}) {
		t.Errorf("got %+v", fs)
	}
}

func TestExeShadowedByUnmanagedFile(t *testing.T) {
	env, _, home := testEnv(t)
	cargoBin, usr := filepath.Join(home, "cargo"), filepath.Join(home, "usr")
	makeExe(t, filepath.Join(cargoBin, "rg"), "")
	makeExe(t, filepath.Join(usr, "rg"), "")
	setPath(env, usr, cargoBin)
	fs := byCheck(analyze(env, []Inventory{inv("cargo", cargoBin, [2]string{"ripgrep", "rg"})}), "exe.shadowed")
	if len(fs) != 1 || fs[0].Subject != "rg" || !strings.Contains(fs[0].Message, filepath.Join(usr, "rg")) ||
		!strings.Contains(fs[0].Message, "cargo:ripgrep") {
		t.Errorf("got %+v", fs)
	}
}

func TestExeConflictBetweenManagers(t *testing.T) {
	env, _, home := testEnv(t)
	goBin, pnpmBin := filepath.Join(home, "go"), filepath.Join(home, "pnpm")
	makeExe(t, filepath.Join(goBin, "jira"), "")
	makeExe(t, filepath.Join(pnpmBin, "jira"), "")
	setPath(env, pnpmBin, goBin)
	fs := byCheck(analyze(env, []Inventory{
		inv("go", goBin, [2]string{"jira", "jira"}),
		inv("pnpm", pnpmBin, [2]string{"jira-cli", "jira"}),
	}), "exe.conflict")
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "go:jira") || !strings.Contains(fs[0].Message, "PATH runs pnpm:jira-cli") {
		t.Errorf("got %+v", fs)
	}
}

func TestExeConflictWithinManager(t *testing.T) {
	env, _, home := testEnv(t)
	b := filepath.Join(home, "pnpm")
	makeExe(t, filepath.Join(b, "tsc"), "")
	setPath(env, b)
	fs := byCheck(analyze(env, []Inventory{inv("pnpm", b, [2]string{"tsc", "tsc"}, [2]string{"typescript", "tsc"})}), "exe.conflict")
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "2 packages") {
		t.Errorf("got %+v", fs)
	}
}

func TestExeMissing(t *testing.T) {
	env, _, home := testEnv(t)
	b := filepath.Join(home, "uvbin")
	mkdir(t, b)
	setPath(env, b)
	fs := byCheck(analyze(env, []Inventory{inv("uv", b, [2]string{"neovim-remote", "nvr"})}), "exe.missing")
	if len(fs) != 1 || fs[0].Subject != "uv:nvr" {
		t.Errorf("got %+v", fs)
	}
}

func TestExeChecksSkipManagersOffPathAndGh(t *testing.T) {
	env, _, home := testEnv(t)
	b := filepath.Join(home, "gembin")
	mkdir(t, b)
	setPath(env, filepath.Join(home, "bin"))
	fs := analyze(env, []Inventory{
		inv("gem", b, [2]string{"rake", "rake"}),
		{Manager: "gh", Available: true, Packages: []Package{{Name: "dash", Executables: []string{"gh dash"}}}},
	})
	if got := byCheck(fs, "exe.missing"); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestExeBroken(t *testing.T) {
	env, _, home := testEnv(t)
	b := filepath.Join(home, "local")
	mkdir(t, b)
	if err := os.Symlink(filepath.Join(home, "nowhere"), filepath.Join(b, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(makeExe(t, filepath.Join(home, "real"), ""), filepath.Join(b, "goodlink")); err != nil {
		t.Fatal(err)
	}
	makeExe(t, filepath.Join(b, "oldpy"), "#!"+home+"/gone/python3\n")
	makeExe(t, filepath.Join(b, "envscript"), "#!/usr/bin/env definitely-not-here-xyz\n")
	makeExe(t, filepath.Join(b, "envflag"), "#!/usr/bin/env -S node --flag\n")
	makeExe(t, filepath.Join(b, "envnoarg"), "#!/usr/bin/env\nnext-line-is-not-an-arg\n")
	makeExe(t, filepath.Join(b, "fine"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(b, "binary"), "\x7fELF\x00\x00")
	mkdir(t, filepath.Join(b, "subdir"))
	setPath(env, filepath.Join(home, "bin"))
	fs := byCheck(analyze(env, nil, b), "exe.broken")
	var names []string
	for _, f := range fs {
		names = append(names, filepath.Base(f.Subject))
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"dangling", "envscript", "oldpy"}) {
		t.Errorf("got %v", names)
	}
	for _, f := range fs {
		if filepath.Base(f.Subject) == "envscript" && !strings.Contains(f.Message, "(via env)") {
			t.Errorf("message %q", f.Message)
		}
	}
}

func TestExeBrokenExpandsScanDirs(t *testing.T) {
	env, _, home := testEnv(t)
	b := filepath.Join(home, ".local", "bin")
	makeExe(t, filepath.Join(b, "oldpy"), "#!/gone/python3\n")
	if fs := byCheck(analyze(env, nil, "~/.local/bin"), "exe.broken"); len(fs) != 1 {
		t.Errorf("got %+v", fs)
	}
}

func TestPnpmLegacyShims(t *testing.T) {
	env, _, home := testEnv(t)
	root := filepath.Join(home, "pnpm")
	shim := func(node string) string {
		return "#!/bin/sh\nbasedir=$(dirname \"$0\")\n\"" + node + "\"  \"$basedir/global/5/x.js\" \"$@\"\n"
	}
	makeExe(t, filepath.Join(root, "bin", "eslint"), "")
	makeExe(t, filepath.Join(root, "eslint"), shim("$basedir/node"))
	makeExe(t, filepath.Join(root, "codex"), shim(root+"/node"))
	makeExe(t, filepath.Join(root, "pnpm"), shim("$basedir/node"))
	makeExe(t, filepath.Join(root, "codex.cmd"), shim("$basedir/node"))
	makeExe(t, filepath.Join(root, "unrelated"), "#!/bin/sh\necho hi\n")
	env.Vars["PNPM_HOME"] = root
	setPath(env, filepath.Join(root, "bin"), root)
	invs := []Inventory{{Manager: "pnpm", Available: true, BinDirs: []string{filepath.Join(root, "bin")}}}
	fs := byCheck(analyze(env, invs), "pnpm.legacy_shim")
	var stale, broken []finding.Finding
	for _, f := range fs {
		if f.Subject == "stale" {
			stale = append(stale, f)
		} else {
			broken = append(broken, f)
		}
	}
	if len(stale) != 1 || !reflect.DeepEqual(stale[0].Details, []string{"eslint"}) || stale[0].Severity != finding.Info {
		t.Errorf("stale = %+v", stale)
	}
	if len(broken) != 1 || broken[0].Subject != "codex" || broken[0].Severity != finding.Error {
		t.Errorf("broken = %+v", broken)
	}
	makeExe(t, filepath.Join(root, "node"), "")
	if got := subjects(byCheck(analyze(env, invs), "pnpm.legacy_shim")); !reflect.DeepEqual(got, []string{"stale"}) {
		t.Errorf("after node exists: %v", got)
	}
}

func TestPnpmLegacyShimsNeedPnpmAndHome(t *testing.T) {
	env, _, home := testEnv(t)
	env.Vars["PNPM_HOME"] = filepath.Join(home, "missing")
	invs := []Inventory{{Manager: "pnpm", Available: true}}
	if fs := byCheck(analyze(env, invs), "pnpm.legacy_shim"); len(fs) != 0 {
		t.Errorf("got %+v", fs)
	}
}

func TestRuntimeDrift(t *testing.T) {
	env, _, _ := testEnv(t)
	invs := []Inventory{{Manager: "cargo", Available: true, Runtime: &Runtime{Name: "rust", Version: "1.101.0"},
		Packages: []Package{
			{Name: "a", RuntimeVersion: "1.90.0"},
			{Name: "b", RuntimeVersion: "1.101.0"},
			{Name: "c"},
			{Name: "d", RuntimeVersion: "1.90.0"},
		}}}
	fs := byCheck(analyze(env, invs), "runtime.drift")
	if len(fs) != 1 || fs[0].Subject != "cargo" || !reflect.DeepEqual(fs[0].Details, []string{"1.90.0: a, d"}) ||
		fs[0].Severity != finding.Info || !strings.HasPrefix(fs[0].Message, "2 cargo package(s)") {
		t.Errorf("got %+v", fs)
	}
}

func TestStaleGemAndPythonDirs(t *testing.T) {
	env, _, home := testEnv(t)
	gemRoot := filepath.Join(home, ".local/share/gem/ruby")
	mkdir(t, filepath.Join(gemRoot, "3.3.0/bin"))
	mkdir(t, filepath.Join(gemRoot, "3.2.0"))
	mkdir(t, filepath.Join(home, ".local/lib/python3.10"))
	mkdir(t, filepath.Join(home, ".local/lib/python3.14"))
	makeExe(t, filepath.Join(home, "bin", "python3.14"), "")
	setPath(env, filepath.Join(home, "bin"))
	invs := []Inventory{{Manager: "gem", Available: true, BinDirs: []string{filepath.Join(gemRoot, "3.3.0/bin")}}}
	got := subjects(byCheck(analyze(env, invs), "runtime.stale_dirs"))
	want := []string{filepath.Join(gemRoot, "3.2.0"), filepath.Join(home, ".local/lib/python3.10")}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestNpmStrayGlobals(t *testing.T) {
	env, fake, home := testEnv(t)
	prefix := filepath.Join(home, "npm-global")
	mods := filepath.Join(prefix, "lib/node_modules")
	for _, n := range []string{"npm", "corepack", "left-pad", "@scope/thing", ".bin"} {
		mkdir(t, filepath.Join(mods, n))
	}
	addBin(t, home, "npm")
	fake.AddOutput(prefix+"\n", "npm", "config", "get", "prefix")
	fs := byCheck(analyze(env, nil), "npm.stray_globals")
	if len(fs) != 1 || !reflect.DeepEqual(fs[0].Details, []string{"@scope/thing", "left-pad"}) {
		t.Errorf("got %+v", fs)
	}
}

func TestNpmStrayGlobalsSkippedWithoutNpm(t *testing.T) {
	env, fake, _ := testEnv(t)
	if fs := byCheck(analyze(env, nil), "npm.stray_globals"); len(fs) != 0 {
		t.Errorf("got %+v", fs)
	}
	for _, c := range fake.Calls {
		if c[0] == "npm" {
			t.Errorf("npm was run: %v", c)
		}
	}
}
