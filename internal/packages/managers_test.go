package packages

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

var ctx = context.Background()

func addBin(t *testing.T, home, name string) {
	t.Helper()
	makeExe(t, filepath.Join(home, "bin", name), "")
}

func TestUnavailableManager(t *testing.T) {
	env, _, _ := testEnv(t)
	inv := Collect(ctx, env, Cargo{})
	if inv.Available || len(inv.Packages) != 0 || inv.Error != "" {
		t.Errorf("got %+v", inv)
	}
}

func TestCollectErrorIsCaptured(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "uv")
	fake.Add([]string{"uv", "tool", "list"}, exec.Result{Code: 2, Stderr: "boom"})
	inv := Collect(ctx, env, Uv{})
	if !inv.Available || !strings.Contains(inv.Error, "boom") {
		t.Errorf("got %+v", inv)
	}
}

type panicky struct{ Gh }

func (panicky) Collect(context.Context, *exec.Env) ([]Package, error) { panic("division by zero") }

func TestPanicIsCaptured(t *testing.T) {
	env, _, home := testEnv(t)
	addBin(t, home, "gh")
	inv := Collect(ctx, env, panicky{})
	if inv.Error != "panic: division by zero" {
		t.Errorf("error = %q", inv.Error)
	}
}

func TestUvInventory(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "uv")
	tools := filepath.Join(home, "tools")
	writeFile(t, filepath.Join(tools, "black", "pyvenv.cfg"), "version_info = 3.12.1\n")
	writeFile(t, filepath.Join(tools, "black", "uv-receipt.toml"),
		"[tool]\nrequirements = [{ name = \"black\", git = \"https://g/black\" }]\n")
	writeFile(t, filepath.Join(tools, "bad", "uv-receipt.toml"), "[tool\n")
	fake.AddOutput("black v24.1.0\n- black\nbad v1.0\n", "uv", "tool", "list")
	fake.AddOutput(tools+"\n", "uv", "tool", "dir")
	fake.AddOutput(home+"/.local/bin\n", "uv", "tool", "dir", "--bin")
	fake.AddOutput("/py/bin/python3\n", "uv", "python", "find")
	fake.AddOutput("Python 3.14.8\n", "/py/bin/python3", "--version")
	fake.AddOutput("uv 0.13.1\n", "uv", "--version")
	inv := Collect(ctx, env, Uv{})
	if inv.Error != "" {
		t.Fatal(inv.Error)
	}
	if inv.ManagerVersion != "0.13.1" || inv.Runtime.Version != "3.14.8" {
		t.Errorf("versions: %q %+v", inv.ManagerVersion, inv.Runtime)
	}
	if !reflect.DeepEqual(inv.BinDirs, []string{home + "/.local/bin"}) {
		t.Errorf("bin dirs %v", inv.BinDirs)
	}
	if len(inv.Packages) != 2 {
		t.Fatalf("packages %+v", inv.Packages)
	}
	bad, black := inv.Packages[0], inv.Packages[1]
	if black.Name != "black" || black.Version != "24.1.0" || black.RuntimeVersion != "3.12.1" ||
		black.Source != "git:https://g/black" || !reflect.DeepEqual(black.Executables, []string{"black"}) {
		t.Errorf("black = %+v", black)
	}
	if bad.Source != "unknown" {
		t.Errorf("malformed receipt source = %q", bad.Source)
	}
}

func TestUvRuntimeIgnoresActiveVenv(t *testing.T) {
	env, fake, _ := testEnv(t)
	env.Vars["VIRTUAL_ENV"] = "/some/venv"
	fake.AddOutput("/py\n", "uv", "python", "find")
	Uv{}.Runtime(ctx, env)
	if !reflect.DeepEqual(fake.CallOpts[0].Unset, []string{"VIRTUAL_ENV"}) {
		t.Errorf("opts = %+v", fake.CallOpts[0])
	}
	if env.Vars["VIRTUAL_ENV"] != "/some/venv" {
		t.Error("caller env was modified")
	}
}

func TestUvToolDirFallback(t *testing.T) {
	env, _, home := testEnv(t)
	if got := (Uv{}).toolDir(ctx, env); got != filepath.Join(home, ".local/share/uv/tools") {
		t.Errorf("got %s", got)
	}
}

func TestPnpmReadsBinsFromManifest(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "pnpm")
	addBin(t, home, "node")
	pkg := filepath.Join(home, "g", "node_modules", "eslint")
	writeFile(t, filepath.Join(pkg, "package.json"), `{"bin": {"eslint": "bin/eslint.js"}}`)
	ls, _ := json.Marshal([]map[string]any{{"dependencies": map[string]any{
		"eslint": map[string]string{"version": "9.1.0", "path": pkg},
		"gone":   map[string]string{"version": "1.0.0", "path": filepath.Join(home, "missing")},
	}}})
	fake.AddOutput(string(ls), "pnpm", "ls", "-g")
	fake.AddOutput("v24.22.0\n", filepath.Join(home, "bin", "node"), "--version")
	fake.AddOutput(home+"/pnpm/bin\n", "pnpm", "bin", "-g")
	inv := Collect(ctx, env, Pnpm{})
	if inv.Error != "" {
		t.Fatal(inv.Error)
	}
	by := map[string]Package{}
	for _, p := range inv.Packages {
		by[p.Name] = p
	}
	if !reflect.DeepEqual(by["eslint"].Executables, []string{"eslint"}) || by["eslint"].RuntimeVersion != "24.22.0" {
		t.Errorf("eslint = %+v", by["eslint"])
	}
	if len(by["gone"].Executables) != 0 {
		t.Errorf("gone = %+v", by["gone"])
	}
	if !reflect.DeepEqual(inv.BinDirs, []string{home + "/pnpm/bin"}) {
		t.Errorf("bin dirs %v", inv.BinDirs)
	}
}

func TestPnpmBinDirFallsBackToPnpmHome(t *testing.T) {
	env, _, _ := testEnv(t)
	env.Vars["PNPM_HOME"] = "/p"
	if got := (Pnpm{}).BinDirs(ctx, env); !reflect.DeepEqual(got, []string{"/p/bin"}) {
		t.Errorf("got %v", got)
	}
	delete(env.Vars, "PNPM_HOME")
	if got := (Pnpm{}).BinDirs(ctx, env); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestCargoReadsCrates2(t *testing.T) {
	env, _, home := testEnv(t)
	addBin(t, home, "cargo")
	writeFile(t, filepath.Join(home, ".cargo", ".crates2.json"),
		`{"installs": {"bat 0.24.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["bat"]}}}`)
	inv := Collect(ctx, env, Cargo{})
	bin := filepath.Join(home, ".cargo", "bin")
	if len(inv.Packages) != 1 || inv.Packages[0].Name != "bat" || inv.Packages[0].Location != bin {
		t.Errorf("packages %+v", inv.Packages)
	}
	if !reflect.DeepEqual(inv.BinDirs, []string{bin}) {
		t.Errorf("bin dirs %v", inv.BinDirs)
	}
}

func TestCargoRespectsCargoHome(t *testing.T) {
	env, _, home := testEnv(t)
	env.Vars["CARGO_HOME"] = filepath.Join(home, "c")
	if got := (Cargo{}).BinDirs(ctx, env); !reflect.DeepEqual(got, []string{filepath.Join(home, "c", "bin")}) {
		t.Errorf("got %v", got)
	}
}

func TestCargoWithoutManifest(t *testing.T) {
	env, _, home := testEnv(t)
	addBin(t, home, "cargo")
	if inv := Collect(ctx, env, Cargo{}); len(inv.Packages) != 0 || inv.Error != "" {
		t.Errorf("got %+v", inv)
	}
}

func TestCargoRuntime(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "rustc")
	fake.AddOutput(rustcVV, filepath.Join(home, "bin", "rustc"), "-vV")
	if rt := (Cargo{}).Runtime(ctx, env); rt == nil || rt.Version != "1.90.0-nightly" {
		t.Errorf("got %+v", rt)
	}
}

func TestGoUsesGobin(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "go")
	gobin := filepath.Join(home, "gobin")
	gopls := makeExe(t, filepath.Join(gobin, "gopls"), "")
	env.Vars["GOBIN"] = gobin
	fake.Add([]string{"go", "version", "-m"}, exec.Result{
		Code: 1, Stdout: gopls + ": go1.26.5\n\tmod\tgolang.org/x/tools/gopls\tv0.20.0\th1:x\n", Stderr: "partial"})
	fake.AddOutput("go1.25.7\n", "go", "env", "GOVERSION")
	inv := Collect(ctx, env, Golang{})
	if !reflect.DeepEqual(inv.BinDirs, []string{gobin}) || inv.Runtime.Version != "1.25.7" {
		t.Errorf("inv %+v", inv)
	}
	// A non-zero exit (some file without build info) still yields the rest.
	if len(inv.Packages) != 1 || inv.Packages[0].Version != "v0.20.0" {
		t.Errorf("packages %+v", inv.Packages)
	}
	found := false
	for _, c := range fake.Calls {
		if reflect.DeepEqual(c, []string{"go", "version", "-m", gopls}) {
			found = true
		}
	}
	if !found {
		t.Errorf("calls %v", fake.Calls)
	}
}

func TestGoDefaultsToGopathBin(t *testing.T) {
	env, _, home := testEnv(t)
	env.Vars["GOPATH"] = home + "/gp:" + home + "/other"
	if got := (Golang{}).BinDirs(ctx, env); !reflect.DeepEqual(got, []string{home + "/gp/bin"}) {
		t.Errorf("got %v", got)
	}
	delete(env.Vars, "GOPATH")
	if got := (Golang{}).BinDirs(ctx, env); !reflect.DeepEqual(got, []string{filepath.Join(home, "go", "bin")}) {
		t.Errorf("got %v", got)
	}
}

func TestGemKeepsNewestVersion(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "gem")
	user := filepath.Join(home, "gems", "3.3.0")
	specs := filepath.Join(user, "specifications")
	writeFile(t, filepath.Join(specs, "rake-13.0.9.gemspec"), `s.executables = ["rake".freeze]`)
	writeFile(t, filepath.Join(specs, "rake-13.0.10.gemspec"), `s.executables = ["rake".freeze]`)
	writeFile(t, filepath.Join(specs, "json-2.7.1.gemspec"), "")
	writeFile(t, filepath.Join(specs, "notes.txt"), "")
	fake.AddOutput(user, "ruby", "-e")
	fake.AddOutput("ruby 3.3.8 (2025-04-09) [x86_64-linux]\n", "ruby", "--version")
	inv := Collect(ctx, env, Gem{})
	got := map[string]string{}
	for _, p := range inv.Packages {
		got[p.Name] = p.Version
	}
	if !reflect.DeepEqual(got, map[string]string{"rake": "13.0.10", "json": "2.7.1"}) {
		t.Errorf("got %v", got)
	}
	if !reflect.DeepEqual(inv.BinDirs, []string{filepath.Join(user, "bin")}) {
		t.Errorf("bin dirs %v", inv.BinDirs)
	}
	if inv.Packages[1].RuntimeVersion != "3.3.8" {
		t.Errorf("ruby version %+v", inv.Packages[1])
	}
}

func TestGhInventory(t *testing.T) {
	env, fake, home := testEnv(t)
	addBin(t, home, "gh")
	fake.AddOutput("gh dash\tdlvhdr/gh-dash\tv4.9.0\n", "gh", "extension", "list")
	fake.AddOutput("gh version 2.52.0 (2024-06-24)\n", "gh", "--version")
	inv := Collect(ctx, env, Gh{})
	if len(inv.Packages) != 1 || inv.Packages[0].RuntimeVersion != "2.52.0" || inv.ManagerVersion != "2.52.0" {
		t.Errorf("got %+v", inv)
	}
	fake2 := &exec.Fake{}
	env.Runner = fake2
	fake2.Add([]string{"gh", "extension", "list"}, exec.Result{Code: 1, Stderr: "auth required"})
	if inv := Collect(ctx, env, Gh{}); !strings.Contains(inv.Error, "auth required") {
		t.Errorf("error = %q", inv.Error)
	}
}

func TestResolve(t *testing.T) {
	all, err := Resolve(nil)
	if err != nil || len(all) != len(Registry) {
		t.Fatalf("%v %v", all, err)
	}
	ms, err := Resolve([]string{"go", "uv"})
	if err != nil || ms[0].Name() != "go" || ms[1].Name() != "uv" {
		t.Errorf("%v %v", ms, err)
	}
	if _, err := Resolve([]string{"uv", "nope"}); err == nil ||
		err.Error() != "unknown manager(s): nope (known: uv, pnpm, cargo, go, gem, gh)" {
		t.Errorf("err = %v", err)
	}
}

func TestCollectAllPreservesOrderAndReports(t *testing.T) {
	env, _, _ := testEnv(t)
	ms, _ := Resolve([]string{"gh", "cargo"})
	var mu sync.Mutex
	var done []string
	invs := CollectAll(ctx, env, ms, func(i Inventory) {
		mu.Lock()
		defer mu.Unlock()
		done = append(done, i.Manager)
	})
	if invs[0].Manager != "gh" || invs[1].Manager != "cargo" {
		t.Errorf("order %+v", invs)
	}
	sort.Strings(done)
	if !reflect.DeepEqual(done, []string{"cargo", "gh"}) {
		t.Errorf("done %v", done)
	}
}
