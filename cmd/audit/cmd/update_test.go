package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// fakeGh answers the gh commands of a scan and an update from a table of
// installed extension versions.
type fakeGh struct {
	mu       sync.Mutex
	versions map[string]string
	upgrades []string
}

func (f *fakeGh) Run(_ context.Context, name string, args []string, _ exec.Options) exec.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case cmd == "gh --version":
		return exec.Result{Stdout: "gh version 2.80.0 (2026-01-01)\n"}
	case cmd == "gh extension list":
		var b strings.Builder
		for _, n := range []string{"ok", "stuck", "bad", "major", "current"} {
			fmt.Fprintf(&b, "gh %s\to/gh-%s\t%s\n", n, n, f.versions[n])
		}
		return exec.Result{Stdout: b.String()}
	case strings.HasPrefix(cmd, "gh extension upgrade "):
		n := args[2]
		f.upgrades = append(f.upgrades, n)
		switch n {
		case "ok":
			f.versions[n] = "v1.1.0"
		case "bad":
			return exec.Result{Code: 1, Stderr: "upgrading bad\nnetwork error\n"}
		}
		return exec.Result{}
	}
	return exec.Result{Code: exec.ExitNotFound, Stderr: name + ": command not found"}
}

type latestLooker struct{}

func (latestLooker) Lookup(context.Context, packages.Package, *packages.Meta, bool) (packages.Meta, bool, error) {
	return packages.Meta{Latest: "v1.1.0"}, false, nil
}

// updateEnv configures a gh-only, process-environment scan over fakeGh.
func updateEnv(t *testing.T) *fakeGh {
	t.Helper()
	cfgHome, _ := env(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	cfg := "packages: {env: process, managers: [gh], scan_dirs: []}\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fakeGh{versions: map[string]string{"ok": "v1.0.0", "stuck": "v1.0.0", "bad": "v1.0.0", "major": "v0.9.0", "current": "v1.1.0"}}
}

func runUpdate(t *testing.T, gh *fakeGh, interactive bool, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return interactive }
	a.in = strings.NewReader(stdin)
	a.runner, a.looker = gh, latestLooker{}
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	return result{out.String(), errOut.String(), e, a}
}

func TestPackagesUpdatePlan(t *testing.T) {
	gh := updateEnv(t)
	r := runUpdate(t, gh, false, "", "packages", "update", "-N")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"gh:ok", "gh extension upgrade ok", "gh:major", "skip: major release; pass --major to update",
		"3 to update, 1 skipped."} {
		if !strings.Contains(r.out, want) {
			t.Errorf("dry run missing %q:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "gh:current") || len(gh.upgrades) != 0 {
		t.Errorf("current packages are not planned and a dry run upgrades nothing: %v\n%s", gh.upgrades, r.out)
	}

	r = runUpdate(t, gh, false, "", "packages", "update", "-N", "-j", "-m")
	var plan packages.Plan
	if r.e != nil || json.Unmarshal([]byte(r.out), &plan) != nil || len(plan.Runnable()) != 4 {
		t.Errorf("json plan with --major: %v %q", r.e, r.out)
	}

	r = runUpdate(t, gh, false, "", "packages", "update", "-N", "current", "nothere")
	if r.e == nil || r.e.Error() != "no installed package matches nothere" {
		t.Errorf("unknown ref: %v", r.e)
	}
	r = runUpdate(t, gh, false, "", "packages", "update", "-N", "current")
	if r.e != nil || !strings.Contains(r.out, "skip: already at the latest release") || !strings.Contains(r.out, "Nothing to update.") {
		t.Errorf("named current package: %v\n%s", r.e, r.out)
	}
}

func TestPackagesUpdateConfirm(t *testing.T) {
	gh := updateEnv(t)
	r := runUpdate(t, gh, false, "", "packages", "update")
	if r.e == nil || !strings.Contains(r.e.Error(), "refusing to update without --yes") {
		t.Errorf("no terminal: %v", r.e)
	}
	r = runUpdate(t, gh, true, "n\n", "packages", "update")
	if r.e != nil || !strings.Contains(r.err, "Update 3 package(s)? [y/N]") || len(gh.upgrades) != 0 {
		t.Errorf("declined: %v %v %q", r.e, gh.upgrades, r.err)
	}
	r = runUpdate(t, gh, true, "y\n", "packages", "update", "ok")
	if r.e != nil || len(gh.upgrades) != 1 || !strings.Contains(r.out, "1 updated, 0 failed, 0 skipped") {
		t.Errorf("accepted: %v %v\n%s", r.e, gh.upgrades, r.out)
	}
}

func TestPackagesUpdateRun(t *testing.T) {
	gh := updateEnv(t)
	r := runUpdate(t, gh, false, "", "packages", "update", "-y")
	if r.e == nil || r.e.Error() != "2 package update(s) failed" {
		t.Fatalf("err = %v\n%s\n%s", r.e, r.out, r.err)
	}
	for _, want := range []string{"Update 2026-03-01", "1 updated, 2 failed, 1 skipped.",
		"FAILED gh:bad v1.0.0 -> v1.1.0: exit status 1: network error", "  $ gh extension upgrade bad", "  | network error",
		"FAILED gh:stuck v1.0.0 -> v1.1.0: the command succeeded but the version is still v1.0.0"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("summary missing %q:\n%s", want, r.out)
		}
	}
	for _, want := range []string{"ok      gh:ok v1.0.0 -> v1.1.0", "FAILED  gh:bad v1.0.0 -> v1.1.0"} {
		if !strings.Contains(r.err, want) {
			t.Errorf("status lines missing %q:\n%s", want, r.err)
		}
	}

	r = runUpdate(t, gh, false, "", "packages", "update", "-L")
	if r.e != nil || !strings.Contains(r.out, "STATUS") || !strings.Contains(r.out, "skipped: major release") ||
		!strings.Contains(r.out, "FAILED gh:bad") {
		t.Errorf("--last: %v\n%s", r.e, r.out)
	}
	r = runUpdate(t, gh, false, "", "packages", "update", "-L", "-j")
	var u packages.Update
	if r.e != nil || json.Unmarshal([]byte(r.out), &u) != nil || len(u.Items) != 4 || u.Items[2].Name != "ok" || u.Items[2].To != "v1.1.0" {
		t.Errorf("--last --json: %v %q", r.e, r.out)
	}
	if r = runUpdate(t, gh, false, "", "packages", "update", "-L", "ok"); r.e == nil {
		t.Error("--last with packages must fail")
	}

	// The rescan after the update notes the failure on the outdated task and
	// shows the last update in the report.
	a, _, _ := loadedApp(t)
	todos, err := a.store.Todos(context.Background(), packages.Command)
	if err != nil {
		t.Fatal(err)
	}
	noted := false
	for _, td := range todos {
		if strings.Contains(strings.Join(td.Details, "\n"), "gh:o/gh-bad: v1.0.0 -> v1.1.0 (minor); last update attempt failed on 2026-03-01: exit status 1: network error") {
			noted = true
		}
		if strings.Contains(td.Key, "gh:o/gh-ok") && td.Status == "open" {
			t.Errorf("the updated package's task should be resolved: %+v", td)
		}
	}
	if !noted {
		t.Errorf("no task notes the failed update: %+v", todos)
	}
	a.close()
	r = runUpdate(t, gh, false, "", "packages")
	if !strings.Contains(r.out, "1 updated, 2 failed, 1 skipped") {
		t.Errorf("report should show the last update:\n%s", r.out)
	}
}
