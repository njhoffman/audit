package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

// fakeApt plays sudo, dpkg and apt: vim 1.0 is installed and 1.1 is
// available until apt-get installs it.
type fakeApt struct {
	mu       sync.Mutex
	vim      string
	sudoOK   bool
	calls    []string
	upgraded bool
}

func (f *fakeApt) Run(_ context.Context, name string, args []string, opts exec.Options) exec.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "sudo -n -v":
		if f.sudoOK {
			return exec.Result{}
		}
		return exec.Result{Code: 1, Stderr: "sudo: a password is required"}
	case cmd == "sudo -v" && opts.Terminal:
		f.sudoOK = true
		return exec.Result{}
	case cmd == "sudo -n apt-get update":
		return exec.Result{Stdout: "Reading package lists..."}
	case strings.HasPrefix(cmd, "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade"):
		f.vim, f.upgraded = "1.1", true
		return exec.Result{}
	case name == "dpkg-query":
		return exec.Result{Stdout: "vim\t" + f.vim + "\tii \n"}
	case cmd == "apt-mark showmanual":
		return exec.Result{Stdout: "vim\n"}
	case cmd == "apt-mark showhold":
		return exec.Result{}
	case cmd == "apt list --upgradable":
		if f.vim == "1.0" {
			return exec.Result{Stdout: "Listing...\nvim/noble 1.1 amd64 [upgradable from: 1.0]\n"}
		}
		return exec.Result{Stdout: "Listing...\n"}
	case cmd == "apt-get --version":
		return exec.Result{Stdout: "apt 2.9.0 (amd64)\n"}
	}
	return exec.Result{Code: exec.ExitNotFound, Stderr: name + ": command not found"}
}

func (f *fakeApt) ran(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func aptEnv(t *testing.T) *fakeApt {
	t.Helper()
	cfgHome, _ := env(t)
	bin := t.TempDir()
	for _, n := range []string{"apt-get", "apt", "apt-mark", "dpkg-query", "sudo"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("HOME", t.TempDir())
	writeConfig(t, cfgHome, "packages: {env: process, managers: [apt], system_managers: always, scan_dirs: []}\n")
	return &fakeApt{vim: "1.0"}
}

func runApt(t *testing.T, f *fakeApt, interactive bool, args ...string) result {
	t.Helper()
	return runAptInput(t, f, interactive, "", args...)
}

func runAptInput(t *testing.T, f *fakeApt, interactive bool, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return interactive }
	a.in = strings.NewReader(stdin)
	a.runner = f
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	a.close()
	return result{out.String(), errOut.String(), e, a}
}

func TestAptUpdate(t *testing.T) {
	f := aptEnv(t)
	r := runApt(t, f, false, "packages", "update", "-N")
	if r.e != nil || !strings.Contains(r.out, "apt:vim") || !strings.Contains(r.out, "apt-get install -y --only-upgrade") ||
		f.ran("sudo") {
		t.Fatalf("dry run uses no sudo: %v %v\n%s", r.e, f.calls, r.out)
	}

	r = runApt(t, f, true, "packages", "update", "-y")
	if r.e != nil || !f.ran("sudo -v") || !f.ran("sudo -n apt-get update") || !f.upgraded ||
		!strings.Contains(r.out, "1 updated, 0 failed, 0 skipped") {
		t.Fatalf("update: %v %v\n%s\n%s", r.e, f.calls, r.out, r.err)
	}
	if !strings.Contains(r.err, "audit needs sudo for refreshing apt's package lists") {
		t.Errorf("the prompt says why: %s", r.err)
	}
}

func TestAptUpdateWithoutSudo(t *testing.T) {
	f := aptEnv(t)
	r := runApt(t, f, false, "packages", "update", "-y")
	if r.e != nil || f.ran("sudo -n apt-get") || f.upgraded ||
		!strings.Contains(r.out, "skip: needs sudo: sudo needs a password for apt, snap and system flatpak updates") ||
		!strings.Contains(r.err, "not refreshing apt's package lists") {
		t.Errorf("no terminal, no cached sudo: %v %v\n%s\n%s", r.e, f.calls, r.out, r.err)
	}
	// Naming only a non-apt package leaves apt's lists alone.
	f2 := aptEnv(t)
	f2.sudoOK = true
	if r := runApt(t, f2, false, "packages", "update", "-y", "ruff"); f2.ran("sudo -n apt-get update") {
		t.Errorf("named non-apt package refreshed apt: %v %v", r.e, f2.calls)
	}
}

// systemEnv is aptEnv under the given packages.system_managers, with one user
// manager that is not installed.
func systemEnv(t *testing.T, mode string) *fakeApt {
	t.Helper()
	f := aptEnv(t)
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	writeConfig(t, cfgHome, "packages: {env: process, managers: [gh], system_managers: "+mode+", scan_dirs: []}\n")
	return f
}

func TestSystemManagersPrompt(t *testing.T) {
	f := systemEnv(t, "ask")
	r := runAptInput(t, f, true, "y\n", "packages", "-r")
	if r.e != nil || !strings.Contains(r.err, systemQuestion) {
		t.Fatalf("yes: %v %q", r.e, r.err)
	}
	r = runApt(t, f, false, "packages", "-l")
	if r.e != nil || !strings.Contains(r.out, "vim") || strings.Contains(r.out, "not rescanned") ||
		strings.Contains(r.out, "Not scanned in this run") {
		t.Fatalf("scanned apt: %v\n%s", r.e, r.out)
	}
	if r = runApt(t, f, true, "packages"); r.e != nil || strings.Contains(r.err, systemQuestion) {
		t.Errorf("fresh saved results need no scan, so no question: %v %q", r.e, r.err)
	}

	r = runAptInput(t, f, true, "n\n", "packages", "-r")
	if r.e != nil || !strings.Contains(r.err, systemQuestion) {
		t.Fatalf("no: %v %q", r.e, r.err)
	}
	r = runApt(t, f, false, "packages", "-l")
	for _, want := range []string{"vim", "not rescanned; checked", "Not scanned in this run: apt, snap, flatpak"} {
		if r.e != nil || !strings.Contains(r.out, want) {
			t.Errorf("carried results missing %q: %v\n%s", want, r.e, r.out)
		}
	}
	if !strings.Contains(r.out, "1.1") {
		t.Errorf("a system package shows the version it is behind on:\n%s", r.out)
	}
	r = runApt(t, f, false, "todo", "--cmd", "packages")
	if r.e != nil || !strings.Contains(r.out, "open    packages  Update 1 outdated apt package") {
		t.Errorf("skipping the scan keeps the task open: %v\n%s", r.e, r.out)
	}
}

func TestSystemManagersNoPrompt(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		interactive bool
		args        []string
		wantVim     bool
		wantNote    string
	}{
		{"no terminal", "ask", false, []string{"packages", "-r"}, false, "apt, snap, flatpak"},
		{"quiet", "ask", true, []string{"packages", "-r", "-q"}, false, "apt, snap, flatpak"},
		{"flag", "ask", true, []string{"packages", "-r", "-S"}, true, ""},
		{"flag off", "ask", true, []string{"packages", "-r", "--system=false"}, false, "apt, snap, flatpak"},
		{"always", "always", true, []string{"packages", "-r"}, true, ""},
		{"always, flag off", "always", true, []string{"packages", "-r", "--system=false"}, false, "apt, snap, flatpak"},
		{"never", "never", true, []string{"packages", "-r"}, false, ""},
		{"never, flag", "never", true, []string{"packages", "-r", "-S"}, true, ""},
		{"outdated with flag", "ask", true, []string{"packages", "outdated", "-S"}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := systemEnv(t, c.mode)
			r := runApt(t, f, c.interactive, c.args...)
			if r.e != nil || strings.Contains(r.err, systemQuestion) {
				t.Fatalf("no question expected: %v %q", r.e, r.err)
			}
			r = runApt(t, f, false, "packages", "-l")
			if r.e != nil || strings.Contains(r.out, "vim") != c.wantVim {
				t.Errorf("vim listed = %v, want %v: %v\n%s", !c.wantVim, c.wantVim, r.e, r.out)
			}
			note := "Not scanned in this run: " + c.wantNote
			if c.wantNote != "" && !strings.Contains(r.out, note) {
				t.Errorf("missing %q:\n%s", note, r.out)
			}
			if c.wantNote == "" && strings.Contains(r.out, "Not scanned in this run") {
				t.Errorf("unexpected note:\n%s", r.out)
			}
		})
	}
}

func TestSystemManagersUpdateQuestion(t *testing.T) {
	f := systemEnv(t, "ask")
	r := runApt(t, f, true, "packages", "update", "-N", "apt:vim")
	if r.e != nil || strings.Contains(r.err, systemQuestion) || !strings.Contains(r.out, "apt:vim") {
		t.Errorf("naming a system package includes them: %v %q\n%s", r.e, r.err, r.out)
	}
	r = runApt(t, f, true, "packages", "update", "-N", "gh:cli")
	if strings.Contains(r.err, systemQuestion) {
		t.Errorf("naming only another manager's package needs no question: %q", r.err)
	}
	r = runAptInput(t, f, true, "n\n", "packages", "update", "-N")
	if r.e != nil || !strings.Contains(r.err, systemQuestion) || strings.Contains(r.out, "apt:vim") {
		t.Errorf("declined: carried packages are not planned: %v %q\n%s", r.e, r.err, r.out)
	}
	r = runAptInput(t, f, true, "y\n", "packages", "update", "-N")
	if r.e != nil || !strings.Contains(r.out, "apt:vim") {
		t.Errorf("accepted: %v\n%s", r.e, r.out)
	}
}

func TestNarrowedScanKeepsSavedFullRun(t *testing.T) {
	f := systemEnv(t, "always")
	if r := runApt(t, f, false, "packages", "-r"); r.e != nil {
		t.Fatal(r.e)
	}
	if r := runApt(t, f, false, "packages", "-r", "-M", "apt"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runApt(t, f, false, "packages", "-s")
	if r.e != nil || strings.Contains(r.out, "scope apt") {
		t.Errorf("the saved view reads the full run: %v\n%s", r.e, r.out)
	}
}

func TestSystemFlagHasNoEffectOnNarrowedList(t *testing.T) {
	f := systemEnv(t, "ask")
	r := runApt(t, f, true, "packages", "-r", "-M", "apt")
	if r.e != nil || strings.Contains(r.err, systemQuestion) {
		t.Errorf("naming managers needs no question: %v %q", r.e, r.err)
	}
}
