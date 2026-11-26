package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

// fakeSystemctl answers list-units with units and show with props, per scope.
func fakeSystemctl(t *testing.T, units map[Scope]string, props map[string]string, fail map[Scope]bool) {
	t.Helper()
	oldRun, oldBus := systemctl, userBus
	t.Cleanup(func() { systemctl, userBus = oldRun, oldBus })
	userBus = func() bool { return true }
	systemctl = func(_ context.Context, args ...string) ([]byte, error) {
		sc := ScopeSystem
		if args[0] == "--user" {
			sc, args = ScopeUser, args[1:]
		}
		if args[len(args)-1] == "list-units" {
			if fail[sc] {
				return nil, fmt.Errorf("systemctl %s: Failed to connect to bus", sc)
			}
			return []byte(units[sc]), nil
		}
		name := args[len(args)-1]
		if p, ok := props[name]; ok {
			return []byte(p), nil
		}
		return nil, fmt.Errorf("no such unit %s", name)
	}
}

func TestScanEnrichesAndSummarizes(t *testing.T) {
	writable := filepath.Join(t.TempDir(), "open.service")
	if err := os.WriteFile(writable, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil { // #nosec G302 -- the fixture under test
		t.Fatal(err)
	}
	fakeSystemctl(t, map[Scope]string{
		ScopeSystem: `[{"unit":"ok.service","load":"loaded","active":"active","sub":"running","description":"OK"},
			{"unit":"bad.service","load":"loaded","active":"failed","sub":"failed","description":"Bad"},
			{"unit":"gone.service","load":"loaded","active":"active","sub":"running","description":"show fails"}]`,
		ScopeUser: `[{"unit":"mine.service","load":"loaded","active":"active","sub":"running","description":"Mine"}]`,
	}, map[string]string{
		"ok.service":   "Type=simple\nNRestarts=0\nFragmentPath=" + writable + "\n",
		"bad.service":  "Type=simple\nNRestarts=9\nResult=exit-code\n",
		"mine.service": "Type=simple\nNRestarts=0\n",
	}, nil)
	r, err := Scan(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "services" || r.Summary["total"] != 3 {
		t.Errorf("a unit whose show fails is left out: %+v", r.Summary)
	}
	if got := r.Summary["by_scope"].(map[string]int); got["system"] != 2 || got["user"] != 1 {
		t.Errorf("by scope: %v", got)
	}
	if got := r.Summary["failed"].([]string); len(got) != 1 || got[0] != "system/bad.service" {
		t.Errorf("failed: %v", got)
	}
	checks := map[string]bool{}
	for _, f := range r.Findings {
		checks[f.Check] = true
		if f.Check == "unit_file_writable" && (f.Severity != scan.SeverityCritical || f.Subject != writable) {
			t.Errorf("writable unit file: %+v", f)
		}
	}
	for _, c := range []string{"unit_file_writable"} {
		if !checks[c] {
			t.Errorf("missing %s in %v", c, checks)
		}
	}
}

func TestScanScopesCapAndCancel(t *testing.T) {
	list := `[{"unit":"a.service","load":"loaded","active":"active","sub":"running"},
		{"unit":"b.service","load":"loaded","active":"active","sub":"running"}]`
	props := map[string]string{"a.service": "Type=simple\n", "b.service": "Type=simple\n"}
	fakeSystemctl(t, map[Scope]string{ScopeSystem: list}, props, map[Scope]bool{ScopeUser: true})
	r, err := Scan(context.Background(), Options{MaxUnits: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary["total"] != 1 {
		t.Errorf("MaxUnits caps each scope: %v", r.Summary["total"])
	}
	if sk := r.Summary["skipped"].(map[Scope]string); !strings.Contains(sk[ScopeUser], "Failed to connect") {
		t.Errorf("a scope that cannot be listed is skipped with the reason: %v", sk)
	}
	r, err = Scan(context.Background(), Options{SkipUserScope: true})
	if err != nil || r.Summary["by_scope"].(map[string]int)["user"] != 0 || len(r.Summary["skipped"].(map[Scope]string)) != 0 {
		t.Errorf("SkipUserScope leaves the user bus alone: %+v %v", r.Summary, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, Options{}); err == nil {
		t.Error("a canceled scan stops")
	}
}

func TestRunSystemctl(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = fail ]; then echo 'unit broken' >&2; exit 1; fi\necho \"$*|$LC_ALL|$NO_COLOR|${SECRET:-unset}\"\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("SECRET", "leak")
	out, err := runSystemctl(context.Background(), "--no-pager", "show", "x.service")
	if err != nil || strings.TrimSpace(string(out)) != "--no-pager show x.service|C|1|unset" {
		t.Errorf("sanitized run: %q %v", out, err)
	}
	if _, err := runSystemctl(context.Background(), "fail"); err == nil || !strings.Contains(err.Error(), "unit broken") {
		t.Errorf("stderr is in the error: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := runSystemctl(context.Background(), "show"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing systemctl: %v", err)
	}
}

func TestUserBusAvailable(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/x")
	if !userBusAvailable() {
		t.Error("a session bus address means a user bus")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	if userBusAvailable() {
		t.Error("no bus socket, no user bus")
	}
	if err := os.WriteFile(filepath.Join(rt, "bus"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !userBusAvailable() {
		t.Error("the runtime dir's bus socket means a user bus")
	}
	if d := DefaultOptions(); d.Findings != DefaultFindingOptions() {
		t.Errorf("defaults: %+v", d)
	}
}
