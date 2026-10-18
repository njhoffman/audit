package registry

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

func TestLookupRuntime(t *testing.T) {
	c, fake, _ := newClient(t)
	fake.AddOutput("/data/uv/python\n", "uv", "python", "dir")
	fake.AddOutput(`[{"version":"3.15.0","path":null,"implementation":"cpython","variant":"default"},
		{"version":"3.14.8","path":"/data/uv/python/cpython-3.14.8/bin/python3.14","implementation":"cpython","variant":"default"}]`,
		"uv", "python", "list")
	fake.Add([]string{"rustup", "check"}, exec.Result{Code: rustupUpdates,
		Stdout: "stable-x86_64-unknown-linux-gnu - update available: 1.99.0 (a 2026-09-01) -> 1.99.1 (b 2026-10-13)\nrustup - up to date : 1.29.1\n"})

	py, err := c.LookupRuntime(ctx, packages.RuntimePython)
	if err != nil || py.Newest != "3.15.0" || py.PythonDir != "/data/uv/python" || len(py.Installs) != 1 || !py.Installs[0].Managed {
		t.Errorf("python: %+v %v", py, err)
	}
	node, err := c.LookupRuntime(ctx, packages.RuntimeNode)
	if err != nil || node.Newest != "24.22.0" || node.Lines["26"] != "26.12.0" {
		t.Errorf("node: %+v %v", node, err)
	}
	gol, err := c.LookupRuntime(ctx, packages.RuntimeGo)
	if err != nil || gol.Newest != "1.27.2" {
		t.Errorf("go: %+v %v", gol, err)
	}
	rust, err := c.LookupRuntime(ctx, packages.RuntimeRust)
	if err != nil || len(rust.Toolchains) != 1 || rust.Lines["stable-x86_64-unknown-linux-gnu"] != "1.99.1 (b 2026-10-13)" {
		t.Errorf("rust (exit 100 means updates are available): %+v %v", rust, err)
	}
	for i, call := range fake.Calls {
		if call[0] == "uv" && !reflect.DeepEqual(fake.CallOpts[i].Unset, []string{"VIRTUAL_ENV"}) {
			t.Errorf("uv runs outside any venv: %v %+v", call, fake.CallOpts[i])
		}
	}
	if _, err := c.LookupRuntime(ctx, packages.RuntimeRuby); err == nil {
		t.Error("ruby has no lookup")
	}

	c2, fake2, _ := newClient(t)
	fake2.Add([]string{"rustup"}, exec.Result{Code: exec.ExitNotFound})
	fake2.Add([]string{"uv"}, exec.Result{Code: 2, Stderr: "error: boom\nmore"})
	if _, err := c2.LookupRuntime(ctx, packages.RuntimeRust); err == nil || err.Error() != "rustup not found" {
		t.Errorf("no rustup: %v", err)
	}
	if _, err := c2.LookupRuntime(ctx, packages.RuntimePython); err == nil || err.Error() != "uv python list exited 2: error: boom" {
		t.Errorf("uv failure: %v", err)
	}
}

type fakeRuntimes struct {
	calls []string
	fail  map[string]bool
}

func (f *fakeRuntimes) LookupRuntime(_ context.Context, name string) (packages.RuntimeMeta, error) {
	f.calls = append(f.calls, name)
	if f.fail[name] {
		return packages.RuntimeMeta{Name: name}, errors.New("offline")
	}
	return packages.RuntimeMeta{Name: name, Newest: "new"}, nil
}

func TestRefreshRuntimes(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	cache := map[string]packages.RuntimeMeta{
		"python": {Name: "python", CheckedAt: now},
		"node":   {Name: "node", Newest: "old", CheckedAt: now.Add(-time.Hour)},
		"go":     {Name: "go", Newest: "old", CheckedAt: now.Add(-48 * time.Hour)},
		"rust":   {Name: "rust", CheckedAt: now, Error: "earlier failure"},
	}
	f := &fakeRuntimes{fail: map[string]bool{"go": true}}
	var done []string
	got := RefreshRuntimes(ctx, f, packages.RuntimeNames, cache, 24*time.Hour, false, now, func(n string) { done = append(done, n) })
	if !reflect.DeepEqual(f.calls, []string{"python", "rust", "go"}) || !reflect.DeepEqual(done, f.calls) {
		t.Errorf("python always, fresh node skipped, failed rust retried, stale go, ruby never: %v", f.calls)
	}
	byName := map[string]packages.RuntimeMeta{}
	for _, m := range got {
		byName[m.Name] = m
	}
	if g := byName["go"]; g.Newest != "old" || g.Error != "offline" || !g.CheckedAt.Equal(now) {
		t.Errorf("a failed lookup keeps the old answer: %+v", g)
	}
	if r := byName["rust"]; r.Error != "" || r.Newest != "new" {
		t.Errorf("rust: %+v", r)
	}

	f = &fakeRuntimes{}
	RefreshRuntimes(ctx, f, []string{"node"}, cache, 24*time.Hour, true, now, nil)
	if !reflect.DeepEqual(f.calls, []string{"node"}) {
		t.Errorf("force with names: %v", f.calls)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	f = &fakeRuntimes{}
	if got := RefreshRuntimes(cctx, f, packages.RuntimeNames, nil, time.Hour, true, now, nil); len(got) != 0 || len(f.calls) != 0 {
		t.Errorf("cancelled: %v %v", got, f.calls)
	}
}
