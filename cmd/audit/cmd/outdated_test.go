package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

type countingLatestLooker struct{ calls atomic.Int32 }

func (l *countingLatestLooker) Lookup(ctx context.Context, p packages.Package, m *packages.Meta, describe bool) (packages.Meta, bool, error) {
	l.calls.Add(1)
	return (latestLooker{}).Lookup(ctx, p, m, describe)
}

func TestOutdatedRefreshSavedAndUpdate(t *testing.T) {
	gh := updateEnv(t)
	looker := &countingLatestLooker{}
	setup := func(a *app) { a.runner, a.looker = gh, looker }
	r := runArgsWith(t, setup, "packages", "outdated", "-j")
	if r.e == nil || looker.calls.Load() != 0 {
		t.Fatal("JSON without saved results should not scan")
	}
	r = runArgsWith(t, setup, "packages", "outdated")
	if r.e != nil || looker.calls.Load() == 0 || !strings.Contains(r.out, "v1.0.0") || !strings.Contains(r.out, "v1.1.0") || !strings.Contains(r.out, "audit packages update") {
		t.Fatalf("outdated: %s %v", r.out, r.e)
	}
	count := looker.calls.Load()
	r = runArgsWith(t, setup, "packages", "outdated", "-j")
	var got struct {
		Saved    bool                 `json:"saved"`
		Packages []packages.Annotated `json:"packages"`
	}
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil || !got.Saved || looker.calls.Load() != count {
		t.Fatalf("saved outdated: %s %v", r.out, r.e)
	}
	if len(got.Packages) != 1 || len(got.Packages[0].Items) != 4 {
		t.Fatalf("outdated filter: %+v", got.Packages)
	}
	for _, p := range got.Packages[0].Items {
		if p.Name == "current" {
			t.Fatal("current package listed as outdated")
		}
	}
	r = runArgsWith(t, setup, "packages", "outdated", "-F", "-j", "-f", "ok", "-M", "gh")
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil || got.Saved || looker.calls.Load() <= count || len(got.Packages) != 1 || len(got.Packages[0].Items) != 1 || got.Packages[0].Items[0].Name != "ok" {
		t.Fatalf("forced filtered refresh: %s %v", r.out, r.e)
	}

	// Saved, text-filtered hints must select only the displayed package.
	r = runArgsWith(t, setup, "packages", "outdated", "-l", "-M", "gh", "-f", "ok")
	preview := "audit packages update --dry-run --manager gh -- gh:ok"
	if r.e != nil || !strings.Contains(r.out, "Preview updates: "+preview+"\nUpdate: audit packages update --manager gh -- gh:ok (add --major") {
		t.Fatalf("scoped hints: %s %v", r.out, r.e)
	}
	// Follow the printed preview and check the resulting plan, not just the text.
	r = runArgsWith(t, setup, strings.Fields(strings.TrimPrefix(preview, "audit "))...)
	if r.e != nil {
		t.Fatal(r.e)
	}
	if !strings.Contains(r.out, "gh:ok") || strings.Contains(r.out, "gh:bad") || strings.Contains(r.out, "gh:stuck") || strings.Contains(r.out, "gh:major") || len(gh.upgrades) != 0 {
		t.Fatalf("preview escaped displayed scope: %s %v", r.out, r.e)
	}

	r = runUpdate(t, gh, false, "", "packages", "update", "-y", "gh:ok")
	if r.e != nil || len(gh.upgrades) != 1 {
		t.Fatalf("update selected outdated package: %s %v", r.out, r.e)
	}
	r = runArgsWith(t, setup, "packages", "outdated", "-j", "-f", "ok")
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil || len(got.Packages) != 0 {
		t.Fatalf("updated package still outdated: %s %v", r.out, r.e)
	}
}

// A failed cache read used to be logged while the command succeeded without
// the list it was asked for.
func TestInventoryViewErrorsFailTheCommand(t *testing.T) {
	gh := updateEnv(t)
	setup := func(a *app) { a.runner, a.looker = gh, latestLooker{} }
	if r := runArgsWith(t, setup, "packages", "outdated"); r.e != nil {
		t.Fatalf("scan: %v", r.e)
	}
	r := runArgsWith(t, setup, "packages", "outdated", "-l")
	if r.e != nil {
		t.Fatal(r.e)
	}
	db, err := sql.Open("sqlite", filepath.Join(r.app.cfg.DataDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE package_tags; CREATE TABLE package_tags (broken TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	for _, args := range [][]string{
		{"packages", "outdated", "-l"}, {"packages", "outdated", "-j"}, {"packages", "-l"}, {"packages", "-j"},
	} {
		if r := runArgsWith(t, setup, args...); r.e == nil {
			t.Errorf("%v: a failed cache read must fail the command: %v\n%s", args, r.e, r.out)
		}
	}
}

func TestOutdatedUpdateArgsScope(t *testing.T) {
	invs := []packages.Inventory{
		{Manager: "gh", Available: true, Packages: []packages.Package{
			{Manager: "gh", Name: "same", Ident: "one/gh-same", Version: "v1.0.0"},
			{Manager: "gh", Name: "other", Ident: "one/gh-other", Version: "v1.0.0"},
		}},
		{Manager: "go", Available: true, Packages: []packages.Package{
			{Manager: "go", Name: "same", Ident: "example.org/tools", Source: "example.org/tools/cmd/same", Version: "v1.0.0"},
			{Manager: "go", Name: "other", Ident: "example.org/tools", Source: "example.org/tools/cmd/other", Version: "v1.0.0"},
		}},
	}
	metas := map[string]packages.Meta{}
	for _, inv := range invs {
		for _, p := range inv.Packages {
			metas[p.Key()] = packages.Meta{Latest: "v1.1.0"}
		}
	}
	for _, tc := range []struct {
		name     string
		managers []string
		find     string
		want     []string
	}{
		{"all", nil, "", []string{"--", "gh:same", "gh:other", "go:same", "go:other"}},
		{"manager", []string{"gh"}, "", []string{"--manager", "gh", "--", "gh:same", "gh:other"}},
		{"text", nil, "same", []string{"--", "gh:same", "go:same"}},
		{"both", []string{"gh"}, "same", []string{"--manager", "gh", "--", "gh:same"}},
		{"multiple managers", []string{"gh", "go"}, "same", []string{"--manager", "gh,go", "--", "gh:same", "go:same"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := invs
			if len(tc.managers) == 1 {
				selected = invs[:1]
			}
			displayed := (packages.Query{Outdated: true, Find: tc.find}).Filter(packages.Annotate(selected, metas, nil, ""))
			args := outdatedUpdateArgs(displayed, tc.managers)
			if !reflect.DeepEqual(args, tc.want) {
				t.Fatalf("args = %v, want %v", args, tc.want)
			}
			refStart := 1
			if len(tc.managers) > 0 {
				refStart = 3
			}
			plan := packages.PlanUpdates(invs, metas, packages.PlanOptions{Refs: parseRefs(args[refStart:])})
			if len(plan.Unmatched) > 0 || len(plan.Items) != len(tc.want)-refStart {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			allowed := map[string]bool{}
			for _, ref := range tc.want[refStart:] {
				allowed[ref] = true
			}
			for _, item := range plan.Items {
				if !allowed[item.Manager+":"+item.Name] {
					t.Errorf("plan escaped view: %+v", item)
				}
			}
		})
	}
}

func TestOutdatedUpdateHintQuotesShellArguments(t *testing.T) {
	args := []string{"--", "pnpm:@scope/tool", "gh:tool's $(touch /tmp/unexpected)"}
	want := "audit packages update -- pnpm:@scope/tool 'gh:tool'\\''s $(touch /tmp/unexpected)'"
	if got := outdatedUpdateHint(args); got != want {
		t.Fatalf("hint = %q, want %q", got, want)
	}
}

// A plain packages rescan refreshes registry entries past max_age, so its
// versions are not as old as the last `outdated` run; saved views stay
// offline, and refresh_on_scan: false keeps scans offline too.
func TestPackagesRescanRefreshesStaleRegistry(t *testing.T) {
	gh := updateEnv(t)
	looker := &countingLatestLooker{}
	setup := func(a *app) { a.runner, a.looker = gh, looker }
	t.Setenv("AUDIT_PACKAGES_REGISTRY_REFRESH_ON_SCAN", "true")
	if r := runArgsWith(t, setup, "packages", "-r"); r.e != nil || looker.calls.Load() == 0 {
		t.Fatalf("rescan should look up never-checked packages: calls %d err %v", looker.calls.Load(), r.e)
	}
	n := looker.calls.Load()
	if r := runArgsWith(t, setup, "packages", "-r"); r.e != nil || looker.calls.Load() != n {
		t.Errorf("entries younger than max_age are reused: calls %d -> %d %v", n, looker.calls.Load(), r.e)
	}
	if r := runArgsWith(t, setup, "packages", "-l"); r.e != nil || looker.calls.Load() != n {
		t.Errorf("a saved view never looks anything up: %d -> %d %v", n, looker.calls.Load(), r.e)
	}

	gh2 := updateEnv(t)
	off := &countingLatestLooker{}
	t.Setenv("AUDIT_PACKAGES_REGISTRY_REFRESH_ON_SCAN", "false")
	if r := runArgsWith(t, func(a *app) { a.runner, a.looker = gh2, off }, "packages", "-r"); r.e != nil || off.calls.Load() != 0 {
		t.Errorf("refresh_on_scan false keeps scans offline: calls %d err %v", off.calls.Load(), r.e)
	}
}

func TestCoverageLine(t *testing.T) {
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	full := packages.Coverage{Packages: 3, Known: 3, OldestCheck: now.Add(-2 * time.Hour)}
	if got := coverageLine(full, now); got != "Checked 3 of 3 packages; registry data up to 2 hours old." {
		t.Errorf("complete: %q", got)
	}
	partial := packages.Coverage{Packages: 10, Known: 6, Unchecked: 2, Failed: 1, Unknown: 1}
	got := coverageLine(partial, now)
	for _, want := range []string{"Checked 6 of 10", "2 never looked up", "1 failed lookups", "1 without comparable versions", "outdated -F"} {
		if !strings.Contains(got, want) {
			t.Errorf("partial %q lacks %q", got, want)
		}
	}
}
