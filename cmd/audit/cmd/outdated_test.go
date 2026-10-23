package cmd

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

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
