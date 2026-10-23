package cmd

import (
	"context"
	"encoding/json"
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
	r = runUpdate(t, gh, false, "", "packages", "update", "-y", "gh:ok")
	if r.e != nil || len(gh.upgrades) != 1 {
		t.Fatalf("update selected outdated package: %s %v", r.out, r.e)
	}
	r = runArgsWith(t, setup, "packages", "outdated", "-j", "-f", "ok")
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil || len(got.Packages) != 0 {
		t.Fatalf("updated package still outdated: %s %v", r.out, r.e)
	}
}
