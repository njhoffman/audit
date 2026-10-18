package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

func TestUpdatesRoundTrip(t *testing.T) {
	s := open(t)
	if u, err := s.LastUpdate(ctx); err != nil || u != nil {
		t.Fatalf("empty store: %+v %v", u, err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	first := &packages.Update{Host: "h", StartedAt: at, FinishedAt: at.Add(time.Minute), Items: []packages.UpdateResult{
		{Manager: "uv", ID: "ruff", Name: "ruff", From: "0.9.0", Latest: "0.9.5", Status: packages.UpdateFailed,
			Command: "uv tool upgrade ruff", Code: 2, Duration: 1500 * time.Millisecond, Reason: "exit status 2", Output: "error"},
		{Manager: "uv", ID: "black", Name: "black", From: "24.1", Latest: "25.1", Status: packages.UpdateFailed, Reason: "exit status 1"},
		{Manager: "uv", ID: "mypy", Name: "mypy", From: "1.0", Latest: "1.1", Status: packages.UpdateFailed, Reason: "exit status 1"},
	}}
	if err := s.SaveUpdate(ctx, first); err != nil || first.ID == 0 {
		t.Fatalf("save: %v id %d", err, first.ID)
	}
	// black succeeds later; mypy is only skipped later, which leaves its
	// failure standing.
	second := &packages.Update{Host: "h", StartedAt: at.Add(time.Hour), FinishedAt: at.Add(time.Hour), Items: []packages.UpdateResult{
		{Manager: "uv", ID: "black", Name: "black", From: "24.1", To: "25.1", Status: packages.UpdateOK, Kind: packages.KindPackage},
		{Manager: "uv", ID: "mypy", Name: "mypy", From: "1.0", Status: packages.UpdateSkipped, Reason: "not run: interrupted"},
	}}
	if err := s.SaveUpdate(ctx, second); err != nil {
		t.Fatal(err)
	}
	last, err := s.LastUpdate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last.StartedAt, last.FinishedAt = last.StartedAt.UTC(), last.FinishedAt.UTC()
	// An unset kind is saved as a package.
	second.Items[1].Kind = packages.KindPackage
	if !reflect.DeepEqual(last, second) {
		t.Errorf("last:\n got %+v\nwant %+v", last, second)
	}
	all, err := s.Updates(ctx, 5)
	if err != nil || len(all) != 2 || all[0].ID != second.ID || len(all[1].Items) != 3 || all[1].Items[0].Output != "error" {
		t.Errorf("updates: %v %+v", err, all)
	}
	fails, err := s.UpdateFailures(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fails) != 2 || fails["uv:ruff"].Reason != "exit status 2" || fails["uv:ruff"].From != "0.9.0" ||
		!fails["uv:mypy"].At.Equal(first.FinishedAt) {
		t.Errorf("failures = %+v", fails)
	}

	if err := s.PruneUpdates(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fails, _ = s.UpdateFailures(ctx); len(fails) != 0 {
		t.Errorf("pruned failures should go with their run: %+v", fails)
	}
}

func TestUpdateKinds(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	pkg := &packages.Update{StartedAt: at, FinishedAt: at, Items: []packages.UpdateResult{
		{Manager: "uv", ID: "ruff", Name: "ruff", Status: packages.UpdateOK}}}
	mig := &packages.Update{StartedAt: at.Add(time.Hour), FinishedAt: at.Add(time.Hour), Items: []packages.UpdateResult{
		{Manager: "uv", ID: "ruff", Name: "ruff", From: "3.14.8", Status: packages.UpdateFailed, Reason: "exit status 1",
			Kind: packages.KindMigration},
		{Manager: "uv", ID: "python3.12", Name: "python3.12", Status: packages.UpdateOK, Kind: packages.KindRuntime}}}
	for _, u := range []*packages.Update{pkg, mig} {
		if err := s.SaveUpdate(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if u, err := s.LastUpdateOf(ctx, packages.KindPackage); err != nil || u == nil || u.ID != pkg.ID {
		t.Errorf("last package update: %+v %v", u, err)
	}
	u, err := s.LastUpdateOf(ctx, packages.KindRuntime, packages.KindMigration)
	if err != nil || u == nil || u.ID != mig.ID || u.Items[0].Kind != packages.KindMigration || u.Items[1].Kind != packages.KindRuntime {
		t.Errorf("last runtime update: %+v %v", u, err)
	}
	if u, err := s.LastUpdate(ctx); err != nil || u.ID != mig.ID {
		t.Errorf("any kind: %+v %v", u, err)
	}
	if fails, err := s.UpdateFailures(ctx); err != nil || len(fails) != 0 {
		t.Errorf("a failed migration is not a failed package update: %+v %v", fails, err)
	}
	if u, err := open(t).LastUpdateOf(ctx, packages.KindRuntime); err != nil || u != nil {
		t.Errorf("empty store: %+v %v", u, err)
	}
}

func TestRuntimeMetaRoundTrip(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	in := []packages.RuntimeMeta{
		{Name: "node", Lines: map[string]string{"24": "24.22.0"}, Newest: "24.22.0", CheckedAt: at},
		{Name: "rust", Toolchains: []packages.Toolchain{{Name: "stable", Installed: "1.99.1"}}, CheckedAt: at, Error: "offline"},
	}
	if err := s.SaveRuntimeMeta(ctx, in); err != nil {
		t.Fatal(err)
	}
	in[0].Newest = "26.0.0"
	if err := s.SaveRuntimeMeta(ctx, in[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := s.RuntimeMeta(ctx)
	if err != nil || len(got) != 2 || got["node"].Newest != "26.0.0" || got["node"].Lines["24"] != "24.22.0" ||
		got["rust"].Error != "offline" || got["rust"].Toolchains[0].Installed != "1.99.1" || !got["rust"].CheckedAt.Equal(at) {
		t.Errorf("runtime meta: %+v %v", got, err)
	}
}
