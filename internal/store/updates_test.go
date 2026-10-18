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
		{Manager: "uv", ID: "black", Name: "black", From: "24.1", To: "25.1", Status: packages.UpdateOK},
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
	if !reflect.DeepEqual(last, second) {
		t.Errorf("last:\n got %+v\nwant %+v", last, second)
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
