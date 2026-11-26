package cmd

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// saveRepoRuns saves two repos runs an hour apart and returns their IDs.
func saveRepoRuns(t *testing.T) (older, newer int64) {
	t.Helper()
	a, _, _ := loadedApp(t)
	f := func(subject string, s finding.Severity) finding.Finding {
		return finding.Finding{Command: "repos", Check: "repo.dirty", Subject: subject, Severity: s, Kind: finding.Issue, Message: subject + " is dirty"}
	}
	runs := []*run.Run{
		{Command: "repos", Host: "h", StartedAt: testNow.Add(-2 * time.Hour), FinishedAt: testNow.Add(-2 * time.Hour),
			Findings: []finding.Finding{f("/r/a", finding.Notice), f("/r/b", finding.Notice)}},
		{Command: "repos", Host: "h", StartedAt: testNow.Add(-time.Hour), FinishedAt: testNow.Add(-time.Hour),
			Findings: []finding.Finding{f("/r/b", finding.Warning), f("/r/c", finding.Notice)}},
		{Command: "system", Host: "h", StartedAt: testNow, FinishedAt: testNow},
	}
	for _, r := range runs {
		if err := a.store.SaveRun(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	a.close()
	return runs[0].ID, runs[1].ID
}

func TestScanDiff(t *testing.T) {
	env(t)
	r := runArgs(t, "repos", "-w")
	if r.e == nil || !strings.Contains(r.e.Error(), "no saved") {
		t.Errorf("nothing saved: %v %q", r.e, r.out)
	}
	older, newer := saveRepoRuns(t)

	r = runArgs(t, "repos", "--diff")
	if r.e != nil {
		t.Fatal(r.e)
	}
	for _, want := range []string{"repos: findings since run " + strconv.FormatInt(older, 10), "-> run " + strconv.FormatInt(newer, 10),
		"1 added, 1 resolved, 1 changed severity, 0 unchanged.", "Added (1)", "/r/c", "Resolved (1)", "/r/a",
		"Changed severity (1)", "notice -> warning"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q:\n%s", want, r.out)
		}
	}

	r = runArgs(t, "repos", "-w", "-j", "-m", "warning")
	var got diffJSON
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil {
		t.Fatalf("%v %s", r.e, r.out)
	}
	if got.From == nil || got.From.ID != older || got.To.ID != newer || got.Delta == nil ||
		len(got.Delta.Added) != 1 || got.Delta.Added[0].Subject != "/r/b" || len(got.Delta.Resolved) != 0 {
		t.Errorf("the filter applies to both runs (b is new at warning and above): %+v %+v", got, got.Delta)
	}

	r = runArgs(t, "system", "-w")
	if r.e != nil || !strings.Contains(r.out, "No earlier system run is kept to compare with; `audit system --rescan` makes one.") {
		t.Errorf("a single run: %v %q", r.e, r.out)
	}
	r = runArgs(t, "system", "-w", "-j")
	if r.e != nil || !strings.Contains(r.out, `"from": null`) || !strings.Contains(r.out, `"delta": null`) {
		t.Errorf("a single run as JSON: %v %s", r.e, r.out)
	}
	if r := runArgs(t, "repos", "-w", "-l"); r.e == nil {
		t.Error("--diff and --list are exclusive")
	}
}

func TestHistoryRunsDiff(t *testing.T) {
	env(t)
	older, newer := saveRepoRuns(t)
	o, n := strconv.FormatInt(older, 10), strconv.FormatInt(newer, 10)
	for _, args := range [][]string{{n, o}, {o, n}, {n}} {
		r := runArgs(t, append([]string{"history", "runs", "diff"}, args...)...)
		if r.e != nil || !strings.Contains(r.out, "findings since run "+o) || !strings.Contains(r.out, "-> run "+n) {
			t.Errorf("%v: the older run is the baseline: %v\n%s", args, r.e, r.out)
		}
	}
	if r := runArgs(t, "history", "runs", "diff", o); r.e != nil || !strings.Contains(r.out, "No earlier repos run") {
		t.Errorf("the first run: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "history", "runs", "diff", o, strconv.FormatInt(newer+1, 10)); r.e == nil || !strings.Contains(r.e.Error(), "is repos and run") {
		t.Errorf("another command: %v", r.e)
	}
	if r := runArgs(t, "history", "runs", "diff", "999"); r.e == nil || !strings.Contains(r.e.Error(), "no saved run 999") {
		t.Errorf("missing run: %v", r.e)
	}
	if r := runArgs(t, "history", "runs", "diff", "x"); r.e == nil || !strings.Contains(r.e.Error(), "not a run ID") {
		t.Errorf("bad id: %v", r.e)
	}
}
