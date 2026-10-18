package todo

import (
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

func f(check string, sev finding.Severity, subject, msg string) finding.Finding {
	return finding.Finding{Command: "packages", Check: check, Severity: sev, Kind: finding.Issue, Subject: subject, Message: msg}
}

func TestPriorityFor(t *testing.T) {
	cases := map[finding.Severity]Priority{
		finding.Critical: High, finding.Error: High, finding.Warning: Medium, finding.Notice: Low, finding.Info: "",
	}
	for sev, want := range cases {
		if got := PriorityFor(f("c", sev, "s", "m")); got != want {
			t.Errorf("PriorityFor(%s) = %q want %q", sev, got, want)
		}
	}
	s := f("c", finding.Info, "s", "m")
	s.Kind = finding.Suggestion
	if PriorityFor(s) != Suggestion {
		t.Error("suggestions map to the suggestion priority regardless of severity")
	}
}

func TestDeriveAggregatesInfoPerCheck(t *testing.T) {
	fs := []finding.Finding{
		f("exe.conflict", finding.Warning, "tsc", "2 packages provide tsc"),
		f("pnpm.legacy_shim", finding.Info, "eslint", "stale shim"),
		f("pnpm.legacy_shim", finding.Info, "prettier", ""),
		f("path.missing", finding.Info, "/gone", "/gone"),
	}
	ts := Derive(fs)
	if len(ts) != 3 {
		t.Fatalf("want 3 tasks, got %d: %+v", len(ts), ts)
	}
	if ts[0].Key != "packages:exe.conflict:tsc" || ts[0].Priority != Medium || ts[0].Title != "tsc: 2 packages provide tsc" {
		t.Errorf("finding task wrong: %+v", ts[0])
	}
	shim := ts[1]
	if shim.Key != "packages:pnpm.legacy_shim:*" || shim.Priority != Low || shim.Source != FromAggregate {
		t.Errorf("aggregate task wrong: %+v", shim)
	}
	if !strings.Contains(shim.Title, "Review 2 items from pnpm.legacy_shim") {
		t.Errorf("aggregate title: %q", shim.Title)
	}
	if strings.Join(shim.Details, "|") != "eslint: stale shim|prettier" {
		t.Errorf("aggregate details: %v", shim.Details)
	}
	if !strings.Contains(ts[2].Title, "1 item from") || ts[2].Details[0] != "/gone" {
		t.Errorf("single aggregate: %+v", ts[2])
	}
}

func TestDeriveMergesDuplicateKeys(t *testing.T) {
	ts := Derive([]finding.Finding{
		f("x", finding.Notice, "a", "first"),
		f("x", finding.Error, "a", "second"),
	})
	if len(ts) != 1 || ts[0].Priority != High || len(ts[0].Details) != 1 {
		t.Errorf("duplicate keys not merged: %+v", ts)
	}
}

func TestTitleFor(t *testing.T) {
	cases := []struct{ subject, msg, want string }{
		{"", "msg", "msg"},
		{"subj", "", "subj"},
		{"tsc", "tsc is shadowed", "tsc is shadowed"},
		{"tsc", "shadowed", "tsc: shadowed"},
		{"adm", "members: x; membership in adm confers privileges", "adm: members: x; membership in adm confers privileges"},
	}
	for _, c := range cases {
		if got := titleFor(finding.Finding{Subject: c.subject, Message: c.msg}); got != c.want {
			t.Errorf("titleFor(%q,%q) = %q want %q", c.subject, c.msg, got, c.want)
		}
	}
}

func byKey(ts []Todo) map[string]Todo {
	m := map[string]Todo{}
	for _, t := range ts {
		m[t.Key] = t
	}
	return m
}

func TestReconcileLifecycle(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	derived := Derive([]finding.Finding{
		f("a", finding.Error, "1", "m"),
		f("b", finding.Warning, "2", "m"),
		f("c", finding.Warning, "3", "m"),
		f("d", finding.Warning, "4", "m"),
	})
	created := Reconcile("packages", nil, derived, t0)
	if len(created) != 4 || created[0].Status != Open || !created[0].CreatedAt.Equal(t0) {
		t.Fatalf("creation wrong: %+v", created)
	}
	stored := byKey(created)
	set := func(k string, s Status) {
		x := stored[k]
		x.Status = s
		stored[k] = x
	}
	set("packages:b:2", WontDo)
	set("packages:c:3", Done)
	set("packages:d:4", InProgress)
	manual := Todo{Key: "manual:1", Command: "packages", Source: Manual, Status: Open}
	other := Todo{Key: "system:x:y", Command: "system", Source: FromFinding, Status: Open}
	existing := []Todo{stored["packages:a:1"], stored["packages:b:2"], stored["packages:c:3"], stored["packages:d:4"], manual, other}

	// Rescan: a and b gone, c (done) still present, d still present.
	changed := byKey(Reconcile("packages", existing, Derive([]finding.Finding{
		f("c", finding.Warning, "3", "m"),
		f("d", finding.Error, "4", "now worse"),
	}), t1))

	if got := changed["packages:a:1"]; got.Status != Resolved || !got.ResolvedAt.Equal(t1) {
		t.Errorf("vanished open task should resolve: %+v", got)
	}
	if _, ok := changed["packages:b:2"]; ok {
		t.Error("won't-do task must not change when its finding vanishes")
	}
	if got := changed["packages:c:3"]; got.Status != Open {
		t.Errorf("done task with a live finding should reopen: %+v", got)
	}
	if got := changed["packages:d:4"]; got.Status != InProgress || got.Priority != High || got.Title != "4: now worse" {
		t.Errorf("in-progress task should keep status and refresh fields: %+v", got)
	}
	if _, ok := changed["manual:1"]; ok {
		t.Error("manual tasks are never reconciled")
	}
	if _, ok := changed["system:x:y"]; ok {
		t.Error("other commands' tasks are never reconciled")
	}

	// A resolved task reopens when its finding returns; won't-do never reopens.
	resolved := changed["packages:a:1"]
	wont := stored["packages:b:2"]
	again := byKey(Reconcile("packages", []Todo{resolved, wont}, Derive([]finding.Finding{
		f("a", finding.Error, "1", "m"), f("b", finding.Warning, "2", "m"),
	}), t1.Add(time.Hour)))
	if again["packages:a:1"].Status != Open || !again["packages:a:1"].ResolvedAt.IsZero() {
		t.Errorf("resolved task should reopen: %+v", again["packages:a:1"])
	}
	if again["packages:b:2"].Status != WontDo {
		t.Errorf("won't-do must stay closed: %+v", again["packages:b:2"])
	}
}

func TestParseStatusAndPriority(t *testing.T) {
	for in, want := range map[string]Status{
		"in-progress": InProgress, "In Progress": InProgress, "wip": InProgress, "won't do": WontDo,
		"wont-do": WontDo, "done": Done, "reopen": Open, "resolved": Resolved,
	} {
		if got, err := ParseStatus(in); err != nil || got != want {
			t.Errorf("ParseStatus(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseStatus("later"); err == nil {
		t.Error("expected error")
	}
	if p, err := ParsePriority("M"); err != nil || p != Medium {
		t.Errorf("ParsePriority(M) = %q, %v", p, err)
	}
	if _, err := ParsePriority("urgent"); err == nil {
		t.Error("expected error")
	}
}

func TestSortAndFilter(t *testing.T) {
	ts := []Todo{
		{ID: 1, Command: "b", Priority: Low, Status: Open, Title: "low"},
		{ID: 2, Command: "a", Priority: High, Status: Done, Title: "done"},
		{ID: 3, Command: "a", Priority: Medium, Status: InProgress, Title: "wip"},
		{ID: 4, Command: "a", Priority: High, Status: Open, Title: "high", Note: "needle"},
	}
	Sort(ts)
	var ids []int64
	for _, x := range ts {
		ids = append(ids, x.ID)
	}
	if want := []int64{3, 4, 1, 2}; !equal(ids, want) {
		t.Errorf("Sort ids = %v want %v", ids, want)
	}
	if got := (Filter{}).Apply(ts); len(got) != 3 {
		t.Errorf("default filter hides closed: %v", got)
	}
	if got := (Filter{ShowClosed: true, Command: "a"}).Apply(ts); len(got) != 3 {
		t.Errorf("command filter: %v", got)
	}
	if got := (Filter{Statuses: []Status{Done}}).Apply(ts); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("status filter: %v", got)
	}
	if got := (Filter{Priorities: []Priority{High}, Search: "NEEDLE"}).Apply(ts); len(got) != 1 || got[0].ID != 4 {
		t.Errorf("priority+search filter: %v", got)
	}
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
