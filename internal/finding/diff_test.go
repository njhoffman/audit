package finding

import "testing"

func TestDiff(t *testing.T) {
	f := func(check, subject string, s Severity) Finding {
		return Finding{Command: "repos", Check: check, Subject: subject, Severity: s, Message: check + " " + subject}
	}
	older := []Finding{
		f("repo.dirty", "a", Notice), f("repo.dirty", "b", Notice), f("repo.behind", "a", Info),
		f("repo.dirty", "b", Notice), // a repeat counts once
	}
	newer := []Finding{
		f("repo.dirty", "a", Notice),   // unchanged, even with another message below
		f("repo.behind", "a", Warning), // severity moved
		f("repo.stash", "c", Notice), f("repo.missing", "d", Warning),
	}
	newer[0].Message = "still dirty"
	d := Diff(older, newer)
	if d.Unchanged != 1 || d.Empty() {
		t.Errorf("unchanged %d", d.Unchanged)
	}
	if len(d.Added) != 2 || d.Added[0].Check != "repo.missing" || d.Added[1].Check != "repo.stash" {
		t.Errorf("added, most serious first: %+v", d.Added)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].Subject != "b" {
		t.Errorf("resolved: %+v", d.Resolved)
	}
	if len(d.Changed) != 1 || d.Changed[0].From != Info || d.Changed[0].Severity != Warning {
		t.Errorf("changed: %+v", d.Changed)
	}
	if e := Diff(newer, newer); !e.Empty() || e.Unchanged != 4 {
		t.Errorf("same set: %+v", e)
	}
	if e := Diff(nil, nil); !e.Empty() || e.Added == nil || e.Resolved == nil || e.Changed == nil {
		t.Errorf("empty lists are non-nil for JSON: %+v", e)
	}
}
