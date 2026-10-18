package finding

import (
	"fmt"
	"reflect"
	"testing"
)

func TestKey(t *testing.T) {
	f := Finding{Command: "packages", Check: "exe.conflict", Subject: "tsc"}
	if got := f.Key(); got != "packages:exe.conflict:tsc" {
		t.Errorf("Key() = %q", got)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{
		"warn": Warning, "WARNING": Warning, "E": Error, "crit": Critical, "info": Info, "n": Notice,
	} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("loud"); err == nil {
		t.Error("expected error for unknown severity")
	}
}

func TestSortAndCounts(t *testing.T) {
	fs := []Finding{
		{Check: "b", Severity: Info, Subject: "x"},
		{Check: "a", Severity: Error, Subject: "z"},
		{Check: "a", Severity: Error, Subject: "y"},
		{Check: "c", Severity: Critical},
	}
	Sort(fs)
	var got []string
	for _, f := range fs {
		got = append(got, string(f.Severity)+"/"+f.Subject)
	}
	want := []string{"critical/", "error/y", "error/z", "info/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Sort = %v want %v", got, want)
	}
	c := Count(fs)
	if c.Total() != 4 || c[Error] != 2 || c.Worst() != Critical {
		t.Errorf("Count = %v", c)
	}
	if (Counts{}).Worst() != "" {
		t.Error("empty Worst should be empty")
	}
}

func TestFilter(t *testing.T) {
	fs := []Finding{
		{Check: "path.missing", Severity: Info},
		{Check: "path.duplicate", Severity: Warning},
		{Check: "exe.broken", Severity: Error},
	}
	got := Filter{MinSeverity: Warning, Check: "path"}.Apply(fs)
	if len(got) != 1 || got[0].Check != "path.duplicate" {
		t.Errorf("Apply = %v", got)
	}
	if len(Filter{}.Apply(fs)) != 3 {
		t.Error("empty filter should keep everything")
	}
}

func TestIgnorer(t *testing.T) {
	ig := NewIgnorer([]string{"path.missing", "packages:exe.conflict", "environment:path.duplicate:/a", " "})
	cases := []struct {
		f    Finding
		want bool
	}{
		{Finding{Command: "environment", Check: "path.missing", Subject: "/x"}, true},
		{Finding{Command: "packages", Check: "exe.conflict", Subject: "tsc"}, true},
		{Finding{Command: "other", Check: "exe.conflict", Subject: "tsc"}, false},
		{Finding{Command: "environment", Check: "path.duplicate", Subject: "/a"}, true},
		{Finding{Command: "environment", Check: "path.duplicate", Subject: "/b"}, false},
	}
	for _, tc := range cases {
		if got := ig.Ignored(tc.f); got != tc.want {
			t.Errorf("Ignored(%s) = %v", tc.f.Key(), got)
		}
	}
	kept, ignored := ig.Split([]Finding{cases[0].f, cases[2].f})
	if len(kept) != 1 || len(ignored) != 1 {
		t.Errorf("Split = %v / %v", kept, ignored)
	}
}

func TestRunChecks(t *testing.T) {
	checks := []Check[int]{
		{ID: "a.low", Fn: func(n int) []Finding {
			return []Finding{{Severity: Info, Subject: "x", Message: fmt.Sprint(n)}}
		}},
		{ID: "b.crash", Fn: func(int) []Finding { panic("boom") }},
		{ID: "c.own", Fn: func(int) []Finding {
			return []Finding{{Check: "c.other", Severity: Warning, Kind: Suggestion}}
		}},
	}
	fs := RunChecks("cmd", 7, checks)
	if len(fs) != 3 {
		t.Fatalf("got %d findings: %+v", len(fs), fs)
	}
	if fs[0].Check != "b.crash" || fs[0].Severity != Error || fs[0].Message != "check crashed: boom" {
		t.Errorf("crash finding = %+v", fs[0])
	}
	if fs[1].Check != "c.other" || fs[1].Kind != Suggestion {
		t.Errorf("own check id/kind not kept: %+v", fs[1])
	}
	if fs[2].Command != "cmd" || fs[2].Check != "a.low" || fs[2].Kind != Issue || fs[2].Message != "7" {
		t.Errorf("defaults not applied: %+v", fs[2])
	}
}
