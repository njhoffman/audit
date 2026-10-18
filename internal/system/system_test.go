package system

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scan"
)

type recorder struct {
	phases []string
	steps  []string
}

func (r *recorder) Phase(label string, _ int) { r.phases = append(r.phases, label) }
func (r *recorder) Step(item string)          { r.steps = append(r.steps, item) }
func (r *recorder) Done()                     {}

func part(kind string, res *scan.Result, err error) Part {
	return Part{Kind: kind, Scan: func(context.Context) (*scan.Result, error) { return res, err }}
}

func TestConvert(t *testing.T) {
	got := Convert("logs", []scan.Finding{
		{Check: "oom-kill", Severity: scan.SeverityError, Subject: "journal", Detail: "OOM (3 hit(s))"},
	})
	want := finding.Finding{Command: "system", Check: "logs.oom_kill", Severity: finding.Error,
		Kind: finding.Issue, Subject: "journal", Message: "OOM (3 hit(s))"}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("got %+v", got)
	}
	if k := got[0].Key(); k != "system:logs.oom_kill:journal" {
		t.Errorf("key %q", k)
	}
}

func TestConvertProgramsSplitsPrefix(t *testing.T) {
	got := Convert("programs", []scan.Finding{
		{Severity: scan.SeverityWarning, Subject: "sshd: PermitRootLogin yes"},
		{Severity: scan.SeverityNotice, Subject: "no prefix here"},
	})
	if got[0].Check != "programs.sshd" || got[0].Subject != "PermitRootLogin yes" {
		t.Errorf("prefixed: %+v", got[0])
	}
	if got[1].Check != "programs" || got[1].Subject != "no prefix here" {
		t.Errorf("unprefixed: %+v", got[1])
	}
}

func TestSeverityMapping(t *testing.T) {
	for in, want := range map[scan.Severity]finding.Severity{
		scan.SeverityCritical: finding.Critical, scan.SeverityError: finding.Error,
		scan.SeverityWarning: finding.Warning, scan.SeverityNotice: finding.Notice,
		scan.SeverityInfo: finding.Info, "bogus": finding.Info,
	} {
		if got := severity(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestStats(t *testing.T) {
	type rec struct{ A int }
	got := Stats("procs", map[string]any{
		"total":      12,
		"load":       1.25,
		"readable":   false,
		"by_status":  map[string]int{"sleep": 10, "run": 2},
		"skipped":    []string{},
		"programs":   []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		"top_cpu":    []rec{{1}, {2}},
		"host":       map[string]any{"nested": map[string]int{"x": 1}},
		"empty":      "",
		"errors":     map[string]string{"x": "y"},
		"none":       nil,
		"empty_map":  map[string]int{},
		"string_val": "ok",
	})
	want := []run.Stat{
		{Group: "procs", Name: "by status", Value: "run=2, sleep=10"},
		{Group: "procs", Name: "empty map", Value: "none"},
		{Group: "procs", Name: "load", Value: "1.2"},
		{Group: "procs", Name: "programs", Value: "a, b, c, d, e, f, g, h (+2 more)"},
		{Group: "procs", Name: "readable", Value: "no"},
		{Group: "procs", Name: "skipped", Value: "none"},
		{Group: "procs", Name: "string val", Value: "ok"},
		{Group: "procs", Name: "top cpu", Value: "2"},
		{Group: "procs", Name: "total", Value: "12"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

func TestScanContinuesPastFailures(t *testing.T) {
	ok := &scan.Result{
		Kind:     "users",
		Summary:  map[string]any{"users_total": 3, "errors": map[string]string{"dmesg": "permission denied"}},
		Findings: []scan.Finding{{Check: "uid_shared", Severity: scan.SeverityWarning, Subject: "UID 5"}},
	}
	rep := &recorder{}
	s := &Scanner{Progress: rep, Parts: []Part{
		part("procs", nil, errors.New("boom")),
		{Kind: "services", Scan: func(context.Context) (*scan.Result, error) { panic("bad") }},
		part("logs", nil, nil),
		part("users", ok, nil),
	}}
	res, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantErrs := []string{"procs: boom", "services: scanner crashed: bad", "logs: scanner returned no result",
		"users dmesg: permission denied"}
	if !reflect.DeepEqual(res.Errors, wantErrs) {
		t.Errorf("errors %q", res.Errors)
	}
	if len(res.Findings) != 1 || res.Findings[0].Check != "users.uid_shared" {
		t.Errorf("findings %+v", res.Findings)
	}
	if len(res.Stats) != 1 || res.Stats[0].Name != "users total" {
		t.Errorf("stats %+v", res.Stats)
	}
	if _, ok := res.Data.Parts["users"]; !ok || len(res.Data.Parts) != 1 {
		t.Errorf("data %+v", res.Data)
	}
	if !strings.Contains(string(res.RawData()), "users_total") {
		t.Errorf("raw data %s", res.RawData())
	}
	if len(rep.steps) != 4 || rep.phases[0] != "scanning system" {
		t.Errorf("progress %+v", rep)
	}
}

func TestScanStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	s := &Scanner{Parts: []Part{
		{Kind: "procs", Scan: func(context.Context) (*scan.Result, error) {
			calls++
			cancel()
			return nil, context.Canceled
		}},
		{Kind: "users", Scan: func(context.Context) (*scan.Result, error) { calls++; return &scan.Result{}, nil }},
	}}
	if _, err := s.Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if calls != 1 {
		t.Errorf("calls %d", calls)
	}
}

func TestNewScanner(t *testing.T) {
	s, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Parts) != len(Kinds) || s.Scope() != "" {
		t.Errorf("all parts: %d scope %q", len(s.Parts), s.Scope())
	}
	s, err = NewScanner(Options{Only: []string{"logs", "procs"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Scope() != "procs,logs" {
		t.Errorf("scope %q", s.Scope())
	}
	for _, o := range []Options{
		{Only: []string{"nope"}},
		{LogSources: []string{"nope"}},
		{Programs: []string{"nope"}},
	} {
		if _, err := NewScanner(o); err == nil {
			t.Errorf("%+v: expected error", o)
		}
	}
}
