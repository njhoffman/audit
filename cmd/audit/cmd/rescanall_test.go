package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
)

// fakeScans records the scans of fake scanners.
type fakeScans struct {
	mu       sync.Mutex
	order    []string
	inFlight int
	peak     int
	fail     map[string]bool
}

type recordingScanner struct {
	command string
	f       *fakeScans
}

func (s recordingScanner) Command() string { return s.command }
func (s recordingScanner) Scope() string   { return "" }

func (s recordingScanner) Scan(_ context.Context, rep progress.Reporter) (*core.Outcome, error) {
	s.f.mu.Lock()
	s.f.order = append(s.f.order, s.command)
	s.f.inFlight++
	s.f.peak = max(s.f.peak, s.f.inFlight)
	fail := s.f.fail[s.command]
	s.f.mu.Unlock()
	rep.Phase("working", 0)
	time.Sleep(20 * time.Millisecond)
	s.f.mu.Lock()
	s.f.inFlight--
	s.f.mu.Unlock()
	if fail {
		return nil, errors.New("boom")
	}
	return &core.Outcome{Findings: []finding.Finding{{Command: s.command, Check: s.command + ".x", Severity: finding.Warning, Subject: "s", Message: "m"}}}, nil
}

func (f *fakeScans) setup(a *app) {
	a.scanner = func(c string) (core.Scanner, error) { return recordingScanner{c, f}, nil }
}

func (f *fakeScans) scanned() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.order)
	f.order = nil
	return out
}

func TestRescanAll(t *testing.T) {
	cfgHome, _ := env(t)
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte("scan: {concurrency: 2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeScans{}

	r := runArgsWith(t, f.setup, "-r")
	got := f.scanned()
	if r.e != nil || len(got) != len(core.Commands) || got[0] != "packages" {
		t.Fatalf("-r scans every never-run command, packages first: %v %v", r.e, got)
	}
	if f.peak > 2 {
		t.Errorf("scan.concurrency 2, but %d scans ran at once", f.peak)
	}
	if !strings.Contains(r.out, "COMMAND") || !strings.Contains(r.out, "environment") {
		t.Errorf("-r prints the summary: %q", r.out)
	}
	if !strings.Contains(r.err, "system: scanning") || !strings.Contains(r.err, "system: ") || !strings.Contains(r.err, "1 task(s) updated") {
		t.Errorf("without a terminal each scan gets a start and an end line: %q", r.err)
	}

	r = runArgsWith(t, f.setup, "-r")
	if got := f.scanned(); r.e != nil || len(got) != 0 || !strings.Contains(r.err, "Every command is fresh") {
		t.Errorf("fresh commands are skipped: %v %v %q", r.e, got, r.err)
	}

	r = runArgsWith(t, f.setup, "-a", "-O", "ai,system")
	if got := f.scanned(); r.e != nil || !slices.Equal(sorted(got), []string{"ai", "system"}) {
		t.Errorf("-a -O ai,system rescans just those: %v %v", r.e, got)
	}

	if r = runArgsWith(t, f.setup, "-r", "-O", "bogus"); r.e == nil || !strings.Contains(r.e.Error(), `unknown command "bogus"`) {
		t.Errorf("unknown --only command: %v", r.e)
	}
}

func TestRescanAllKeepsGoing(t *testing.T) {
	env(t)
	f := &fakeScans{fail: map[string]bool{"files": true}}
	r := runArgsWith(t, f.setup, "-r")
	if got := f.scanned(); len(got) != len(core.Commands) {
		t.Errorf("a failed scan does not stop the others: %v", got)
	}
	if r.e == nil || !strings.Contains(r.e.Error(), fmt.Sprintf("1 of %d scans failed", len(core.Commands))) || !strings.Contains(r.e.Error(), "files: boom") {
		t.Errorf("error = %v", r.e)
	}
	r = runArgsWith(t, f.setup, "-r")
	if got := f.scanned(); !slices.Equal(got, []string{"files"}) {
		t.Errorf("the failed command is still stale: %v", got)
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
