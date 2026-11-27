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
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/todo"
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

func TestRescanAllWithAIReview(t *testing.T) {
	cfgHome, _ := env(t)
	claude, stdin, _ := fakeAI(t, "claude", claudeJSON(t, map[string]any{"subtype": "success", "result": "## Summary\n\nFine."}))
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude+"}}\n")
	f := &fakeScans{}
	if r := runArgsWith(t, f.setup, "-A"); r.e == nil || !strings.Contains(r.e.Error(), "add -r") {
		t.Errorf("--ai alone: %v", r.e)
	}
	r := runArgsWith(t, f.setup, "-r", "-A", "-O", "system")
	if r.e != nil || !slices.Equal(f.scanned(), []string{"system"}) {
		t.Fatalf("%v\n%s", r.e, r.err)
	}
	if p := readFile(t, stdin); !strings.Contains(p, "system.x") {
		t.Errorf("the rescanned run is reviewed:\n%s", p)
	}
	a, _, _ := loadedApp(t)
	saved, err := a.engine.Saved(context.Background(), "system", "")
	if err != nil || saved == nil || saved.Analysis == nil {
		t.Errorf("the review is saved with the run: %+v %v", saved, err)
	}
}

func TestRescanAllNotifies(t *testing.T) {
	cfgHome, _ := env(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	f := &fakeScans{}
	fake := &exec.Fake{}
	fake.AddOutput("", "notify-send")
	setup := func(a *app) { f.setup(a); a.runner = fake }
	notified := func() []string {
		var out []string
		for _, c := range fake.Calls {
			if c[0] == "notify-send" {
				out = append(out, strings.Join(c[1:], " | "))
			}
		}
		fake.Calls = nil
		return out
	}

	// Off by default.
	if r := runArgsWith(t, setup, "-r", "-O", "system"); r.e != nil || len(notified()) != 0 {
		t.Fatalf("disabled: %v %v", r.e, notified())
	}
	writeConfig(t, cfgHome, "notify: {enabled: true, min_priority: medium}\n")
	// The system task is open already; repos' warning makes a new medium one.
	r := runArgsWith(t, setup, "-r", "-a", "-O", "system,repos")
	n := notified()
	if r.e != nil || len(n) != 1 || !strings.Contains(n[0], "audit: 1 new task(s) at medium or above") || !strings.Contains(n[0], "repos:") ||
		strings.Contains(n[0], "system:") {
		t.Fatalf("one new task: %v %v", r.e, n)
	}
	if r := runArgsWith(t, setup, "-r", "-a", "-O", "repos"); r.e != nil || len(notified()) != 0 {
		t.Errorf("nothing new, no notification: %v", r.e)
	}
	writeConfig(t, cfgHome, "notify: {enabled: true}\n")
	if r := runArgsWith(t, setup, "-r", "-a", "-O", "files"); r.e != nil || len(notified()) != 0 {
		t.Errorf("a new medium task is below the default high: %v", r.e)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	writeConfig(t, cfgHome, "notify: {enabled: true, min_priority: low}\n")
	if r := runArgsWith(t, setup, "-r", "-a", "-O", "ai"); r.e != nil || len(notified()) != 0 {
		t.Errorf("no session bus, no notification: %v", r.e)
	}
}

func TestNewUrgentTasks(t *testing.T) {
	before := map[int64]bool{1: true}
	after := []todo.Todo{
		{ID: 1, Priority: todo.High, Status: todo.Open},
		{ID: 2, Priority: todo.High, Status: todo.Open},
		{ID: 3, Priority: todo.Low, Status: todo.Open},
		{ID: 4, Priority: todo.High, Status: todo.Resolved},
		{ID: 5, Priority: todo.Medium, Status: todo.InProgress},
	}
	got := newUrgentTasks(before, after, todo.Medium)
	if len(got) != 2 || got[0].ID != 5 || got[1].ID != 2 { // todo.Sort: in progress first
		t.Errorf("%+v", got)
	}
}

func TestReviewOnScan(t *testing.T) {
	cfgHome, _ := env(t)
	review := `{"points":[{"title":"Rotate the old keys","subject":"","severity":"notice","details":["3 keys older than a year"],"fix":"ssh-keygen"},` +
		`{"title":"Same subject as a finding","subject":"s","severity":"info","details":[],"fix":""}]}`
	claude, stdin, argv := fakeAI(t, "claude", claudeJSON(t, map[string]any{"subtype": "success", "result": review, "total_cost_usd": 0.5}))
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude+"}, review_on_scan: [system], review_daily_usd: 0.4}\n")
	f := &fakeScans{}
	if r := runArgsWith(t, f.setup, "-r", "-O", "system"); r.e != nil {
		t.Fatalf("%v\n%s", r.e, r.err)
	}
	if p := readFile(t, stdin) + readFile(t, argv); !strings.Contains(p, "system.x") || !strings.Contains(p, "NOT already cover") {
		t.Errorf("the scan's findings are sent:\n%s", p)
	}
	a, _, _ := loadedApp(t)
	ctx := context.Background()
	saved, err := a.engine.Saved(ctx, "system", "")
	if err != nil || saved == nil {
		t.Fatal(err)
	}
	var ai []finding.Finding
	for _, x := range saved.Findings {
		if x.Check == "ai.review" {
			ai = append(ai, x)
		}
	}
	if len(ai) != 1 || ai[0].Subject != "rotate-the-old-keys" || ai[0].Kind != finding.Suggestion {
		t.Errorf("one point becomes a finding, the one about a reported subject is dropped: %+v", ai)
	}
	ts, _ := a.store.Todos(ctx, "system")
	if !slices.ContainsFunc(ts, func(x todo.Todo) bool { return x.Check == "ai.review" && x.Priority == todo.Suggestion }) {
		t.Errorf("it becomes a suggestion task: %+v", ts)
	}
	a.close()

	// The same result set is answered from the cache although $0.50 is past
	// the $0.40 cap; a new one is skipped for the day.
	if err := os.Remove(stdin); err != nil {
		t.Fatal(err)
	}
	if r := runArgsWith(t, f.setup, "-r", "-a", "-O", "system"); r.e != nil {
		t.Fatal(r.e)
	}
	if _, err := os.Stat(stdin); err == nil {
		t.Error("a cached review does not call the AI")
	}
	writeConfig(t, cfgHome, "ai: {claude: {command: "+claude+"}, review_on_scan: [system, repos], review_daily_usd: 0.4}\n")
	if r := runArgsWith(t, f.setup, "-r", "-a", "-O", "repos"); r.e != nil {
		t.Fatal(r.e)
	}
	a, _, _ = loadedApp(t)
	saved, _ = a.engine.Saved(ctx, "repos", "")
	if saved == nil || !slices.ContainsFunc(saved.Errors, func(e string) bool { return strings.Contains(e, "ai review skipped: today's AI spend $0.50") }) {
		t.Errorf("over budget: %+v", saved)
	}
	writeConfig(t, cfgHome, "ai: {review_on_scan: [nope]}\n")
	if r := runArgs(t, "todo"); r.e == nil || !strings.Contains(r.e.Error(), `ai.review_on_scan: unknown command "nope"`) {
		t.Errorf("bad command: %v", r.e)
	}
}
