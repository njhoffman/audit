package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
	"github.com/njhoffman/audit/internal/version"
)

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// env isolates config and data in temp dirs and pins the clock.
func env(t *testing.T) (cfgHome, dataHome string) {
	t.Helper()
	cfgHome, dataHome = t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("NO_COLOR", "1")
	old := timeNow
	timeNow = func() time.Time { return testNow }
	t.Cleanup(func() { timeNow = old })
	return cfgHome, dataHome
}

type result struct {
	out, err string
	e        error
	app      *app
}

func runArgs(t *testing.T, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return false }
	a.opener = func(string) error { return errors.New("opener called") }
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	return result{out.String(), errOut.String(), e, a}
}

func TestVersion(t *testing.T) {
	env(t)
	for _, f := range []string{"--version", "-V"} {
		r := runArgs(t, f)
		if r.e != nil {
			t.Fatal(r.e)
		}
		if want := "audit " + version.String() + "\n"; r.out != want {
			t.Errorf("%s: got %q want %q", f, r.out, want)
		}
	}
}

func TestHelpListsCommands(t *testing.T) {
	env(t)
	r := runArgs(t, "--help")
	if r.e != nil {
		t.Fatal(r.e)
	}
	for _, c := range []string{"system", "environment", "packages", "todo", "history", "config", "--summary", "--no-color"} {
		if !strings.Contains(r.out, c) {
			t.Errorf("help missing %q", c)
		}
	}
}

func TestEveryFlagHasShortForm(t *testing.T) {
	env(t)
	a := newApp(&bytes.Buffer{}, &bytes.Buffer{})
	root := newRootCmd(a)
	cmds := root.Commands()
	cmds = append(cmds, root)
	for i := 0; i < len(cmds); i++ {
		c := cmds[i]
		if c != root {
			cmds = append(cmds, c.Commands()...)
		}
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name != "help" && f.Shorthand == "" {
				t.Errorf("%s --%s has no short form", c.CommandPath(), f.Name)
			}
		})
	}
}

func TestBareAuditPrintsSummaryWhenNotInteractive(t *testing.T) {
	env(t)
	r := runArgs(t)
	if r.e != nil {
		t.Fatal(r.e)
	}
	for _, c := range core.Commands {
		if !strings.Contains(r.out, c) {
			t.Errorf("summary missing %s:\n%s", c, r.out)
		}
	}
	if !strings.Contains(r.out, "never") {
		t.Errorf("fresh install should show never-run commands:\n%s", r.out)
	}
}

func TestSavedOnlyWithoutRunFails(t *testing.T) {
	env(t)
	r := runArgs(t, "system", "--report")
	if r.e == nil || !errors.Is(r.e, core.ErrNoSavedRun) {
		t.Fatalf("want ErrNoSavedRun, got %v", r.e)
	}
	if !strings.Contains(r.e.Error(), "audit system --rescan") {
		t.Errorf("error should suggest the rescan command: %v", r.e)
	}
}

func TestScanOutputFlagsAreExclusive(t *testing.T) {
	env(t)
	r := runArgs(t, "packages", "--report", "--json")
	if r.e == nil {
		t.Fatal("--report with --json should fail")
	}
}

func TestUnknownManager(t *testing.T) {
	env(t)
	r := runArgs(t, "packages", "-M", "nosuch", "-r")
	if r.e == nil || !strings.Contains(r.e.Error(), "nosuch") {
		t.Fatalf("want unknown manager error, got %v", r.e)
	}
}

func TestBadSeverity(t *testing.T) {
	env(t)
	r := runArgs(t, "system", "-m", "loud")
	if r.e == nil {
		t.Fatal("bad --min-severity should fail")
	}
}

func TestConfigInitPathAndShow(t *testing.T) {
	cfgHome, _ := env(t)
	want := filepath.Join(cfgHome, "audit.yaml")

	r := runArgs(t, "config", "--path")
	if r.e != nil || strings.TrimSpace(r.out) != want {
		t.Fatalf("path: %q %v", r.out, r.e)
	}
	if _, err := os.Stat(want); err == nil {
		t.Fatal("--path must not create the file")
	}
	r = runArgs(t, "config")
	if r.e != nil || !strings.HasPrefix(r.out, "# "+want) || !strings.Contains(r.err, "created "+want) {
		t.Fatalf("first show should create the file: %q %q %v", r.out, r.err, r.e)
	}
	if r = runArgs(t, "config", "-i"); r.e == nil || !strings.Contains(r.e.Error(), "already exists") {
		t.Fatalf("second init should refuse: %v", r.e)
	}
	if r = runArgs(t, "config", "-i", "-f"); r.e != nil {
		t.Fatalf("forced init: %v", r.e)
	}
	r = runArgs(t, "config")
	if r.e != nil || !strings.HasPrefix(r.out, "# "+want) {
		t.Fatalf("show file: %q %v", r.out, r.e)
	}
}

func TestFirstRunCreatesConfig(t *testing.T) {
	cfgHome, _ := env(t)
	want := filepath.Join(cfgHome, "audit.yaml")
	r := runArgs(t, "todo")
	if r.e != nil || !strings.Contains(r.err, "created "+want) {
		t.Fatalf("first run: %q %v", r.err, r.e)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatal(err)
	}
	if r = runArgs(t, "todo"); strings.Contains(r.err, "created") {
		t.Errorf("second run must not recreate: %q", r.err)
	}

	cfgHome, _ = env(t)
	if r = runArgs(t, "-q", "todo"); r.e != nil || r.err != "" {
		t.Errorf("--quiet should create silently: %q %v", r.err, r.e)
	}
	if _, err := os.Stat(filepath.Join(cfgHome, "audit.yaml")); err != nil {
		t.Error("--quiet must still create the file")
	}

	_, _ = env(t)
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	if r = runArgs(t, "-c", missing, "todo"); r.e == nil {
		t.Error("a missing --config must fail, not be created")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("--config file must not be created")
	}
}

func TestTodoLifecycle(t *testing.T) {
	env(t)
	r := runArgs(t, "todo", "add", "clean", "up", "-p", "high", "-H", "rm -rf ~/junk")
	if r.e != nil || r.out != "#1 added\n" {
		t.Fatalf("add: %q %v", r.out, r.e)
	}
	r = runArgs(t, "todo", "-j")
	var ts []todo.Todo
	if err := json.Unmarshal([]byte(r.out), &ts); err != nil || len(ts) != 1 {
		t.Fatalf("list json: %q %v", r.out, err)
	}
	if ts[0].Title != "clean up" || ts[0].Priority != todo.High || ts[0].Command != "manual" || ts[0].Source != todo.Manual {
		t.Errorf("unexpected task %+v", ts[0])
	}

	if r = runArgs(t, "todo", "set", "1", "in-progress", "-N", "halfway"); r.e != nil {
		t.Fatal(r.e)
	}
	r = runArgs(t, "todo", "show", "#1", "-j")
	var one todo.Todo
	if err := json.Unmarshal([]byte(r.out), &one); err != nil {
		t.Fatal(err)
	}
	if one.Status != todo.InProgress || one.Note != "halfway" {
		t.Errorf("after set: %+v", one)
	}

	if r = runArgs(t, "todo", "note", "1", "almost", "done"); r.e != nil {
		t.Fatal(r.e)
	}
	if r = runArgs(t, "todo", "set", "1", "done"); r.e != nil {
		t.Fatal(r.e)
	}
	r = runArgs(t, "todo")
	if !strings.Contains(r.out, "No tasks match") {
		t.Errorf("done tasks should be hidden by default:\n%s", r.out)
	}
	r = runArgs(t, "todo", "-a", "-f", "clean")
	if !strings.Contains(r.out, "clean up") {
		t.Errorf("--all should show done tasks:\n%s", r.out)
	}

	if r = runArgs(t, "todo", "rm", "1"); r.e != nil {
		t.Fatal(r.e)
	}
	r = runArgs(t, "todo", "-a", "-j")
	if strings.TrimSpace(r.out) != "[]" {
		t.Errorf("after rm: %q", r.out)
	}
}

func TestTodoBadInput(t *testing.T) {
	env(t)
	for _, args := range [][]string{
		{"todo", "set", "x", "done"},
		{"todo", "set", "0", "done"},
		{"todo", "set", "1", "finished-ish"},
		{"todo", "add", "t", "-p", "urgent"},
		{"todo", "-p", "urgent"},
		{"todo", "show", "99"},
		{"todo", "-i"},
	} {
		if r := runArgs(t, args...); r.e == nil {
			t.Errorf("%v should fail", args)
		}
	}
}

func TestHistoryValidatesCommand(t *testing.T) {
	env(t)
	if r := runArgs(t, "history", "nosuch"); r.e == nil {
		t.Fatal("unknown command should fail")
	}
	r := runArgs(t, "history", "-j")
	if r.e != nil || strings.TrimSpace(r.out) != "[]" {
		t.Fatalf("%q %v", r.out, r.e)
	}
}

type fakeScanner struct {
	findings []finding.Finding
	scans    int
}

func (f *fakeScanner) Command() string { return "packages" }
func (f *fakeScanner) Scope() string   { return "" }
func (f *fakeScanner) Scan(context.Context, progress.Reporter) (*core.Outcome, error) {
	f.scans++
	return &core.Outcome{Findings: f.findings, Stats: []run.Stat{{Name: "packages", Value: "3"}}}, nil
}

func loadedApp(t *testing.T) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	a.engine.Now = timeNow
	t.Cleanup(a.close)
	return a, &out, &errOut
}

func TestRunScanModes(t *testing.T) {
	env(t)
	a, out, errOut := loadedApp(t)
	s := &fakeScanner{findings: []finding.Finding{
		{Command: "packages", Check: "pkg.broken", Severity: finding.Error, Subject: "foo", Message: "foo is broken"},
		{Command: "packages", Check: "pkg.note", Severity: finding.Info, Subject: "bar", Message: "bar note"},
	}}
	ctx := context.Background()

	if err := a.runScan(ctx, s, &scanFlags{json: true}, nil); !errors.Is(err, core.ErrNoSavedRun) {
		t.Fatalf("json with no run: %v", err)
	}
	if err := a.runScan(ctx, s, &scanFlags{}, nil); err != nil {
		t.Fatal(err)
	}
	if s.scans != 1 || !strings.Contains(out.String(), "foo is broken") {
		t.Fatalf("auto with no run should scan and report: scans=%d\n%s", s.scans, out)
	}
	if !strings.Contains(errOut.String(), "2 task(s) updated") {
		t.Errorf("want task notice, got %q", errOut)
	}

	out.Reset()
	if err := a.runScan(ctx, s, &scanFlags{json: true}, nil); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Saved bool     `json:"saved"`
		Run   *run.Run `json:"run"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Saved || len(got.Run.Findings) != 2 || s.scans != 1 {
		t.Errorf("json should reuse the saved run: saved=%v findings=%d scans=%d", got.Saved, len(got.Run.Findings), s.scans)
	}

	out.Reset()
	if err := a.runScan(ctx, s, &scanFlags{list: true, minSeverity: "warning"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "bar note") || !strings.Contains(out.String(), "foo is broken") {
		t.Errorf("--min-severity warning should hide info:\n%s", out)
	}

	if err := a.runScan(ctx, s, &scanFlags{rescan: true, summary: true}, nil); err != nil {
		t.Fatal(err)
	}
	if s.scans != 2 {
		t.Errorf("--rescan should scan again, scans=%d", s.scans)
	}
}

func TestRunScanHTML(t *testing.T) {
	_, dataHome := env(t)
	a, _, errOut := loadedApp(t)
	s := &fakeScanner{}
	if err := a.runScan(context.Background(), s, &scanFlags{html: true}, nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(dataHome, "audit", "reports")
	for _, f := range []string{"packages.html", "index.html"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if !strings.Contains(errOut.String(), "report: "+filepath.Join(dir, "packages.html")) {
		t.Errorf("want report path, got %q", errOut)
	}

	var opened string
	a.opener = func(p string) error { opened = p; return nil }
	if err := a.runScan(context.Background(), s, &scanFlags{open: true, summary: true}, nil); err != nil {
		t.Fatal(err)
	}
	if opened != filepath.Join(dir, "packages.html") {
		t.Errorf("opened %q", opened)
	}
}

func TestRootHTMLWritesIndex(t *testing.T) {
	_, dataHome := env(t)
	r := runArgs(t, "-H")
	if r.e != nil {
		t.Fatal(r.e)
	}
	index := filepath.Join(dataHome, "audit", "reports", "index.html")
	if _, err := os.Stat(index); err != nil {
		t.Fatal(err)
	}
	if r.out != "" {
		t.Errorf("--html alone should not print the summary: %q", r.out)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList([]string{"a, b", "", "c,,"})
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("got %v", got)
	}
}
