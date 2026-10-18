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
	"github.com/njhoffman/audit/internal/packages"
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

// seedPackages saves a packages run with a small inventory and registry
// cache, for the commands that read them.
func seedPackages(t *testing.T) {
	t.Helper()
	a, _, _ := loadedApp(t)
	ctx := context.Background()
	d := packages.Data{Inventories: []packages.Inventory{
		{Manager: "uv", Available: true, Packages: []packages.Package{
			{Manager: "uv", Name: "ruff", Version: "0.9.0", Source: "pypi", Executables: []string{"ruff"}},
			{Manager: "uv", Name: "black", Version: "25.1", Source: "pypi"},
			{Manager: "uv", Name: "dup", Version: "1.0", Source: "pypi"},
		}},
		{Manager: "cargo", Available: true, Packages: []packages.Package{
			{Manager: "cargo", Name: "dup", Version: "1.0", Source: "crates.io"},
			{Manager: "cargo", Name: "mine", Source: "path:/src/mine"},
		}},
	}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	r := &run.Run{Command: packages.Command, Host: "h", StartedAt: testNow, FinishedAt: testNow, Data: raw}
	if err := a.store.SaveRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	err = a.store.SavePackageMeta(ctx, []packages.Meta{
		{Manager: "uv", ID: "ruff", Registry: packages.RegistryPyPI, Installed: "0.9.0", Latest: "0.10.0",
			LatestAt: testNow.Add(-72 * time.Hour), Description: "An extremely fast Python linter",
			Repo: "https://github.com/astral-sh/ruff", CheckedAt: testNow, DescribedAt: testNow},
		{Manager: "uv", ID: "black", Registry: packages.RegistryPyPI, Installed: "25.1", Latest: "25.1",
			Description: "The uncompromising code formatter", CheckedAt: testNow, DescribedAt: testNow},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.close()
}

func TestPackagesQueryFlags(t *testing.T) {
	env(t)
	seedPackages(t)

	r := runArgs(t, "packages", "-u")
	if r.e != nil {
		t.Fatal(r.e)
	}
	if !strings.Contains(r.out, "ruff") || strings.Contains(r.out, "black") || !strings.Contains(r.out, "0.10.0") {
		t.Errorf("--outdated should list only ruff with its latest version:\n%s", r.out)
	}
	if !strings.Contains(r.out, "3 days ago") {
		t.Errorf("want the release age:\n%s", r.out)
	}

	r = runArgs(t, "packages", "-f", "FORMATTER")
	if r.e != nil || !strings.Contains(r.out, "black") || strings.Contains(r.out, "ruff") {
		t.Errorf("--find should match the description ignoring case: %v\n%s", r.e, r.out)
	}

	r = runArgs(t, "packages", "-t", "cargo", "-t", "local")
	if r.e != nil || !strings.Contains(r.out, "mine") || strings.Contains(r.out, "dup") {
		t.Errorf("--tag should need every tag: %v\n%s", r.e, r.out)
	}

	r = runArgs(t, "packages", "-t", "nothing-has-this")
	if r.e != nil || !strings.Contains(r.out, "No packages match the filter.") {
		t.Errorf("empty filter result: %v\n%s", r.e, r.out)
	}

	r = runArgs(t, "packages", "-j", "-u")
	if r.e != nil {
		t.Fatal(r.e)
	}
	var got struct {
		Packages []packages.Annotated `json:"packages"`
	}
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Packages) != 1 || len(got.Packages[0].Items) != 1 || got.Packages[0].Items[0].Name != "ruff" {
		t.Errorf("json should carry the filtered inventory: %+v", got.Packages)
	}
}

func TestPackagesInfo(t *testing.T) {
	env(t)
	r := runArgs(t, "packages", "info", "ruff")
	if !errors.Is(r.e, core.ErrNoSavedRun) {
		t.Errorf("info with no run: %v", r.e)
	}
	seedPackages(t)

	r = runArgs(t, "packages", "info", "ruff")
	if r.e != nil {
		t.Fatal(r.e)
	}
	for _, want := range []string{"0.9.0", "0.10.0", "An extremely fast Python linter", "https://github.com/astral-sh/ruff"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("info missing %q:\n%s", want, r.out)
		}
	}
	if r = runArgs(t, "packages", "info", "dup"); r.e == nil || !strings.Contains(r.e.Error(), "cargo:dup") ||
		!strings.Contains(r.e.Error(), "uv:dup") {
		t.Errorf("ambiguous name should list the keys: %v", r.e)
	}
	if r = runArgs(t, "packages", "info", "cargo:dup"); r.e != nil || !strings.Contains(r.out, "1.0") {
		t.Errorf("manager:name picks one: %v\n%s", r.e, r.out)
	}
	if r = runArgs(t, "packages", "info", "nope"); r.e == nil || !strings.Contains(r.e.Error(), `no installed package matches "nope"`) {
		t.Errorf("unknown package: %v", r.e)
	}
	r = runArgs(t, "packages", "info", "-j", "black")
	var got struct {
		Name string `json:"name"`
		Meta struct {
			Description string `json:"description"`
		} `json:"meta"`
	}
	if r.e != nil || json.Unmarshal([]byte(r.out), &got) != nil || got.Name != "black" || got.Meta.Description == "" {
		t.Errorf("info --json: %v\n%s", r.e, r.out)
	}
}

func TestPackagesTag(t *testing.T) {
	env(t)
	seedPackages(t)

	r := runArgs(t, "packages", "tag", "ruff", "Lint Tool", "linter")
	if r.e != nil || !strings.Contains(r.out, "uv:ruff: ") || !strings.Contains(r.out, "lint-tool") || !strings.Contains(r.out, "linter") {
		t.Fatalf("add tags: %v\n%s", r.e, r.out)
	}
	if r = runArgs(t, "packages", "-t", "lint-tool"); r.e != nil || !strings.Contains(r.out, "ruff") || strings.Contains(r.out, "black") {
		t.Errorf("user tag should filter: %v\n%s", r.e, r.out)
	}

	r = runArgs(t, "packages", "tag")
	if r.e != nil {
		t.Fatal(r.e)
	}
	if !strings.Contains(r.out, "lint-tool") || !strings.Contains(r.out, "user 1") || !strings.Contains(r.out, "auto 3") {
		t.Errorf("tag list should count packages per source:\n%s", r.out)
	}

	r = runArgs(t, "packages", "tag", "-d", "ruff", "linter", "uv")
	if r.e != nil || strings.Contains(r.out, "linter") || !strings.Contains(r.out, "uv") {
		t.Errorf("delete: %v\n%s", r.e, r.out)
	}
	if !strings.Contains(r.err, "1 of 2 tag(s) were not stored") {
		t.Errorf("want the automatic-tag notice, got %q", r.err)
	}

	r = runArgs(t, "packages", "tag", "-j")
	var uses []tagUse
	if r.e != nil || json.Unmarshal([]byte(r.out), &uses) != nil || len(uses) == 0 || uses[0].Packages < uses[len(uses)-1].Packages {
		t.Errorf("tag --json should sort by count: %v\n%s", r.e, r.out)
	}

	for _, args := range [][]string{{"tag", "-d"}, {"tag", "-d", "ruff"}, {"tag", "dup", "x"}} {
		if r = runArgs(t, append([]string{"packages"}, args...)...); r.e == nil {
			t.Errorf("%v should fail", args)
		}
	}
}

func TestPackagesAITag(t *testing.T) {
	env(t)
	seedPackages(t)
	a, _, errOut := loadedApp(t)
	ctx := context.Background()

	dir := t.TempDir()
	answer := `{"subtype":"success","result":"{\"uv:ruff\": [\"linter\", \"Not-In-Vocab\", \"cli\"], \"uv:other\": [\"cli\"]}"}`
	script := filepath.Join(dir, "claude")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s' '"+answer+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.cfg.AI.Command = script
	r, err := a.store.LatestRun(ctx, packages.Command, "")
	if err != nil {
		t.Fatal(err)
	}

	// Only ruff is named; black has meta but is not asked about.
	if err := a.aiTag(ctx, r, []packages.Ref{packages.ParseRef("ruff")}, false, true); err != nil {
		t.Fatal(err)
	}
	tags, err := a.store.PackageTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tg := range tags {
		if tg.Source != packages.TagAI || tg.ID != "ruff" {
			t.Errorf("unexpected tag %+v", tg)
		}
		got = append(got, tg.Tag)
	}
	if strings.Join(got, ",") != "cli,linter" {
		t.Errorf("ai tags = %v", got)
	}
	metas, err := a.store.PackageMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !metas["uv:ruff"].TaggedAt.Equal(testNow) || !metas["uv:black"].TaggedAt.IsZero() {
		t.Errorf("TaggedAt: ruff %v black %v", metas["uv:ruff"].TaggedAt, metas["uv:black"].TaggedAt)
	}

	// Already tagged: nothing to ask without retag.
	errOut.Reset()
	if err := a.aiTag(ctx, r, []packages.Ref{packages.ParseRef("ruff")}, false, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "every package with registry data is tagged") {
		t.Errorf("want the nothing-to-tag notice, got %q", errOut)
	}

	// A failing command is reported, not fatal to the other batches.
	a.cfg.AI.Command = filepath.Join(dir, "missing")
	if err := a.aiTag(ctx, r, nil, true, false); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing command: %v", err)
	}
}
