package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

var th = config.Thresholds{Warn: 24 * time.Hour, Old: 168 * time.Hour}

func printer(width int) (*Printer, *bytes.Buffer) {
	var b bytes.Buffer
	p := New(&b, true, width)
	p.Now = func() time.Time { return now }
	return p, &b
}

func sampleRun(age time.Duration) *run.Run {
	fin := now.Add(-age)
	return &run.Run{
		Command: "system", Host: "box", StartedAt: fin.Add(-2 * time.Second), FinishedAt: fin, Ignored: 2,
		Stats:  []run.Stat{{Group: "procs", Name: "total", Value: "412"}, {Name: "plain", Value: "x"}},
		Errors: []string{"logs dmesg: permission denied"},
		Findings: []finding.Finding{
			{Command: "system", Check: "logs.oom_kill", Severity: finding.Error, Kind: finding.Issue,
				Subject: "journal", Message: "OOM killer activated (3 hit(s))", Hint: "add swap",
				Details: []string{"a", "b", "c", "d", "e", "f", "g"}},
			{Command: "system", Check: "procs.high_cpu", Severity: finding.Notice, Kind: finding.Issue,
				Subject: "firefox", Message: "93% CPU"},
			{Command: "system", Check: "users.tidy", Severity: finding.Info, Kind: finding.Suggestion,
				Subject: "accounts", Message: "remove unused accounts"},
		},
	}
}

func TestBanner(t *testing.T) {
	p, _ := printer(80)
	if b := p.Banner(sampleRun(time.Hour), th, false, ""); b != "" {
		t.Errorf("fresh scan should have no banner: %q", b)
	}
	cases := []struct {
		age  time.Duration
		want []string
	}{
		{time.Hour, []string{"Saved results from 1h ago"}},
		{3 * 24 * time.Hour, []string{"! Saved results are 3d old", "Run `audit system -r` to rescan."}},
		{30 * 24 * time.Hour, []string{"OUTDATED", "4w old", "to rescan", "┏"}},
	}
	for _, c := range cases {
		b := ansi.Strip(p.Banner(sampleRun(c.age), th, true, "audit system -r"))
		for _, w := range c.want {
			if !strings.Contains(strings.Join(strings.Fields(b), " "), w) {
				t.Errorf("age %s: banner %q missing %q", c.age, b, w)
			}
		}
	}
}

func TestReport(t *testing.T) {
	p, b := printer(100)
	p.Report(sampleRun(3*24*time.Hour), ReportOptions{Thresholds: th, Saved: true})
	out := b.String()
	for _, w := range []string{
		"audit system", "box", "took 2s", "● 1 error  ◆ 1 notice  ○ 1 info  (2 ignored)",
		"Summary", "procs", "total  412", "Scan errors", "permission denied",
		"Issues", "ERROR    logs.oom_kill  journal", "OOM killer activated", "hint: add swap",
		"- e", "(+2 more; display.details sets how many show)", "key system:logs.oom_kill:journal",
		"Suggestions", "users.tidy", "! Saved results",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("report missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "- f") {
		t.Errorf("details beyond %d should be hidden", defaultDetails)
	}
	if strings.Index(out, "Issues") > strings.Index(out, "Suggestions") {
		t.Error("issues should come before suggestions")
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no-color output contains escape codes")
	}
}

func TestReportAllDetailsAndFilter(t *testing.T) {
	p, b := printer(100)
	p.AllDetails = true
	p.Report(sampleRun(0), ReportOptions{Filter: finding.Filter{MinSeverity: finding.Warning}})
	out := b.String()
	if !strings.Contains(out, "- g") {
		t.Error("AllDetails should show every detail")
	}
	if strings.Contains(out, "procs.high_cpu") || !strings.Contains(out, "2 finding(s) hidden by filters") {
		t.Errorf("filter not applied:\n%s", out)
	}
	if strings.Contains(out, "Saved results") {
		t.Error("unsaved run should have no banner")
	}
}

func TestReportAnalysis(t *testing.T) {
	p, b := printer(80)
	r := sampleRun(0)
	r.Analysis = &run.Analysis{Text: "## Top issues\n\n- swap is off", Model: "m1", Level: "brief",
		Cached: true, CreatedAt: now.Add(-2 * time.Hour), CostUSD: 0.01}
	p.Report(r, ReportOptions{})
	out := b.String()
	for _, w := range []string{"AI review", "m1  brief  cached 2h ago  $0.0100", "Top issues", "swap is off"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
}

func TestListTruncatesToWidth(t *testing.T) {
	p, b := printer(60)
	r := sampleRun(0)
	r.Findings[1].Message = strings.Repeat("long message ", 20)
	p.List(r, ReportOptions{})
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	var table []string
	for i, l := range lines {
		if strings.HasPrefix(l, "SEVERITY") {
			table = lines[i:]
		}
	}
	if len(table) != 4 {
		t.Fatalf("want header + 3 rows, got:\n%s", b.String())
	}
	for _, l := range table {
		if w := ansi.StringWidth(l); w > 60 {
			t.Errorf("line wider than 60 (%d): %q", w, l)
		}
	}
	if !strings.Contains(table[2], "…") || !strings.Contains(table[3], "(suggestion) accounts") {
		t.Errorf("rows:\n%s", strings.Join(table, "\n"))
	}
}

func TestListUnlimitedWidth(t *testing.T) {
	p, b := printer(0)
	r := sampleRun(0)
	r.Findings[1].Message = strings.Repeat("x", 300)
	p.List(r, ReportOptions{})
	if !strings.Contains(b.String(), strings.Repeat("x", 300)) {
		t.Error("width 0 should not truncate")
	}
}

func TestSummary(t *testing.T) {
	p, b := printer(120)
	p.Summary([]CommandStatus{
		{Command: "system", Thresholds: th, Latest: &store.RunInfo{FinishedAt: now.Add(-2 * time.Hour),
			Counts: finding.Counts{finding.Error: 2, finding.Info: 1}},
			Open: map[todo.Priority]int{todo.High: 2, todo.Low: 1}},
		{Command: "packages", Thresholds: th, Latest: &store.RunInfo{FinishedAt: now.Add(-10 * 24 * time.Hour)}},
		{Command: "repos", Thresholds: th},
	})
	out := b.String()
	for _, w := range []string{"COMMAND", "system", "2h", "● 2  ○ 1  ● 2  ○ 1",
		"packages", "10d", "✓ none", "repos", "never"} {
		if !strings.Contains(out, w) {
			t.Errorf("summary missing %q:\n%s", w, out)
		}
	}
}

func TestOpenCounts(t *testing.T) {
	got := OpenCounts([]todo.Todo{
		{Priority: todo.High, Status: todo.Open}, {Priority: todo.High, Status: todo.InProgress},
		{Priority: todo.Low, Status: todo.Done}, {Priority: todo.Low, Status: todo.WontDo},
	})
	if got[todo.High] != 2 || got[todo.Low] != 0 {
		t.Errorf("%v", got)
	}
}

func TestTodos(t *testing.T) {
	p, b := printer(80)
	p.Todos(nil)
	if !strings.Contains(b.String(), "No tasks match.") {
		t.Error("empty message")
	}
	b.Reset()
	ts := []todo.Todo{
		{ID: 3, Priority: todo.High, Status: todo.InProgress, Command: "system", Title: "Fix OOM"},
		{ID: 7, Priority: todo.Suggestion, Status: todo.WontDo, Command: "environment", Title: "Tidy PATH"},
	}
	p.Todos(ts)
	out := b.String()
	for _, w := range []string{"ID", "PRIORITY", "3   high", "in progress", "won't do", "Tidy PATH"} {
		if !strings.Contains(out, w) {
			t.Errorf("todos missing %q:\n%s", w, out)
		}
	}
	b.Reset()
	p.Todo(todo.Todo{ID: 3, Title: "Fix OOM", Priority: todo.High, Status: todo.Open, Key: "system:x:y",
		Note: "after reboot", Details: []string{"one"}, CreatedAt: now})
	out = b.String()
	for _, w := range []string{"#3 Fix OOM", "priority  high", "key       system:x:y", "note      after reboot",
		"- one", "created   2026-10-17"} {
		if !strings.Contains(out, w) {
			t.Errorf("todo missing %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "resolved") {
		t.Error("zero times should be omitted")
	}
	if strings.Contains(out, "vim -q") {
		t.Error("a task without file:line details has no editor line")
	}
	b.Reset()
	p.Todo(todo.Todo{ID: 9, Title: "Fix shellcheck errors in 1 script", Details: []string{"/bin/x:3: SC2086 quote"}})
	if !strings.Contains(b.String(), "editor    vim -q <(audit todo show 9 -l)") {
		t.Errorf("lint task should name the quickfix command:\n%s", b.String())
	}
}

func TestPackages(t *testing.T) {
	p, b := printer(140)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p.Now = func() time.Time { return now }
	p.Verbose = true
	invs := []packages.Inventory{
		{Manager: "cargo", Available: true, ManagerVersion: "1.90", Runtime: &packages.Runtime{Name: "rust", Version: "1.90"},
			Packages: []packages.Package{
				{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", RuntimeVersion: "1.88", Source: "crates.io", Executables: []string{"rg"}},
				{Manager: "cargo", Name: "fd-find", Version: "9.0.0", Source: "crates.io"},
				{Manager: "cargo", Name: "mine", Version: "0.1.0", Source: "path:/src/mine"},
			}},
		{Manager: "gh"},
		{Manager: "uv", Available: true, Error: "boom"},
	}
	metas := map[string]packages.Meta{
		"cargo:ripgrep": {Latest: "15.0.0", LatestAt: now.Add(-72 * time.Hour), CheckedAt: now.Add(-3 * time.Hour), Archived: true},
	}
	p.Packages(packages.Annotate(invs, metas, map[string][]string{"cargo:ripgrep": {"search"}}, ""))
	out := b.String()
	for _, w := range []string{"cargo  1.90  rust 1.90  3 package(s)", "registry checked 3 hours ago (1 unchecked)",
		"ripgrep", "14.1.0", "15.0.0 (archived)", "3 days ago", "cargo search", "crates.io", "rg", "unchecked",
		"EXECUTABLES", "gh  not installed", "uv  error: boom"} {
		if !strings.Contains(out, w) {
			t.Errorf("packages missing %q:\n%s", w, out)
		}
	}
}

func TestEnvironment(t *testing.T) {
	p, b := printer(100)
	p.Environment(environment.Data{
		EnvSource: "zsh tty",
		Captures: []environment.Capture{
			{Shell: "zsh", Mode: "tty", Duration: 450 * time.Millisecond, Output: []string{"oops"}},
			{Shell: "bash", Mode: "notty", TimedOut: true},
		},
		Scripts: []environment.Script{
			{Path: "/h/.zshrc", Dialect: "zsh", Startup: true, LoadedBy: []string{"zsh"}},
			{Path: "/h/notes.sh", Dialect: "sh"},
			{Path: "/h/bin/tool", Dialect: "bash", Executable: true},
		},
		Syntax: []environment.SyntaxResult{{Path: "/h/notes.sh"}},
		Traced: []string{"/h/.zshrc"},
	})
	out := b.String()
	for _, w := range []string{"zsh    tty    450ms", "timed out", "analyzed env: zsh tty", "startup",
		"not loaded  syntax error  /h/notes.sh", "executable"} {
		if !strings.Contains(out, w) {
			t.Errorf("environment missing %q:\n%s", w, out)
		}
	}
}

func TestWrappedHintHasNoTrailingPadding(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf, true, 40)
	p.findings([]finding.Finding{{Command: "c", Check: "k", Severity: finding.Error, Subject: "s", Message: "m",
		Hint: "Add /a/very/long/path/that/cannot/be/broken/at/spaces/anywhere to PATH"}})
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasSuffix(l, " ") {
			t.Errorf("trailing space in %q", l)
		}
	}
}

func TestTrimPadding(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain   \nnext", "plain\nnext"},
		{"\x1b[1mbold\x1b[0m \x1b[0m  ", "\x1b[1mbold\x1b[0m"},
		{"  indented", "  indented"},
		{"", ""},
	}
	for _, c := range cases {
		if got := trimPadding(c.in); got != c.want {
			t.Errorf("trimPadding(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestPackageInfoAndTable(t *testing.T) {
	p, b := printer(120)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p.Now = func() time.Time { return now }
	it := packages.Item{
		Package: packages.Package{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", Source: "crates.io",
			Executables: []string{"rg"}},
		Meta: &packages.Meta{Latest: "15.0.0", LatestAt: now.Add(-72 * time.Hour), CheckedAt: now.Add(-time.Hour),
			Description: "line-oriented search", Repo: "https://github.com/BurntSushi/ripgrep", License: "MIT",
			Keywords: []string{"grep", "regex"}, Archived: true, Error: "HTTP 502"},
		Gap:  packages.GapMajor,
		Tags: []string{"cargo", "search"},
	}
	p.PackageInfo(it, []packages.Tag{{Manager: "cargo", ID: "ripgrep", Tag: "search", Source: packages.TagAI}})
	out := b.String()
	for _, w := range []string{"ripgrep", "14.1.0", "15.0.0", "major", "3 days ago", "1 hour ago", "line-oriented search",
		"https://github.com/BurntSushi/ripgrep", "MIT", "grep, regex", "archived", "HTTP 502", "search (ai)", "cargo (auto)", "rg"} {
		if !strings.Contains(out, w) {
			t.Errorf("info missing %q:\n%s", w, out)
		}
	}

	b.Reset()
	p.PackageInfo(packages.Item{Package: packages.Package{Manager: "uv", Name: "x", Version: "1", Source: "pypi"}}, nil)
	if !strings.Contains(b.String(), "unchecked") || strings.Contains(b.String(), "description") {
		t.Errorf("unchecked package:\n%s", b)
	}

	b.Reset()
	p.Table([]string{"TAG", "PACKAGES"}, [][]string{{"cli", "3"}, {"search", "1"}})
	if out := b.String(); !strings.Contains(out, "TAG") || !strings.Contains(out, "cli") || !strings.Contains(out, "search") {
		t.Errorf("table:\n%s", out)
	}
	b.Reset()
	p.Table([]string{"", ""}, [][]string{{"k", "v"}})
	if out := b.String(); strings.Contains(strings.SplitN(out, "\n", 2)[0], "  \n") || !strings.HasPrefix(strings.TrimSpace(out), "k") {
		t.Errorf("empty titles should print no header:\n%q", out)
	}
}

func TestStatsLayout(t *testing.T) {
	p, b := printer(0)
	p.Home = "/home/u"
	stats := []run.Stat{
		{Group: "scripts", Name: "startup scripts", Value: "791", Note: "bash 352, zsh 193"},
		{Group: "scripts", Name: "syntax failures", Value: "1"},
		{Group: "startup", Name: "zsh notty", Value: "0.45s", Note: "7 unexpected line(s)"},
		{Group: "startup", Name: "bash tty", Value: "0.22s", Extra: true},
		{Group: "zsh", Name: "config", Value: "/home/u/.zshrc", Note: "read"},
	}
	p.stats(stats)
	want := `  scripts
    startup scripts    791  bash 352, zsh 193
    syntax failures      1
  startup
    zsh notty        0.45s  7 unexpected line(s)
    bash tty         0.22s
  zsh
    config           ~/.zshrc  read
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	p.Collapsed = true
	p.stats(stats)
	if strings.Contains(b.String(), "bash tty") || !strings.Contains(b.String(), "zsh notty") {
		t.Errorf("collapsed keeps Extra lines:\n%s", b.String())
	}
}

func TestTilde(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u":                      "~",
		"in /home/u/.zshrc: line 2":    "in ~/.zshrc: line 2",
		"/home/u/a:/home/u/b":          "~/a:~/b",
		"/home/u2/x /mnt/home/u/x":     "/home/u2/x /mnt/home/u/x",
		"`shellcheck /home/u/x` fixes": "`shellcheck ~/x` fixes",
		"no paths":                     "no paths",
	} {
		if got := Tilde(in, "/home/u/"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if Tilde("/a", "") != "/a" || Tilde("/a", "/") != "/a" {
		t.Error("empty or root home changes nothing")
	}
}

func TestReportCollapsed(t *testing.T) {
	p, b := printer(60)
	p.Collapsed = true
	p.Home = "/home/u"
	r := sampleRun(0)
	r.Findings = append(r.Findings, finding.Finding{Command: "environment", Check: "shell.shellcheck", Severity: finding.Error,
		Subject: "/home/u/x", Message: "shellcheck reports 5 problems in /home/u/.shell/scripts/ui-widgets/yad/yadcomposite",
		Hint: "Run shellcheck", Details: []string{"line 1"}})
	p.Report(r, ReportOptions{})
	out := b.String()
	if !strings.Contains(out, "  ● shell.shellcheck  shellcheck reports 5 problems in ~/.s…") {
		t.Errorf("collapsed line missing or not cut to the width:\n%s", out)
	}
	for _, gone := range []string{"hint:", "- line 1", "key "} {
		if strings.Contains(out, gone) {
			t.Errorf("collapsed report shows %q:\n%s", gone, out)
		}
	}
}

func TestCountColumnsAlign(t *testing.T) {
	p, _ := printer(0)
	rows := []CommandStatus{
		{Command: "a", Latest: &store.RunInfo{Counts: finding.Counts{finding.Error: 8, finding.Warning: 88, finding.Info: 54}},
			Open: map[todo.Priority]int{todo.High: 3, todo.Low: 5}},
		{Command: "b", Latest: &store.RunInfo{Counts: finding.Counts{finding.Warning: 4}}, Open: map[todo.Priority]int{todo.Low: 12}},
		{Command: "c", Latest: &store.RunInfo{}},
		{Command: "d"},
	}
	cc := NewCountColumns(rows)
	var got []string
	for _, r := range rows {
		got = append(got, p.RunCounts(cc, r)+" | "+p.TaskCounts(cc, r.Open))
	}
	want := []string{
		"● 8  ▲ 88  ○ 54 | ● 3  ○  5",
		"     ▲  4 |      ○ 12",
		"✓ none | ",
		" | ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestNerdGlyphs(t *testing.T) {
	p, b := printer(0)
	p.Glyphs = GlyphsFor(true)
	p.Report(sampleRun(0), ReportOptions{})
	out := b.String()
	for _, w := range []string{"\uf108 audit system", "\uf188 Issues", "\uf057 ERROR", "\uf057 1 error"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q:\n%s", w, out)
		}
	}
	if GlyphsFor(false).Icon("system") != "" || GlyphsFor(true).Icon("nothing") != "" {
		t.Error("Unicode markers have no icons, and an unknown name has none")
	}
}
