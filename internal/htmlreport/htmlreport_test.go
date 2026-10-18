package htmlreport

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func sample(age time.Duration) *run.Run {
	fin := now.Add(-age)
	return &run.Run{
		ID: 1, Command: "system", Host: "box", StartedAt: fin.Add(-3 * time.Second), FinishedAt: fin, Ignored: 1,
		Stats:  []run.Stat{{Group: "procs", Name: "total", Value: "412"}, {Group: "procs", Name: "zombies", Value: "0"}},
		Errors: []string{"logs dmesg: permission denied"},
		Findings: []finding.Finding{
			{Command: "system", Check: "logs.oom_kill", Severity: finding.Error, Kind: finding.Issue,
				Subject: "journal", Message: "OOM <script>alert(1)</script>", Hint: "add swap", Details: []string{"a", "b"}},
			{Command: "system", Check: "users.tidy", Severity: finding.Info, Kind: finding.Suggestion,
				Subject: "accounts", Message: "remove unused accounts"},
		},
	}
}

func render(t *testing.T, r *run.Run, o Options) string {
	t.Helper()
	var b bytes.Buffer
	if o.Now.IsZero() {
		o.Now = now
	}
	if err := Write(&b, r, o); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestWrite(t *testing.T) {
	out := render(t, sample(time.Hour), Options{Thresholds: th, RescanHint: "audit system -r",
		Todos: []todo.Todo{
			{ID: 4, Command: "system", Title: "Fix OOM", Priority: todo.High, Status: todo.Open},
			{ID: 5, Command: "packages", Title: "other command", Priority: todo.Low, Status: todo.Open},
			{ID: 6, Command: "system", Title: "Old thing", Priority: todo.Low, Status: todo.Done},
		}})
	for _, w := range []string{
		"<title>audit system</title>", "box", "took 3s", "1 ignored", "banner fresh", "Results from 1h ago.",
		"1 error", "1 info", "<h3>procs</h3>", "<dt>total</dt><dd>412</dd>", "permission denied",
		"<h3>Issues</h3>", "logs.oom_kill", "hint: add swap", "system:logs.oom_kill:journal",
		"<h3>Suggestions</h3>", "users.tidy", "Fix OOM", `class="closed"`, "Old thing",
		`data-sev="error"`, `value="info" checked`,
	} {
		if !strings.Contains(out, w) {
			t.Errorf("report missing %q", w)
		}
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("finding text must be escaped")
	}
	if strings.Contains(out, "other command") {
		t.Error("tasks of other commands should be excluded")
	}
	if strings.Contains(out, "AI review") {
		t.Error("no analysis section without analysis")
	}
	if strings.Contains(out, "<link") || strings.Contains(out, "src=\"http") {
		t.Error("report must be self-contained")
	}
}

func TestWriteBanners(t *testing.T) {
	stale := render(t, sample(3*24*time.Hour), Options{Thresholds: th, RescanHint: "audit system -r"})
	if !strings.Contains(stale, "banner stale") || !strings.Contains(stale, "3d old") || !strings.Contains(stale, "<code>audit system -r</code>") {
		t.Error("stale banner")
	}
	old := render(t, sample(30*24*time.Hour), Options{Thresholds: th})
	if !strings.Contains(old, "banner old") || !strings.Contains(old, "OUTDATED") || !strings.Contains(old, "audit system --rescan") {
		t.Error("old banner should default the rescan hint")
	}
}

func TestWriteEmptyRun(t *testing.T) {
	r := &run.Run{Command: "environment", Host: "h", StartedAt: now, FinishedAt: now}
	out := render(t, r, Options{Thresholds: th})
	if !strings.Contains(out, "no findings") || !strings.Contains(out, "No tasks for this command.") {
		t.Error("empty run")
	}
	if strings.Contains(out, `id="q"`) {
		t.Error("no filter controls without findings")
	}
}

func TestWriteAnalysis(t *testing.T) {
	r := sample(0)
	r.Analysis = &run.Analysis{Text: "## Top\n\n- swap is **off**\n\n<img src=x onerror=alert(1)>\n\n[x](javascript:alert(1))",
		Model: "m1", Level: "deep", CreatedAt: now}
	out := render(t, r, Options{Thresholds: th})
	for _, w := range []string{"AI review", "m1 · deep", "<h2>Top</h2>", "<strong>off</strong>"} {
		if !strings.Contains(out, w) {
			t.Errorf("analysis missing %q", w)
		}
	}
	if strings.Contains(out, "onerror") || strings.Contains(out, "javascript:") {
		t.Error("raw HTML and dangerous links must be dropped")
	}
}

func TestTables(t *testing.T) {
	pd, _ := json.Marshal(packages.Data{Inventories: []packages.Inventory{
		{Manager: "cargo", Available: true, ManagerVersion: "1.90", Packages: []packages.Package{{Name: "ripgrep", Version: "14.1.0", Executables: []string{"rg"}}}},
		{Manager: "gh"},
	}})
	ts := Tables(&run.Run{Command: packages.Command, Data: pd})
	if len(ts) != 2 || ts[0].Title != "cargo" || ts[0].Rows[0][0] != "ripgrep" || ts[0].Rows[0][8] != "rg" ||
		!strings.Contains(ts[1].Note, "not installed") {
		t.Errorf("package tables %+v", ts)
	}

	ed, _ := json.Marshal(environment.Data{EnvSource: "zsh tty",
		Captures: []environment.Capture{{Shell: "zsh", Mode: "tty", Output: []string{"hi"}}},
		Scripts:  []environment.Script{{Path: "/h/.zshrc", Startup: true}, {Path: "/h/x.sh"}},
		Syntax:   []environment.SyntaxResult{{Path: "/h/x.sh"}}, Traced: []string{"zsh"}})
	ts = Tables(&run.Run{Command: environment.Command, Data: ed})
	if len(ts) != 2 || ts[0].Rows[0][4] != "hi" || ts[1].Rows[1][1] != "not loaded" || ts[1].Rows[1][2] != "syntax error" {
		t.Errorf("environment tables %+v", ts)
	}

	if Tables(&run.Run{Command: packages.Command, Data: json.RawMessage("{bad")}) != nil {
		t.Error("bad payload should yield no tables")
	}
	if Tables(&run.Run{Command: "system", Data: pd}) != nil {
		t.Error("system has no data tables")
	}
}

func TestWritePackages(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	invs := []packages.Inventory{{Manager: "cargo", Available: true, Packages: []packages.Package{
		{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", Source: "crates.io"},
		{Manager: "cargo", Name: "fd", Version: "9.0.0", Source: "crates.io"},
	}}}
	metas := map[string]packages.Meta{
		"cargo:ripgrep": {Latest: "15.0.0", LatestAt: now.Add(-48 * time.Hour), CheckedAt: now.Add(-time.Hour), Description: "grep <fast>"},
		"cargo:fd":      {Latest: "9.0.0", CheckedAt: now.Add(-time.Hour), Deprecated: "use x"},
	}
	r := &run.Run{Command: packages.Command, FinishedAt: now}
	var b strings.Builder
	err := Write(&b, r, Options{Thresholds: th, Now: now,
		Packages: packages.Annotate(invs, metas, map[string][]string{"cargo:ripgrep": {"search"}}, "")})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, w := range []string{"registry checked 1 hour ago", `class="pkg gap-major" data-tags="cargo search"`,
		`class="pkg gap-current gap-dead"`, "15.0.0", "2 days ago", "grep &lt;fast&gt;", "9.0.0 (deprecated)",
		`<option value="cargo">cargo (2)</option>`, `<option value="search">search (1)</option>`, `id="pout"`} {
		if !strings.Contains(out, w) {
			t.Errorf("report missing %q", w)
		}
	}
}

func TestWriteIndex(t *testing.T) {
	var b bytes.Buffer
	err := WriteIndex(&b, []IndexRow{
		{Command: "system", Thresholds: th, Link: "system.html", Open: map[todo.Priority]int{todo.High: 2},
			Latest: &store.RunInfo{FinishedAt: now.Add(-10 * 24 * time.Hour), Counts: finding.Counts{finding.Error: 3}}},
		{Command: "repos", Thresholds: th},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, w := range []string{`<a href="system.html">system</a>`, `class="age-old"`, "10d", "3 error", "2 high", "never"} {
		if !strings.Contains(out, w) {
			t.Errorf("index missing %q:\n%s", w, out)
		}
	}
}

func TestSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	path := filepath.Join(dir, FileName("system"))
	if err := Save(path, func(w io.Writer) error { _, err := io.WriteString(w, "ok"); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "ok" {
		t.Errorf("content %q", b)
	}
	if err := Save(path, func(io.Writer) error { return io.ErrUnexpectedEOF }); err == nil {
		t.Error("render error should propagate")
	}
	if b, _ := os.ReadFile(path); string(b) != "ok" {
		t.Error("failed save must not clobber the existing report")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}
