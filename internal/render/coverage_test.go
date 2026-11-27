package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/muesli/termenv"

	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

func TestFixes(t *testing.T) {
	p, b := printer(120)
	p.Fixes(nil, 10)
	if strings.TrimSpace(b.String()) != FixesEmpty {
		t.Errorf("empty log: %q", b.String())
	}
	b.Reset()
	as := []store.Activity{
		{At: now.Add(-time.Hour), Kind: "task", Command: "system", Action: "resolved", Priority: todo.High, Title: "Swap is off"},
		{At: now.Add(-2 * time.Hour), Kind: "task", Command: "system", Action: "done", Priority: todo.Low, Title: "Tidy"},
		{At: now.Add(-3 * time.Hour), Kind: "task", Command: "repos", Action: "wont_do", Priority: todo.Low, Title: "Ignored"},
		{At: now.Add(-4 * time.Hour), Kind: "task", Command: "repos", Action: "reopened", Priority: todo.Medium, Title: "Back"},
		{At: now.Add(-5 * time.Hour), Kind: "package", Command: "packages", Action: "updated", Title: "uv:ruff", From: "0.9", To: "0.10"},
		{At: now.Add(-6 * time.Hour), Kind: "clean", Action: "updated", Title: "cache"},
	}
	p.Fixes(as, 2)
	out := b.String()
	for _, w := range []string{"Tasks fixed (resolved or done):", "system   2      1 high, 1 low", "Steps done: 1 clean, 1 package.",
		"Reopened: 1 task(s)", "Swap is off", "4 older entries"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	if strings.Contains(out, "uv:ruff") {
		t.Error("the limit cuts the table")
	}
	b.Reset()
	p.Fixes(as[4:], 0)
	if out := b.String(); !strings.Contains(out, "uv:ruff 0.9 -> 0.10") || !strings.Contains(out, " clean ") {
		t.Errorf("steps: an empty command shows the kind, a change its versions:\n%s", out)
	}
	if tot := SumFixes(as); tot.Reopened != 1 || len(tot.Closed["repos"]) != 0 || tot.StepsText() != "1 clean, 1 package" {
		t.Errorf("totals %+v", tot)
	}
}

func TestDiff(t *testing.T) {
	p, b := printer(120)
	from := &run.Run{ID: 1, Command: "system", FinishedAt: now.Add(-48 * time.Hour)}
	to := &run.Run{ID: 2, Command: "system", Scope: "procs", FinishedAt: now.Add(-time.Hour)}
	p.Diff(from, to, finding.Delta{Unchanged: 3})
	if out := b.String(); !strings.Contains(out, "system (procs): findings since run 1") || !strings.Contains(out, "No change: the same 3 finding(s).") {
		t.Errorf("no change:\n%s", out)
	}
	b.Reset()
	f := finding.Finding{Check: "procs.zombie", Subject: "pid 9", Severity: finding.Warning, Message: "zombie"}
	p.Diff(from, to, finding.Delta{Added: []finding.Finding{f}, Resolved: []finding.Finding{f},
		Changed: []finding.Change{{From: finding.Info, Finding: f}}, Unchanged: 1})
	out := b.String()
	for _, w := range []string{"1 added, 1 resolved, 1 changed severity, 1 unchanged.", "info -> warning", "procs.zombie"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
}

func TestFilesView(t *testing.T) {
	p, b := printer(120)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	p.Files(files.Data{Bytes: 4 << 30, Reclaimable: 1 << 30,
		Top:     []files.File{{Path: "/home/me/src", Bytes: 2 << 30}},
		Caches:  []files.Cache{{Name: "go build", Path: "/home/me/.cache/go-build", Bytes: 1 << 29}, {Name: "docker", Bytes: 1 << 20}},
		Build:   []files.BuildDir{{Path: "/home/me/src/x/node_modules", Kind: "node_modules", Bytes: 1 << 28, ModTime: at}},
		Orphans: []files.Orphan{{Path: "/home/me/.local/share/gone", Bytes: 1 << 20}},
		Big:     []files.File{{Path: "/tmp/big.iso", Bytes: 1 << 30, ModTime: at}},
		Dups:    []files.Dup{{Bytes: 1 << 20, Paths: []string{"/home/me/a", "/home/me/b"}}},
	}, "/home/me")
	out := b.String()
	for _, w := range []string{"Largest directories", "50%", "~/src", "Caches", "go build", "-", "Idle build", "2026-09-01",
		"look uninstalled", "Largest files", "/tmp/big.iso", "Duplicates", "~/a", "reclaimable"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	b.Reset()
	p.Files(files.Data{}, "")
	if out := b.String(); strings.Contains(out, "Largest") || !strings.Contains(out, "scanned") || pct(1, 0) != "-" {
		t.Errorf("empty data shows only the total:\n%s", out)
	}
}

func TestBriefAndAI(t *testing.T) {
	p, b := printer(120)
	r := sampleRun(time.Hour)
	p.Brief(r, ReportOptions{})
	if out := b.String(); !strings.Contains(out, r.Command) || strings.Contains(out, "Issues") {
		t.Errorf("brief:\n%s", out)
	}
	b.Reset()
	p.AI("AI review", "sonnet", true, now.Add(-2*time.Hour), 0.25, "**fix** it")
	if out := b.String(); !strings.Contains(out, "AI review") || !strings.Contains(out, "sonnet") || !strings.Contains(out, "fix") {
		t.Errorf("ai:\n%s", out)
	}
}

func TestRepoStateAndShortHome(t *testing.T) {
	if got := RepoState(repos.Repo{}); got != "clean" {
		t.Errorf("clean: %q", got)
	}
	got := RepoState(repos.Repo{Operation: "rebase", Conflicts: 1, Staged: 2, Modified: 3, Untracked: 4, Ahead: 5, Behind: 6, Stashes: 1, Error: "x"})
	if got != "rebase, 1 conflicted, 2 staged, 3 modified, 4 untracked, +5 -6, 1 stash, error" {
		t.Errorf("state %q", got)
	}
	if shortHome("/home/me/x", "/home/me") != "~/x" || shortHome("/home/mex", "/home/me") != "/home/mex" || shortHome("/a", "") != "/a" {
		t.Error("shortHome")
	}
}

func TestNewProfileAndStyles(t *testing.T) {
	var b bytes.Buffer
	p := NewProfile(&b, termenv.Ascii, 40)
	if p.Width != 40 || p.Now == nil {
		t.Errorf("profile printer %+v", p)
	}
	if got := p.PriorityStyle(todo.High).Render("x"); got != "x" {
		t.Errorf("ascii has no color: %q", got)
	}
	if got := p.StatusStyle(todo.Done).Render("y"); got != "y" {
		t.Errorf("ascii has no color: %q", got)
	}
}
