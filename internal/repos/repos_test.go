package repos

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

var ctx = context.Background()

func TestParseStatus(t *testing.T) {
	var r Repo
	ParseStatus(`# branch.oid abc
# branch.head main
# branch.upstream origin/main
# branch.ab +2 -3
1 M. N... 100644 100644 100644 a b staged.go
1 .M N... 100644 100644 100644 a b modified.go
1 MM N... 100644 100644 100644 a b both.go
2 R. N... 100644 100644 100644 a b R100 new.go	old.go
u UU N... 100644 100644 100644 100644 a b c conflict.go
? new.txt
? other.txt
`, &r)
	want := Repo{Branch: "main", Upstream: "origin/main", Ahead: 2, Behind: 3, Staged: 3, Modified: 2, Conflicts: 1, Untracked: 2}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("got %+v\nwant %+v", r, want)
	}
	var d Repo
	ParseStatus("# branch.oid abc\n# branch.head (detached)\n", &d)
	if !d.Detached || d.Branch != "" {
		t.Errorf("detached: %+v", d)
	}
}

func TestParseRemote(t *testing.T) {
	for in, want := range map[string][3]string{
		"https://github.com/njhoffman/audit.git": {"github.com", "njhoffman", "audit"},
		"git@github.com:Owner/Repo.git":          {"github.com", "Owner", "Repo"},
		"ssh://git@gitlab.com/group/sub/proj":    {"gitlab.com", "sub", "proj"},
		"https://GitHub.com/o/r/":                {"github.com", "o", "r"},
		"/local/path/repo":                       {"", "", ""},
		"git@host:single":                        {"host", "", ""},
	} {
		h, o, n := ParseRemote(in)
		if [3]string{h, o, n} != want {
			t.Errorf("%s: %s %s %s", in, h, o, n)
		}
	}
	if got := StripCredentials("https://user:ghp_secret@github.com/o/r.git"); got != "https://github.com/o/r.git" {
		t.Errorf("credentials kept: %s", got)
	}
	if got := StripCredentials("git@github.com:o/r.git"); got != "git@github.com:o/r.git" {
		t.Errorf("scp form changed: %s", got)
	}
}

func TestParseRemotes(t *testing.T) {
	got := ParseRemotes(`[core]
	bare = false
[remote "origin"]
	url = git@github.com:o/r.git
	url = https://mirror/o/r
	fetch = +refs/heads/*:refs/remotes/origin/*
[remote "up stream"]
	url = "https://github.com/up/r"
[branch "main"]
	remote = origin
`)
	want := map[string]string{"origin": "git@github.com:o/r.git", "up stream": "https://github.com/up/r"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("remotes: %v", got)
	}
}

func TestLanguage(t *testing.T) {
	if got := Language([]string{"a.go", "b.go", "c.py", "README.md", "x.yaml", ""}); got != "go" {
		t.Errorf("language = %q", got)
	}
	if got := Language([]string{"README.md"}); got != "" {
		t.Errorf("markup only: %q", got)
	}
}

func mkrepo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	mkrepo(t, filepath.Join(home, "ghq/github.com/o/a"))
	mkrepo(t, filepath.Join(home, "ghq/github.com/o/a/nested"))
	mkrepo(t, filepath.Join(home, "proj"))
	mkrepo(t, filepath.Join(home, ".zinit/plugins/x"))
	mkrepo(t, filepath.Join(home, "web/node_modules/dep"))
	mkrepo(t, filepath.Join(home, "a/b/c/d/e/deep"))
	if err := os.Symlink(filepath.Join(home, "proj"), filepath.Join(home, "link-to-proj")); err != nil {
		t.Fatal(err)
	}
	got := Discover(Options{Roots: []string{filepath.Join(home, "ghq"), home}, MaxDepth: 4,
		Exclude: []string{filepath.Join(home, ".zinit"), "**/node_modules"}})
	want := []string{filepath.Join(home, "ghq/github.com/o/a"), filepath.Join(home, "proj")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := osexec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestInspect(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	upstream := filepath.Join(root, "upstream")
	gitRun(t, root, "init", "-q", "-b", "main", upstream)
	if err := os.WriteFile(filepath.Join(upstream, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, upstream, "add", ".")
	gitRun(t, upstream, "commit", "-q", "-m", "one")
	clone := filepath.Join(root, "clone")
	gitRun(t, root, "clone", "-q", upstream, clone)
	gitRun(t, clone, "remote", "set-url", "origin", "https://u:tok@github.com/o/r.git")
	if err := os.WriteFile(filepath.Join(clone, "main.go"), []byte("package main // edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clone, "new.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := exec.FromOS()
	r := Inspect(ctx, env, clone)
	if r.Error != "" || r.Branch != "main" || r.Upstream != "origin/main" || r.Modified != 1 || r.Untracked != 1 ||
		r.Remote != "https://github.com/o/r.git" || r.Owner != "o" || r.Name != "r" || r.Remotes != 1 ||
		r.Language != "go" || r.LastCommit.IsZero() || r.RemoteHEAD != "main" || r.Empty {
		t.Errorf("clone: %+v", r)
	}
	empty := filepath.Join(root, "empty")
	gitRun(t, root, "init", "-q", empty)
	if e := Inspect(ctx, env, empty); !e.Empty || e.Remotes != 0 || e.Error != "" {
		t.Errorf("empty: %+v", e)
	}
	if bad := Inspect(ctx, env, filepath.Join(root, "nothing")); bad.Error == "" {
		t.Error("not a repo")
	}
}

func TestLinks(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	mkrepo(t, repo)
	links := filepath.Join(dir, "git")
	if err := os.MkdirAll(links, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"ok": repo, "gone": filepath.Join(dir, "missing"), "plain": dir} {
		if err := os.Symlink(target, filepath.Join(links, name)); err != nil {
			t.Fatal(err)
		}
	}
	by := map[string]Link{}
	for _, l := range Links([]string{links, filepath.Join(dir, "nope")}) {
		by[filepath.Base(l.Path)] = l
	}
	if len(by) != 3 || by["ok"].Broken || by["ok"].NotRepo || !by["gone"].Broken || !by["plain"].NotRepo {
		t.Errorf("links: %+v", by)
	}
}

func checksBy(fs []finding.Finding) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, f := range fs {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

func TestChecks(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	gh := "/h/ghq"
	rs := []Repo{
		{Path: gh + "/github.com/me/clean", Host: "github.com", Owner: "me", Name: "clean", Remotes: 1, Branch: "main",
			Upstream: "origin/main", LastFetch: now, RemoteHEAD: "master"},
		{Path: gh + "/github.com/me/work", Host: "github.com", Owner: "me", Name: "work", Remotes: 1, Branch: "dev",
			Upstream: "origin/dev", Ahead: 2, Behind: 1, Modified: 3, Untracked: 1, Stashes: 2, LastFetch: now.Add(-60 * 24 * time.Hour)},
		{Path: "/h/elsewhere/work", Host: "github.com", Owner: "me", Name: "work", Remotes: 1, Detached: true, Operation: "rebase", Conflicts: 1},
		{Path: gh + "/github.com/wrong/place", Host: "github.com", Owner: "other", Name: "thing", Remotes: 1, Branch: "x"},
		{Path: "/h/scratch", Remotes: 0},
		{Path: "/h/broken", Error: "git status failed: fatal"},
	}
	metas := map[string]Meta{
		"github.com/me/clean":    {Key: "github.com/me/clean", DefaultBranch: "main", Archived: true, Moved: "me/clean2"},
		"github.com/other/thing": {Key: "github.com/other/thing", Missing: true},
		"github.com/me/work":     {Key: "github.com/me/work", Error: "rate limited", Missing: true},
	}
	s := &State{Repos: rs, Meta: metas, User: "me", GhqRoot: gh, StaleFetch: 30 * 24 * time.Hour, Now: now,
		Links: []Link{{Path: "/h/git/x", Target: "/gone", Broken: true}}}
	by := checksBy(Analyze(s))
	count := func(check string) int { return len(by[check]) }
	for check, n := range map[string]int{
		"repo.error": 1, "repo.operation": 1, "repo.dirty": 1, "repo.unpushed": 1, "repo.no_remote": 1, "repo.missing": 1,
		"repo.moved": 1, "repo.default_branch": 1, "repo.duplicate": 1, "repo.behind": 1, "repo.untracked": 1,
		"repo.stash": 1, "repo.no_upstream": 1, "repo.detached": 1, "repo.stale_fetch": 3, "repo.layout": 1,
		"repo.archived": 1, "links.broken": 1,
	} {
		if count(check) != n {
			t.Errorf("%s: %d findings, want %d: %+v", check, count(check), n, by[check])
		}
	}
	if f := by["repo.unpushed"][0]; !strings.Contains(f.Hint, "--push") {
		t.Errorf("my own repo: %+v", f)
	}
	if f := by["repo.duplicate"][0]; len(f.Details) != 2 || f.Severity != finding.Warning {
		t.Errorf("duplicate: %+v", f)
	}
	if f := by["repo.missing"][0]; f.Subject != gh+"/github.com/wrong/place" {
		t.Errorf("a failed lookup is not evidence of a missing repo: %+v", by["repo.missing"])
	}
}

func TestAnnotateAndQuery(t *testing.T) {
	rs := []Repo{
		{Path: "/a", Host: "github.com", Owner: "me", Name: "a", Remotes: 1, Language: "go", Modified: 1},
		{Path: "/b", Host: "gitlab.com", Owner: "them", Name: "b", Remotes: 1, Behind: 2},
		{Path: "/c", Remotes: 0},
	}
	items := Annotate(rs, map[string]Meta{"github.com/me/a": {Fork: true, Topics: []string{"Neovim Plugin"}}},
		map[string][]string{"gitlab.com/them/b": {"work"}}, "me")
	if !reflect.DeepEqual(items[0].Tags, []string{"fork", "github", "go", "mine", "neovim-plugin"}) || !items[0].IsMine {
		t.Errorf("a: %+v", items[0])
	}
	if !reflect.DeepEqual(items[1].Tags, []string{"gitlab", "others", "work"}) || !reflect.DeepEqual(items[2].Tags, []string{"local"}) {
		t.Errorf("b, c: %+v %+v", items[1].Tags, items[2].Tags)
	}
	pick := func(q Query) string {
		var names []string
		for _, it := range q.Filter(items) {
			names = append(names, it.Path)
		}
		return strings.Join(names, ",")
	}
	for _, c := range []struct {
		q    Query
		want string
	}{
		{Query{}, "/a,/b,/c"},
		{Query{Owner: "mine"}, "/a"},
		{Query{Owner: "others"}, "/b"},
		{Query{Owner: "them"}, "/b"},
		{Query{Outdated: true}, "/b"},
		{Query{Dirty: true}, "/a"},
		{Query{Tags: []string{"WORK"}}, "/b"},
		{Query{Find: "github.com/me"}, "/a"},
	} {
		if got := pick(c.q); got != c.want {
			t.Errorf("%+v: %q, want %q", c.q, got, c.want)
		}
	}
	if !(Query{}).Empty() || (Query{Dirty: true}).Empty() {
		t.Error("Empty")
	}
}
