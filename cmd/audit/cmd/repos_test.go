package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

// ghOnly runs git for real and answers gh: the user is "me", and GitHub
// says me/tool moved to me/tool2.
type ghOnly struct {
	mu   sync.Mutex
	real exec.Runner
	gh   []string
}

func (g *ghOnly) Run(ctx context.Context, name string, args []string, opts exec.Options) exec.Result {
	if name != "gh" {
		return g.real.Run(ctx, name, args, opts)
	}
	g.mu.Lock()
	g.gh = append(g.gh, strings.Join(args, " "))
	g.mu.Unlock()
	switch {
	case len(args) > 1 && args[0] == "api" && args[1] == "user":
		return exec.Result{Stdout: "me\n"}
	case len(args) > 1 && args[0] == "api" && args[1] == "graphql":
		return exec.Result{Stdout: `{"data":{"r0":{"nameWithOwner":"me/tool2","defaultBranchRef":{"name":"main"},` +
			`"repositoryTopics":{"nodes":[{"topic":{"name":"cli"}}]}}}}`}
	}
	return exec.Result{Code: exec.ExitNotFound}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := osexec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// reposEnv makes ~/ghq/github.com/me/tool (dirty, mine), ~/ghq/github.com/x/lib
// (clean, someone else's) and a broken link in ~/git.
func reposEnv(t *testing.T) string {
	t.Helper()
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	for _, slug := range []string{"github.com/me/tool", "github.com/x/lib"} {
		p := filepath.Join(home, "ghq", slug)
		gitIn(t, home, "init", "-q", "-b", "main", p)
		if err := os.WriteFile(filepath.Join(p, "main.go"), []byte("package main\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitIn(t, p, "add", ".")
		gitIn(t, p, "commit", "-q", "-m", "init")
		gitIn(t, p, "remote", "add", "origin", "git@"+strings.Replace(slug, "/", ":", 1)+".git")
	}
	if err := os.WriteFile(filepath.Join(home, "ghq/github.com/me/tool/main.go"), []byte("package main // wip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "git"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "ghq/gone"), filepath.Join(home, "git", "gone")); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, cfgHome, "repos: {roots: ["+home+"], link_dirs: ["+filepath.Join(home, "git")+"], ghq_root: "+
		filepath.Join(home, "ghq")+"}\n")
	return home
}

// inventory is the repo table of a --list output.
func inventory(out string) string {
	if i := strings.Index(out, "\nREPO "); i >= 0 {
		return out[i:]
	}
	return out
}

func runRepos(t *testing.T, g *ghOnly, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return false }
	a.runner = g
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	a.close()
	return result{out.String(), errOut.String(), e, a}
}

func TestReposScanAndFilters(t *testing.T) {
	home := reposEnv(t)
	g := &ghOnly{real: exec.NewOSRunner(exec.FromOS())}
	r := runRepos(t, g, "repos", "-l")
	if r.e == nil {
		t.Fatal("--list with no saved run must fail")
	}
	r = runRepos(t, g, "repos", "-r", "-l")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"repo.dirty", "links.broken", "github.com/me/tool", "github.com/x/lib", "1 modified", "2 repo(s), 1 yours."} {
		if !strings.Contains(r.out, want) {
			t.Errorf("list missing %q:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "repo.moved") {
		t.Error("a plain scan never asks GitHub")
	}
	if r := runRepos(t, g, "repos", "-O", "mine"); !strings.Contains(r.out, "1 repo(s), 1 yours.") || strings.Contains(inventory(r.out), "x/lib") {
		t.Errorf("--owner mine:\n%s", r.out)
	}
	if r := runRepos(t, g, "repos", "-d"); !strings.Contains(inventory(r.out), "me/tool") || strings.Contains(inventory(r.out), "x/lib") {
		t.Errorf("--dirty:\n%s", r.out)
	}
	if r := runRepos(t, g, "repos", "-t", "nothing"); !strings.Contains(r.out, "No repos match the filter.") {
		t.Errorf("no match:\n%s", r.out)
	}

	if r := runRepos(t, g, "repos", "tag", "lib", "Work Stuff"); r.e != nil || r.out != "Tagged github.com/x/lib: work-stuff\n" {
		t.Errorf("tag: %v %q", r.e, r.out)
	}
	if r := runRepos(t, g, "repos", "-t", "work-stuff"); !strings.Contains(inventory(r.out), "x/lib") || strings.Contains(inventory(r.out), "me/tool") {
		t.Errorf("tag filter:\n%s", r.out)
	}
	if r := runRepos(t, g, "repos", "info", filepath.Join(home, "ghq/github.com/me/tool"), "-j"); r.e != nil ||
		!strings.Contains(r.out, `"mine": true`) || !strings.Contains(r.out, `"language": "go"`) {
		t.Errorf("info: %v\n%s", r.e, r.out)
	}
	if r := runRepos(t, g, "repos", "info", "nope"); r.e == nil {
		t.Error("unknown repo")
	}

	r = runRepos(t, g, "repos", "refresh", "-N", "-l")
	if r.e != nil || !strings.Contains(r.out, "repo.moved") || !strings.Contains(r.out, "me/tool was renamed or transferred to me/tool2") {
		t.Fatalf("refresh: %v\n%s\n%s", r.e, r.out, r.err)
	}
	var graphql int
	for _, c := range g.gh {
		if strings.HasPrefix(c, "api graphql") {
			graphql++
		}
	}
	if graphql != 1 {
		t.Errorf("one batch for two repos: %v", g.gh)
	}
	r = runRepos(t, g, "repos", "-j")
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || !strings.Contains(r.out, `"cli"`) {
		t.Errorf("GitHub topics become tags:\n%s", r.out)
	}
}
