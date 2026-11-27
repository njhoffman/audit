package gitfix

import (
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := osexec.Command("git", append([]string{"-C", dir}, args...)...) // #nosec G204 -- test
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotDiffCommit(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "t")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "t@t")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	repo := filepath.Join(home, "repo")
	git(t, home, "init", "-q", "-b", "main", repo)
	write(t, filepath.Join(repo, "a.conf"), "a=1\n")
	write(t, filepath.Join(repo, "b.conf"), "b=1\n")
	write(t, filepath.Join(repo, "c.conf"), "c=1\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "init")
	// The user's own work in progress: b edited, c staged.
	write(t, filepath.Join(repo, "b.conf"), "b=mine\n")
	write(t, filepath.Join(repo, "c.conf"), "c=staged\n")
	git(t, repo, "add", "c.conf")

	env := exec.FromOS()
	ctx := context.Background()
	roots := Roots(ctx, env, []string{filepath.Join(repo, "a.conf"), filepath.Join(repo, "sub", "missing.conf"), home})
	if len(roots) != 1 || roots[0] != repo {
		t.Fatalf("roots %v", roots)
	}
	before, err := Take(ctx, env, roots)
	if err != nil {
		t.Fatal(err)
	}
	// The fix: a changed, a new file, and b (already dirty) changed again.
	write(t, filepath.Join(repo, "a.conf"), "a=fixed\n")
	write(t, filepath.Join(repo, "new.conf"), "n=1\n")
	write(t, filepath.Join(repo, "b.conf"), "b=mine and fixed\n")
	cs, err := Diff(ctx, env, before)
	if err != nil || len(cs) != 1 || !slices.Equal(cs[0].Files, []string{"a.conf", "new.conf"}) || !slices.Equal(cs[0].Mixed, []string{"b.conf"}) {
		t.Fatalf("changes %+v %v", cs, err)
	}
	if err := Commit(ctx, env, cs[0], "audit: fix #7 sshd"); err != nil {
		t.Fatal(err)
	}
	if got := git(t, repo, "show", "--name-only", "--format=%s", "HEAD"); got != "audit: fix #7 sshd\n\na.conf\nnew.conf\n" {
		t.Errorf("commit holds only the fix's files:\n%s", got)
	}
	st := git(t, repo, "status", "--porcelain")
	if !strings.Contains(st, " M b.conf") || !strings.Contains(st, "M  c.conf") {
		t.Errorf("the user's changes stay as they were (b edited, c staged):\n%s", st)
	}
	if err := Commit(ctx, env, Change{Root: repo}, "x"); err == nil {
		t.Error("an empty change is refused")
	}
	if cs, _ := Diff(ctx, env, Snapshot{{Root: repo, Dirty: map[string]string{}}}); len(cs) != 1 {
		t.Errorf("against an empty snapshot everything dirty is new: %+v", cs)
	}
}
