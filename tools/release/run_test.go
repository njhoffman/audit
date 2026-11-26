package main

import (
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repo makes a git repository on main with a bare origin, CHANGELOG.md
// committed and tagged v0.1.0, and changes into it.
func repo(t *testing.T, changelogText string) (dir, remote string) {
	t.Helper()
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	dir, remote = filepath.Join(root, "work"), filepath.Join(root, "origin.git")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "test")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "test@example.invalid")
	}
	sh := func(d string, args ...string) {
		t.Helper()
		c := osexec.Command("git", args...)
		c.Dir = d
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	sh(root, "init", "-q", "--bare", "-b", "main", remote)
	sh(root, "init", "-q", "-b", "main", dir)
	sh(dir, "config", "tag.gpgSign", "false")
	sh(dir, "config", "commit.gpgSign", "false")
	sh(dir, "remote", "add", "origin", remote)
	if err := os.WriteFile(filepath.Join(dir, changelog), []byte(changelogText), 0o600); err != nil {
		t.Fatal(err)
	}
	sh(dir, "add", changelog)
	sh(dir, "commit", "-q", "-m", "init")
	sh(dir, "tag", "-a", "v0.1.0", "-m", "v0.1.0")
	sh(dir, "push", "-q", "origin", "main", "v0.1.0")
	t.Chdir(dir)
	return dir, remote
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := osexec.Command("git", args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestRunNoPush(t *testing.T) {
	dir, remote := repo(t, log)
	if err := run("", false, true, false); err != nil {
		t.Fatal(err)
	}
	if got := gitOut(t, dir, "describe", "--tags", "--exact-match"); got != "v0.1.1" {
		t.Errorf("tag at HEAD = %q, want v0.1.1 (Fixed is a patch)", got)
	}
	if typ := gitOut(t, dir, "cat-file", "-t", "v0.1.1"); typ != "tag" {
		t.Errorf("the tag is %s, want an annotated tag", typ)
	}
	if msg := gitOut(t, dir, "log", "-1", "--format=%s"); msg != "Release v0.1.1" {
		t.Errorf("commit message %q", msg)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, changelog))
	if body, _, _, _ := Unreleased(string(raw)); body != "" || !strings.Contains(string(raw), "## [0.1.1] - ") {
		t.Errorf("changelog not rewritten:\n%s", raw)
	}
	if tags := gitOut(t, remote, "tag"); strings.Contains(tags, "v0.1.1") {
		t.Error("--no-push pushed the tag")
	}
	if s := gitOut(t, dir, "status", "--porcelain"); s != "" {
		t.Errorf("tree left dirty: %q", s)
	}
}

func TestRunPushAndLevels(t *testing.T) {
	dir, remote := repo(t, strings.Replace(log, "### Fixed", "### Removed", 1))
	if err := run("", false, false, false); err != nil {
		t.Fatal(err)
	}
	// A removal is major, which before 1.0 moves the minor.
	if got := gitOut(t, remote, "tag"); !strings.Contains(got, "v0.2.0") {
		t.Errorf("remote tags %q, want v0.2.0", got)
	}
	if local, origin := gitOut(t, dir, "rev-parse", "main"), gitOut(t, remote, "rev-parse", "main"); local != origin {
		t.Errorf("main not pushed: %s vs %s", local, origin)
	}
	// An explicit level overrides the inferred one; the new Unreleased
	// section is empty, so there is nothing to release.
	if err := run(Patch, false, true, false); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty Unreleased section: %v", err)
	}
}

func TestRunExplicitMajor(t *testing.T) {
	dir, _ := repo(t, log)
	if err := run(Major, false, true, true); err != nil {
		t.Fatal(err)
	}
	if got := gitOut(t, dir, "describe", "--tags", "--exact-match"); got != "v1.0.0" {
		t.Errorf("--allow-major major: %q", got)
	}
}

func TestRunDryRun(t *testing.T) {
	dir, _ := repo(t, log)
	head := gitOut(t, dir, "rev-parse", "HEAD")
	if err := run("", true, false, false); err != nil {
		t.Fatal(err)
	}
	if gitOut(t, dir, "rev-parse", "HEAD") != head || gitOut(t, dir, "tag") != "v0.1.0" {
		t.Error("a dry run committed or tagged")
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, changelog)); string(raw) != log {
		t.Error("a dry run rewrote the changelog")
	}
}

func TestRunRefuses(t *testing.T) {
	dir, _ := repo(t, log)
	if err := os.WriteFile(filepath.Join(dir, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("", false, true, false); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Errorf("a dirty tree: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "x")); err != nil {
		t.Fatal(err)
	}
	gitOut(t, dir, "checkout", "-q", "-b", "feature")
	if err := run("", false, true, false); err == nil || !strings.Contains(err.Error(), "from main") {
		t.Errorf("a branch other than main: %v", err)
	}
	gitOut(t, dir, "checkout", "-q", "main")
	if err := run("huge", false, true, false); err == nil || !strings.Contains(err.Error(), "unknown bump") {
		t.Errorf("an unknown level: %v", err)
	}
	if gitOut(t, dir, "tag") != "v0.1.0" {
		t.Error("a refused run tagged")
	}
}
