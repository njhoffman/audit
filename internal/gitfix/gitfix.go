// Package gitfix finds what an AI fix session changed in the git work trees
// a task touches and commits exactly that.
package gitfix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

const timeout = 30 * time.Second

// Tree is one work tree's dirty files, by path relative to Root, with a
// hash of their content ("" for a deleted file).
type Tree struct {
	Root  string
	Dirty map[string]string
}

// Snapshot is the state of every work tree before a session.
type Snapshot []Tree

// Roots are the distinct git work trees containing paths (files or
// directories; missing ones are looked up through their nearest existing
// parent), in the order first seen.
func Roots(ctx context.Context, env *exec.Env, paths []string) []string {
	var out []string
	for _, p := range paths {
		dir := p
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			dir = filepath.Dir(p)
		}
		for dir != "/" && dir != "." {
			if _, err := os.Stat(dir); err == nil {
				break
			}
			dir = filepath.Dir(dir)
		}
		r := env.Run(ctx, "git", []string{"-C", dir, "rev-parse", "--show-toplevel"}, exec.Options{Timeout: timeout})
		if !r.OK() {
			continue
		}
		if root := strings.TrimSpace(r.Stdout); root != "" && !slices.Contains(out, root) {
			out = append(out, root)
		}
	}
	return out
}

// Take records the dirty files of roots.
func Take(ctx context.Context, env *exec.Env, roots []string) (Snapshot, error) {
	var s Snapshot
	for _, root := range roots {
		d, err := dirty(ctx, env, root)
		if err != nil {
			return nil, err
		}
		s = append(s, Tree{Root: root, Dirty: d})
	}
	return s, nil
}

// dirty lists modified, added, deleted and untracked files with a hash of
// each one's content.
func dirty(ctx context.Context, env *exec.Env, root string) (map[string]string, error) {
	r := env.Run(ctx, "git", []string{"-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all"}, exec.Options{Timeout: timeout})
	if !r.OK() {
		return nil, fmt.Errorf("git status in %s: %s", root, strings.TrimSpace(r.Stderr))
	}
	out := map[string]string{}
	fields := strings.Split(r.Stdout, "\x00")
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if len(f) < 4 {
			continue
		}
		xy, path := f[:2], f[3:]
		if xy[0] == 'R' || xy[0] == 'C' {
			i++ // the rename's source follows
		}
		out[path] = hashFile(filepath.Join(root, path))
	}
	return out, nil
}

func hashFile(p string) string {
	f, err := os.Open(p) // #nosec G304 -- a file git status named
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Change is what a session did to one work tree: Files were clean before
// and are changed now, so they can be committed alone; Mixed already had
// changes of the user's and changed again, so they are left uncommitted.
type Change struct {
	Root  string
	Files []string
	Mixed []string
}

// Diff compares before with the work trees now.
func Diff(ctx context.Context, env *exec.Env, before Snapshot) ([]Change, error) {
	var out []Change
	for _, t := range before {
		now, err := dirty(ctx, env, t.Root)
		if err != nil {
			return nil, err
		}
		c := Change{Root: t.Root}
		for path, h := range now {
			old, was := t.Dirty[path]
			switch {
			case !was:
				c.Files = append(c.Files, path)
			case old != h:
				c.Mixed = append(c.Mixed, path)
			}
		}
		slices.Sort(c.Files)
		slices.Sort(c.Mixed)
		if len(c.Files) > 0 || len(c.Mixed) > 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

// Commit commits c.Files alone with message: staged changes to other files
// stay staged and out of the commit.
func Commit(ctx context.Context, env *exec.Env, c Change, message string) error {
	if len(c.Files) == 0 {
		return errors.New("nothing to commit")
	}
	add := append([]string{"-C", c.Root, "add", "--all", "--"}, c.Files...)
	if r := env.Run(ctx, "git", add, exec.Options{Timeout: timeout}); !r.OK() {
		return fmt.Errorf("git add in %s: %s", c.Root, strings.TrimSpace(r.Stderr))
	}
	commit := append([]string{"-C", c.Root, "commit", "--only", "-m", message, "--"}, c.Files...)
	if r := env.Run(ctx, "git", commit, exec.Options{Timeout: timeout}); !r.OK() {
		return fmt.Errorf("git commit in %s: %s", c.Root, strings.TrimSpace(r.Stderr+"\n"+r.Stdout))
	}
	return nil
}
