// Package repos finds the git repositories on the workstation, inspects
// their local state, and checks them for unsaved work, drift from their
// remotes and layout problems. Inspection never touches the network; what a
// repo knows about its remote is as old as its last fetch.
package repos

import (
	"context"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Command is the audit subcommand name.
const Command = "repos"

// Repo is one repository's local state.
type Repo struct {
	Path string `json:"path"`
	// Remote is origin's URL (or the first remote's) without credentials.
	Remote string `json:"remote,omitempty"`
	// Host, Owner and Name are parsed from Remote; empty when it has none or
	// it cannot be parsed.
	Host  string `json:"host,omitempty"`
	Owner string `json:"owner,omitempty"`
	Name  string `json:"name,omitempty"`
	// Remotes counts the configured remotes.
	Remotes  int    `json:"remotes"`
	Branch   string `json:"branch,omitempty"`
	Detached bool   `json:"detached,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	Ahead    int    `json:"ahead"`
	Behind   int    `json:"behind"`
	// RemoteHEAD is the default branch origin had at the last fetch.
	RemoteHEAD string `json:"remote_head,omitempty"`
	Staged     int    `json:"staged"`
	Modified   int    `json:"modified"`
	Untracked  int    `json:"untracked"`
	Conflicts  int    `json:"conflicts"`
	Stashes    int    `json:"stashes"`
	// Operation is a merge, rebase, cherry-pick, revert or bisect in
	// progress.
	Operation  string    `json:"operation,omitempty"`
	LastCommit time.Time `json:"last_commit,omitzero"`
	// LastFetch is FETCH_HEAD's time; zero when never fetched.
	LastFetch time.Time `json:"last_fetch,omitzero"`
	Language  string    `json:"language,omitempty"`
	// Empty marks a repository with no commits.
	Empty bool   `json:"empty,omitempty"`
	Error string `json:"error,omitempty"`
}

// Slug is host/owner/name, or the path when the remote is unknown.
func (r Repo) Slug() string {
	if r.Host != "" && r.Owner != "" && r.Name != "" {
		return r.Host + "/" + r.Owner + "/" + r.Name
	}
	return r.Path
}

// Key identifies the repo for metadata and tags: its slug, lowercased.
func (r Repo) Key() string { return strings.ToLower(r.Slug()) }

// Dirty reports uncommitted changes (untracked files aside).
func (r Repo) Dirty() bool { return r.Staged+r.Modified+r.Conflicts > 0 }

// Clean reports a working tree with nothing to lose: no changes, no
// untracked files and no operation in progress.
func (r Repo) Clean() bool { return !r.Dirty() && r.Untracked == 0 && r.Operation == "" }

// Data is what a repos run stores in run.Run.Data.
type Data struct {
	Repos []Repo `json:"repos"`
	// Links are the symlinks of repos.link_dirs and where they point.
	Links []Link `json:"links,omitempty"`
}

// Link is a symlink in a link directory.
type Link struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	// Broken: the target is missing; NotRepo: it exists but is no repo.
	Broken  bool `json:"broken,omitempty"`
	NotRepo bool `json:"not_repo,omitempty"`
}

// Options control Discover.
type Options struct {
	Roots []string
	// Exclude are paths (prefix match) or "**/NAME" (any directory called
	// NAME) never descended into.
	Exclude  []string
	MaxDepth int
}

// Discover walks the roots up to MaxDepth directories deep and returns every
// repository's path (by real path, so a repo reached twice counts once). It
// does not descend into a repository.
func Discover(o Options) []string {
	seen := map[string]bool{}
	var out []string
	excluded := func(p string) bool {
		for _, e := range o.Exclude {
			if name, ok := strings.CutPrefix(e, "**/"); ok {
				if filepath.Base(p) == name {
					return true
				}
				continue
			}
			e = filepath.Clean(e)
			if p == e || strings.HasPrefix(p, e+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	for _, root := range o.Roots {
		root = filepath.Clean(root)
		base := strings.Count(root, string(filepath.Separator))
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if p != root && excluded(p) {
				return filepath.SkipDir
			}
			if strings.Count(p, string(filepath.Separator))-base > o.MaxDepth {
				return filepath.SkipDir
			}
			if st, err := os.Stat(filepath.Join(p, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
				real := p
				if r, err := filepath.EvalSymlinks(p); err == nil {
					real = r
				}
				if !seen[real] {
					seen[real] = true
					out = append(out, real)
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// InspectAll inspects paths with up to workers at a time, calling onDone as
// each finishes. Results keep the order of paths.
func InspectAll(ctx context.Context, env *exec.Env, paths []string, workers int, onDone func(Repo)) []Repo {
	if workers < 1 {
		workers = 1
	}
	out := make([]Repo, len(paths))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, max(1, len(paths))) {
		wg.Go(func() {
			for i := range jobs {
				out[i] = Inspect(ctx, env, paths[i])
				if onDone != nil {
					onDone(out[i])
				}
			}
		})
	}
	for i := range paths {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

func git(ctx context.Context, env *exec.Env, dir string, args ...string) exec.Result {
	return env.Run(ctx, "git", append([]string{"-C", dir}, args...),
		exec.Options{Timeout: 30 * time.Second, Unset: []string{"GIT_DIR", "GIT_WORK_TREE"}})
}

// Inspect reads one repository's state with local git commands.
func Inspect(ctx context.Context, env *exec.Env, path string) Repo {
	r := Repo{Path: path}
	st := git(ctx, env, path, "status", "--porcelain=v2", "--branch", "--untracked-files=normal")
	if !st.OK() {
		r.Error = "git status failed: " + firstLine(st.Stderr)
		return r
	}
	ParseStatus(st.Stdout, &r)

	dir := filepath.Join(path, ".git")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		// A worktree or submodule: .git is a file pointing elsewhere.
		dir = ""
		if gd := git(ctx, env, path, "rev-parse", "--absolute-git-dir"); gd.OK() {
			dir = strings.TrimSpace(gd.Stdout)
		}
	}
	urls, names := remoteURLs(ctx, env, path, dir)
	r.Remotes = len(names)
	u, ok := urls["origin"]
	if !ok && len(names) > 0 {
		u = urls[names[0]]
	}
	if u != "" {
		r.Remote = StripCredentials(u)
		r.Host, r.Owner, r.Name = ParseRemote(r.Remote)
	}
	if lc := git(ctx, env, path, "log", "-1", "--format=%ct"); lc.OK() {
		if n, err := strconv.ParseInt(strings.TrimSpace(lc.Stdout), 10, 64); err == nil {
			r.LastCommit = time.Unix(n, 0)
		}
	} else {
		r.Empty = true
	}
	if dir != "" {
		r.Operation = operation(dir)
		if fi, err := os.Stat(filepath.Join(dir, "FETCH_HEAD")); err == nil {
			r.LastFetch = fi.ModTime()
		}
		if b, err := os.ReadFile(filepath.Join(dir, "logs", "refs", "stash")); err == nil { // #nosec G304 -- inside a repo
			r.Stashes = strings.Count(strings.TrimRight(string(b), "\n"), "\n") + 1
		}
		if b, err := os.ReadFile(filepath.Join(dir, "refs", "remotes", "origin", "HEAD")); err == nil { // #nosec G304 -- inside a repo
			if ref, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "ref: refs/remotes/origin/"); ok {
				r.RemoteHEAD = ref
			}
		}
	}
	if ls := git(ctx, env, path, "ls-files", "-z"); ls.OK() {
		r.Language = Language(strings.Split(ls.Stdout, "\x00"))
	}
	return r
}

// remoteURLs reads the remotes from the repo's config file, falling back to
// git config for layouts it cannot read (a worktree's shared config).
// names are sorted.
func remoteURLs(ctx context.Context, env *exec.Env, path, dir string) (map[string]string, []string) {
	urls := map[string]string{}
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "config")); err == nil { // #nosec G304 -- inside a repo
			urls = ParseRemotes(string(b))
			if len(urls) > 0 || !strings.Contains(string(b), "[remote") {
				return urls, sortedKeys(urls)
			}
		}
	}
	if rem := git(ctx, env, path, "config", "--get-regexp", `^remote\..*\.url$`); rem.OK() {
		for line := range strings.SplitSeq(strings.TrimSpace(rem.Stdout), "\n") {
			if k, v, ok := strings.Cut(line, " "); ok {
				urls[strings.TrimSuffix(strings.TrimPrefix(k, "remote."), ".url")] = v
			}
		}
	}
	return urls, sortedKeys(urls)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	remoteSection = regexp.MustCompile(`^\[remote\s+"([^"]+)"\]`)
	urlLine       = regexp.MustCompile(`^url\s*=\s*(.+)$`)
)

// ParseRemotes reads the remote URLs from a git config file. Only the first
// url of each remote counts, as with git's fetch.
func ParseRemotes(config string) map[string]string {
	out := map[string]string{}
	current := ""
	for line := range strings.SplitSeq(config, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			current = ""
			if m := remoteSection.FindStringSubmatch(t); m != nil {
				current = m[1]
			}
			continue
		}
		if current == "" {
			continue
		}
		if m := urlLine.FindStringSubmatch(t); m != nil {
			if _, seen := out[current]; !seen {
				out[current] = strings.Trim(strings.TrimSpace(m[1]), `"`)
			}
		}
	}
	return out
}

func operation(gitDir string) string {
	for _, op := range []struct{ file, name string }{
		{"rebase-merge", "rebase"}, {"rebase-apply", "rebase"}, {"MERGE_HEAD", "merge"},
		{"CHERRY_PICK_HEAD", "cherry-pick"}, {"REVERT_HEAD", "revert"}, {"BISECT_LOG", "bisect"},
	} {
		if _, err := os.Stat(filepath.Join(gitDir, op.file)); err == nil {
			return op.name
		}
	}
	return ""
}

// ParseStatus fills r from `git status --porcelain=v2 --branch`.
func ParseStatus(out string, r *Repo) {
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case strings.HasPrefix(line, "# branch.head "):
			h := strings.TrimPrefix(line, "# branch.head ")
			if h == "(detached)" {
				r.Detached = true
			} else {
				r.Branch = h
			}
		case strings.HasPrefix(line, "# branch.upstream "):
			r.Upstream = strings.TrimPrefix(line, "# branch.upstream ")
		case strings.HasPrefix(line, "# branch.ab "):
			if a, b, ok := parseAB(strings.TrimPrefix(line, "# branch.ab ")); ok {
				r.Ahead, r.Behind = a, b
			}
		case strings.HasPrefix(line, "1 "), strings.HasPrefix(line, "2 "):
			f := strings.Fields(line)
			if len(f) > 1 && len(f[1]) == 2 {
				if f[1][0] != '.' {
					r.Staged++
				}
				if f[1][1] != '.' {
					r.Modified++
				}
			}
		case strings.HasPrefix(line, "u "):
			r.Conflicts++
		case strings.HasPrefix(line, "? "):
			r.Untracked++
		}
	}
}

// parseAB reads git's "+A -B" ahead/behind counts.
func parseAB(s string) (ahead, behind int, ok bool) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimPrefix(f[0], "+"))
	b, err2 := strconv.Atoi(strings.TrimPrefix(f[1], "-"))
	return a, b, err1 == nil && err2 == nil
}

// StripCredentials drops a password or token from an http(s) remote URL,
// so it is never saved or exported.
func StripCredentials(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.User == nil || (p.Scheme != "http" && p.Scheme != "https") {
		return u
	}
	p.User = nil
	return p.String()
}

var scpRe = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// ParseRemote splits a remote URL (https://host/owner/name.git,
// git@host:owner/name.git, ssh://git@host/owner/name) into its parts.
func ParseRemote(u string) (host, owner, name string) {
	var p string
	if pu, err := url.Parse(u); err == nil && pu.Scheme != "" && pu.Host != "" {
		host, p = pu.Hostname(), pu.Path
	} else if m := scpRe.FindStringSubmatch(u); m != nil {
		host, p = m[1], m[2]
	} else {
		return "", "", ""
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(p, ".git"), "/"), "/")
	if len(parts) < 2 {
		return host, "", ""
	}
	return strings.ToLower(host), parts[len(parts)-2], parts[len(parts)-1]
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}

// languages maps file extensions to a language name.
var languages = map[string]string{
	".go": "go", ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".rs": "rust", ".c": "c", ".h": "c", ".cc": "c++", ".cpp": "c++",
	".hpp": "c++", ".cxx": "c++", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php", ".lua": "lua",
	".sh": "shell", ".bash": "shell", ".zsh": "shell", ".fish": "shell", ".vim": "vim", ".el": "elisp",
	".hs": "haskell", ".ml": "ocaml", ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".clj": "clojure",
	".scala": "scala", ".swift": "swift", ".m": "objective-c", ".cs": "c#", ".fs": "f#", ".dart": "dart",
	".zig": "zig", ".nim": "nim", ".jl": "julia", ".r": "r", ".pl": "perl", ".pm": "perl", ".vue": "vue",
	".svelte": "svelte", ".css": "css", ".scss": "css", ".html": "html", ".tex": "tex", ".nix": "nix",
	".tf": "terraform", ".sql": "sql", ".ps1": "powershell", ".qml": "qml", ".glsl": "glsl", ".v": "verilog",
}

// Language is the most common language among files, by extension; "" when
// none is recognized. Markup and data files do not count.
func Language(files []string) string {
	count := map[string]int{}
	for i, f := range files {
		if i > 20000 {
			break
		}
		if l, ok := languages[strings.ToLower(filepath.Ext(f))]; ok {
			count[l]++
		}
	}
	best, n := "", 0
	for l, c := range count {
		if c > n || c == n && l < best {
			best, n = l, c
		}
	}
	return best
}

// Links reads the symlinks of dirs and whether each points at a repo.
func Links(dirs []string) []Link {
	var out []Link
	for _, d := range dirs {
		es, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range es {
			p := filepath.Join(d, e.Name())
			if e.Type()&os.ModeSymlink == 0 {
				continue
			}
			target, _ := os.Readlink(p)
			l := Link{Path: p, Target: target}
			if _, err := os.Stat(p); err != nil {
				l.Broken = true
			} else if _, err := os.Stat(filepath.Join(p, ".git")); err != nil {
				l.NotRepo = true
			}
			out = append(out, l)
		}
	}
	return out
}
