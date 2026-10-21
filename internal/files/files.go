package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// Options configure Scan.
type Options struct {
	Env     *exec.Env
	Roots   []string
	Exclude []string
	// Downloads is the downloads directory checked for old files.
	Downloads string
	// LargeMB, DupMinMB, CacheMinMB, BuildMinMB, OrphanMinMB and
	// DownloadsMinMB are the size thresholds of each check.
	LargeMB, DupMinMB, CacheMinMB, BuildMinMB, OrphanMinMB, DownloadsMinMB int64
	// StaleAfter is how long a build directory goes unchanged before it is
	// reclaimable; OldDownloads the same for downloads.
	StaleAfter, OldDownloads time.Duration
	// HashLimit bounds the bytes read to confirm duplicates.
	HashLimit int64
	Top       int
	Now       time.Time
}

const mb = 1 << 20

// Cache is a cache a tool can clear, with its size.
type Cache struct {
	Name  string `json:"name"`
	Path  string `json:"path,omitempty"`
	Bytes int64  `json:"bytes"`
	// Command clears it; empty means move Path to the trash.
	Command []string `json:"command,omitempty"`
	// Root marks commands that need sudo.
	Root bool `json:"root,omitempty"`
}

// Dup is a set of identical files.
type Dup struct {
	Bytes int64    `json:"bytes"`
	Paths []string `json:"paths"`
}

// Orphan is application data whose program looks uninstalled.
type Orphan struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// Data is what a files run stores.
type Data struct {
	Bytes      int64      `json:"bytes"`
	Files      int64      `json:"files"`
	Dirs       int64      `json:"dirs"`
	Unreadable int64      `json:"unreadable,omitempty"`
	Top        []File     `json:"top"`
	Big        []File     `json:"big"`
	Caches     []Cache    `json:"caches,omitempty"`
	Build      []BuildDir `json:"build,omitempty"`
	Orphans    []Orphan   `json:"orphans,omitempty"`
	Downloads  []File     `json:"old_downloads,omitempty"`
	Trash      int64      `json:"trash_bytes,omitempty"`
	TrashPath  string     `json:"trash_path,omitempty"`
	Dups       []Dup      `json:"duplicates,omitempty"`
	Empty      []string   `json:"empty_dirs,omitempty"`
	Broken     []string   `json:"broken_links,omitempty"`
	Cores      []File     `json:"core_dumps,omitempty"`
	// Reclaimable sums what the cleanup candidates free.
	Reclaimable int64 `json:"reclaimable"`
}

// Human renders a byte count ("1.2 GB").
func Human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= mb:
		return fmt.Sprintf("%.0f MB", float64(n)/mb)
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// appDirs are the XDG directories whose children belong to programs.
func appDirs(home string) []string {
	return []string{filepath.Join(home, ".cache"), filepath.Join(home, ".local", "share"), filepath.Join(home, ".local", "state")}
}

// Scan walks the roots and derives the findings.
func Scan(ctx context.Context, o Options, rep progress.Reporter) (*Data, []finding.Finding, []run.Stat, []string, error) {
	home := o.Env.Home
	apps := appDirs(home)
	trash := filepath.Join(home, ".local", "share", "Trash")
	track := func(p string, depth int) bool {
		if depth <= 2 || p == o.Downloads || p == trash {
			return true
		}
		parent := filepath.Dir(p)
		for _, a := range apps {
			if parent == a {
				return true
			}
		}
		return false
	}
	rep.Phase("measuring files", 0)
	var dirs atomic.Int64
	t := Walk(ctx, WalkOptions{Roots: o.Roots, Exclude: o.Exclude, Track: track, BigFiles: max(o.Top, 50),
		DupMin: o.DupMinMB * mb, OnDir: func() {
			if n := dirs.Add(1); n%5000 == 0 {
				progress.Status(rep, fmt.Sprintf("%d directories", n))
			}
		}})
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	d := &Data{Bytes: t.Bytes, Files: t.Files, Dirs: t.Dirs, Unreadable: t.Skipped, Trash: t.Sizes[trash], TrashPath: trash}
	for p, n := range t.Sizes {
		if p != trash && strings.Count(strings.TrimPrefix(p, home), "/") == 1 {
			d.Top = append(d.Top, File{Path: p, Bytes: n})
		}
	}
	sort.Slice(d.Top, func(i, j int) bool { return d.Top[i].Bytes > d.Top[j].Bytes })
	d.Top = d.Top[:min(len(d.Top), o.Top)]
	inRepo := repoChecker(home)
	for _, f := range t.Big {
		if f.Bytes >= o.LargeMB*mb && UserFile(f.Path) && !inRepo(f.Path) {
			d.Big = append(d.Big, f)
		}
	}
	for _, b := range t.Build {
		if b.Bytes >= o.BuildMinMB*mb && o.Now.Sub(b.ModTime) >= o.StaleAfter && !nested(b.Path, t.Build) && ProjectDir(b.Path, home) {
			d.Build = append(d.Build, b)
		}
	}
	for size, ps := range t.BySize {
		var keep []string
		for _, p := range ps {
			if UserFile(p) && !inRepo(p) {
				keep = append(keep, p)
			}
		}
		t.BySize[size] = keep
	}
	d.Empty = keep(t.Empty)
	d.Broken = keep(t.Broken)
	d.Cores = t.Cores

	var errs []string
	rep.Phase("checking caches", 0)
	d.Caches = caches(ctx, o, t)
	rep.Phase("looking for orphaned app data", 0)
	d.Orphans = orphans(ctx, o, t, apps, d.Caches)
	if o.Downloads != "" {
		d.Downloads = oldFiles(o.Downloads, o.Now, o.OldDownloads)
	}
	rep.Phase("comparing duplicate candidates", 0)
	var stopped bool
	d.Dups, stopped = duplicates(ctx, t.BySize, o.HashLimit)
	if stopped {
		errs = append(errs, fmt.Sprintf("duplicate check stopped after hashing %s (files.hash_limit)", Human(o.HashLimit)))
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	fs := Checks(d, o)
	for _, c := range d.Caches {
		if c.Bytes >= o.CacheMinMB*mb {
			d.Reclaimable += c.Bytes
		}
	}
	for _, b := range d.Build {
		d.Reclaimable += b.Bytes
	}
	for _, x := range d.Orphans {
		d.Reclaimable += x.Bytes
	}
	for _, f := range d.Downloads {
		d.Reclaimable += f.Bytes
	}
	for _, x := range d.Dups {
		d.Reclaimable += x.Bytes * int64(len(x.Paths)-1)
	}
	if d.Trash >= 1<<30 {
		d.Reclaimable += d.Trash
	}
	stats := []run.Stat{
		{Name: "scanned", Value: Human(d.Bytes), Note: fmt.Sprintf("%d files, %d dirs", d.Files, d.Dirs)},
		{Name: "reclaimable", Value: Human(d.Reclaimable)},
	}
	if d.Unreadable > 0 {
		stats = append(stats, run.Stat{Name: "unreadable dirs", Value: strconv.FormatInt(d.Unreadable, 10)})
	}
	for i, f := range d.Top {
		if i >= 8 {
			break
		}
		stats = append(stats, run.Stat{Group: "largest", Name: shortHome(f.Path, home), Value: Human(f.Bytes)})
	}
	return d, fs, stats, errs, nil
}

func shortHome(p, home string) string {
	if rest, ok := strings.CutPrefix(p, home); ok {
		return "~" + rest
	}
	return p
}

// nested reports whether p lies inside another build directory (a venv's
// __pycache__, node_modules within node_modules).
func nested(p string, all []BuildDir) bool {
	for _, b := range all {
		if b.Path != p && strings.HasPrefix(p, b.Path+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// machinery are path parts of things no person put there: version
// control internals, caches, dependency trees and build output.
var machinery = []string{"/.git/", "/objects/pack/", "/node_modules/", "/target/", "/.cache/", "/.cargo/", "/.rustup/",
	"/.npm/", "/go/pkg/", "/.local/share/", "/.local/state/", "/.venv/", "/venv/", "/site-packages/", "/.gradle/", "/.m2/",
	"/snap/", "/.codex/", "/.vscode/"}

// UserFile reports whether p is a file a person keeps (a download, media, a
// document), rather than tool machinery that must not be deleted by hand.
func UserFile(p string) bool {
	for _, m := range machinery {
		if strings.Contains(p, m) {
			return false
		}
	}
	return true
}

// repoChecker reports whether a file lies in a git working tree below home
// (its own directory or a parent holds .git); answers are cached per
// directory.
func repoChecker(home string) func(string) bool {
	cache := map[string]bool{}
	var in func(dir string) bool
	in = func(dir string) bool {
		if v, ok := cache[dir]; ok {
			return v
		}
		v := false
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			v = true
		} else if parent := filepath.Dir(dir); dir != home && parent != dir && strings.HasPrefix(parent, home) {
			v = in(parent)
		}
		cache[dir] = v
		return v
	}
	return func(p string) bool { return in(filepath.Dir(p)) }
}

// toolHomes hold tools' own installs: a node_modules or venv there is the
// tool itself (an LSP from mason, a gh extension, pdm's venv), not a
// project's rebuildable dependencies.
var toolHomes = []string{".local", ".config", ".npm", ".cargo", ".rustup", "go", ".cache", ".gradle", ".m2", ".nvm", ".pyenv", ".codex", ".vscode", "snap"}

// ProjectDir reports whether a build directory belongs to a project rather
// than a tool's installation.
func ProjectDir(p, home string) bool {
	if filepath.Dir(p) == home {
		return false
	}
	for _, t := range toolHomes {
		root := filepath.Join(home, t)
		if strings.HasPrefix(p, root+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// keep drops paths inside .git and dependency trees, where empty
// directories and dangling links are normal.
func keep(ps []string) []string {
	var out []string
	for _, p := range ps {
		if strings.Contains(p, "/.git/") || strings.Contains(p, "/node_modules/") || strings.Contains(p, "/.cache/") ||
			strings.HasSuffix(p, "/.git") {
			continue
		}
		out = append(out, p)
	}
	return out
}

func oldFiles(dir string, now time.Time, age time.Duration) []File {
	var out []File
	_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || !e.Type().IsRegular() {
			return nil
		}
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) >= age {
			out = append(out, File{Path: p, Bytes: allocated(info), ModTime: info.ModTime()})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

func hashFile(p string, partial bool) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- files under the scanned roots
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if !partial {
		n, err := io.Copy(h, f)
		return hex.EncodeToString(h.Sum(nil)), n, err
	}
	const chunk = 64 << 10
	buf := make([]byte, chunk)
	n, _ := io.ReadFull(f, buf)
	h.Write(buf[:n])
	if st, err := f.Stat(); err == nil && st.Size() > 2*chunk {
		if _, err := f.Seek(-chunk, io.SeekEnd); err == nil {
			m, _ := io.ReadFull(f, buf)
			h.Write(buf[:m])
		}
	}
	return hex.EncodeToString(h.Sum(nil)), int64(n), nil
}

// duplicates confirms same-size groups by a hash of each file's ends, then
// of the whole file, reading at most limit bytes in full hashes.
func duplicates(ctx context.Context, bySize map[int64][]string, limit int64) ([]Dup, bool) {
	sizes := make([]int64, 0, len(bySize))
	for s := range bySize {
		sizes = append(sizes, s)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] > sizes[j] })
	var out []Dup
	var read int64
	for _, size := range sizes {
		if ctx.Err() != nil {
			return out, false
		}
		byPart := map[string][]string{}
		for _, p := range bySize[size] {
			if h, _, err := hashFile(p, true); err == nil {
				byPart[h] = append(byPart[h], p)
			}
		}
		for _, ps := range byPart {
			if len(ps) < 2 {
				continue
			}
			byFull := map[string][]string{}
			for _, p := range ps {
				if read+size > limit {
					return out, true
				}
				h, n, err := hashFile(p, false)
				read += n
				if err == nil {
					byFull[h] = append(byFull[h], p)
				}
			}
			for _, same := range byFull {
				if len(same) > 1 {
					sort.Strings(same)
					out = append(out, Dup{Bytes: size, Paths: same})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Bytes*int64(len(out[i].Paths)) > out[j].Bytes*int64(len(out[j].Paths))
	})
	return out, false
}

// Normalize lowercases a name and keeps only letters and digits, so
// "Google-Chrome" and "google_chrome" compare equal.
func Normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shared are XDG children every desktop has, owned by no single program.
var shared = map[string]bool{}

func init() {
	for _, n := range []string{"applications", "icons", "fonts", "mime", "trash", "keyrings", "recentlyusedxbel", "gvfsmetadata",
		"sounds", "themes", "backgrounds", "thumbnails", "fontconfig", "meshshadercache", "mesashadercache", "nvidia",
		"glcache", "dconf", "systemd", "pulse", "pipewire", "wireplumber", "xorg", "gnomeshell", "gnomesettingsdaemon",
		"tracker3", "evolution", "flatpak", "ibus", "sessions", "desktopdirectories", "menus", "gstreamer10", "vulkan",
		"nautilus", "gtk30", "gtk40", "gtk20", "kxmlgui5", "kservices5", "xdgdesktopportal", "zeitgeist", "gegl04", "babl01",
		"man", "doc", "ubuntu", "pop", "cosmic", "lockfile", "mozilla", "recently-used", "user-places.xbel", "baloo",
		"telepathy", "akonadi", "kactivitymanagerd", "kded5", "kwalletd", "fish", "zsh", "bash", "vim", "virtualenv",
		"kioexec", "electron", "nodegyp", "typescript", "pnpm", "uv", "pip", "gobuild", "npm", "yarn", "deno", "bun"} {
		shared[Normalize(n)] = true
	}
}

// Known gathers the normalized names of installed programs: executables on
// PATH, apt packages, flatpak apps (and their last id part), snaps and
// desktop entries.
func Known(ctx context.Context, env *exec.Env) map[string]bool {
	known := map[string]bool{}
	addName := func(n string) {
		if k := Normalize(n); len(k) >= 2 {
			known[k] = true
		}
	}
	for _, d := range env.Path() {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			addName(e.Name())
		}
	}
	run := func(name string, args ...string) string {
		r := env.Run(ctx, name, args, exec.Options{Timeout: time.Minute})
		if !r.OK() {
			return ""
		}
		return r.Stdout
	}
	for _, line := range strings.Split(run("dpkg-query", "-W", "-f", "${Package}\n"), "\n") {
		addName(line)
	}
	for _, line := range strings.Split(run("flatpak", "list", "--columns=application"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			addName(line)
			addName(line[strings.LastIndexByte(line, '.')+1:])
		}
	}
	for i, line := range strings.Split(run("snap", "list"), "\n") {
		if f := strings.Fields(line); i > 0 && len(f) > 0 {
			addName(f[0])
		}
	}
	for _, d := range []string{"/usr/share/applications", filepath.Join(env.Home, ".local/share/applications"),
		"/var/lib/flatpak/exports/share/applications"} {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			name := strings.TrimSuffix(e.Name(), ".desktop")
			addName(name)
			addName(name[strings.LastIndexByte(name, '.')+1:])
		}
	}
	return known
}

// Installed reports whether an app directory's name matches a known
// program: equal names, or one containing the other when both have four or
// more characters.
func Installed(dirName string, known map[string]bool) bool {
	n := Normalize(dirName)
	if n == "" || shared[n] || known[n] {
		return true
	}
	if len(n) < 4 {
		return false
	}
	for k := range known {
		if len(k) >= 4 && (strings.Contains(k, n) || strings.Contains(n, k)) {
			return true
		}
	}
	return false
}

func orphans(ctx context.Context, o Options, t *Tree, apps []string, cs []Cache) []Orphan {
	known := Known(ctx, o.Env)
	cached := map[string]bool{}
	for _, c := range cs {
		cached[filepath.Clean(c.Path)] = true
	}
	var out []Orphan
	for p, n := range t.Sizes {
		if n < o.OrphanMinMB*mb || cached[p] {
			continue
		}
		parent := filepath.Dir(p)
		for _, a := range apps {
			if parent == a && !Installed(filepath.Base(p), known) {
				out = append(out, Orphan{Path: p, Bytes: n})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}
