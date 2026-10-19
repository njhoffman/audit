package files

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

// SizeOf is the allocated size of everything under p (0 when unreadable).
func SizeOf(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, e fs.DirEntry, err error) error {
		if err == nil {
			if info, err := e.Info(); err == nil {
				n += allocated(info)
			}
		}
		return nil
	})
	return n
}

var journalRe = regexp.MustCompile(`take up ([0-9.]+)([KMGT])`)

// toolCaches are caches a tool clears itself: how to find the directory,
// and the command that clears it.
type toolCache struct {
	name    string
	binary  string
	dir     func(ctx context.Context, env *exec.Env) string
	command []string
}

func cmdDir(name string, args ...string) func(context.Context, *exec.Env) string {
	return func(ctx context.Context, env *exec.Env) string {
		r := env.Run(ctx, name, args, exec.Options{Timeout: 20 * time.Second})
		if !r.OK() {
			return ""
		}
		return strings.TrimSpace(r.Stdout)
	}
}

func homeDir(rel string) func(context.Context, *exec.Env) string {
	return func(_ context.Context, env *exec.Env) string { return filepath.Join(env.Home, rel) }
}

var toolCaches = []toolCache{
	{"uv", "uv", cmdDir("uv", "cache", "dir"), []string{"uv", "cache", "clean"}},
	{"pip", "pip", homeDir(".cache/pip"), []string{"pip", "cache", "purge"}},
	{"go build", "go", cmdDir("go", "env", "GOCACHE"), []string{"go", "clean", "-cache"}},
	{"go modules", "go", cmdDir("go", "env", "GOMODCACHE"), []string{"go", "clean", "-modcache"}},
	{"pnpm store", "pnpm", cmdDir("pnpm", "store", "path"), []string{"pnpm", "store", "prune"}},
	{"npm", "npm", homeDir(".npm/_cacache"), []string{"npm", "cache", "clean", "--force"}},
	{"yarn", "yarn", cmdDir("yarn", "cache", "dir"), []string{"yarn", "cache", "clean"}},
	{"cargo registry", "cargo", homeDir(".cargo/registry/cache"), nil},
	{"thumbnails", "", homeDir(".cache/thumbnails"), nil},
}

// caches sizes the tool caches, the system caches (apt archives, the
// journal, disabled snap revisions) and the other large children of
// ~/.cache.
func caches(ctx context.Context, o Options, t *Tree) []Cache {
	env := o.Env
	var out []Cache
	covered := map[string]bool{}
	size := func(p string) int64 {
		if n, ok := t.Sizes[p]; ok {
			return n
		}
		return SizeOf(p)
	}
	for _, tc := range toolCaches {
		if tc.binary != "" && env.Which(tc.binary) == "" {
			continue
		}
		p := tc.dir(ctx, env)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		covered[filepath.Clean(p)] = true
		out = append(out, Cache{Name: tc.name, Path: p, Bytes: size(p), Command: tc.command})
	}
	if _, err := os.Stat("/var/cache/apt/archives"); err == nil {
		out = append(out, Cache{Name: "apt archives", Path: "/var/cache/apt/archives", Bytes: SizeOf("/var/cache/apt/archives"),
			Command: []string{"apt-get", "clean"}, Root: true})
	}
	if env.Which("journalctl") != "" {
		r := env.Run(ctx, "journalctl", []string{"--disk-usage"}, exec.Options{Timeout: 20 * time.Second})
		if m := journalRe.FindStringSubmatch(r.Stdout + r.Stderr); m != nil {
			v, _ := strconv.ParseFloat(m[1], 64)
			mult := map[string]float64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m[2]]
			out = append(out, Cache{Name: "systemd journal", Bytes: int64(v * mult),
				Command: []string{"journalctl", "--vacuum-size=500M"}, Root: true})
		}
	}
	if env.Which("snap") != "" {
		r := env.Run(ctx, "snap", []string{"list", "--all"}, exec.Options{Timeout: 30 * time.Second})
		for i, line := range strings.Split(r.Stdout, "\n") {
			f := strings.Fields(line)
			if i == 0 || len(f) < 3 || !strings.Contains(line, "disabled") {
				continue
			}
			file := fmt.Sprintf("/var/lib/snapd/snaps/%s_%s.snap", f[0], f[2])
			var n int64
			if info, err := os.Stat(file); err == nil {
				n = allocated(info)
			}
			out = append(out, Cache{Name: fmt.Sprintf("snap %s revision %s (disabled)", f[0], f[2]), Path: file, Bytes: n,
				Command: []string{"snap", "remove", f[0], "--revision=" + f[2]}, Root: true})
		}
	}
	if env.Which("docker") != "" {
		r := env.Run(ctx, "docker", []string{"system", "df", "--format", "{{json .}}"}, exec.Options{Timeout: 30 * time.Second})
		var total int64
		for _, line := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
			var row struct {
				Reclaimable string `json:"Reclaimable"`
			}
			if json.Unmarshal([]byte(line), &row) == nil {
				total += parseDockerSize(row.Reclaimable)
			}
		}
		if r.OK() && total > 0 {
			out = append(out, Cache{Name: "docker (unused images, containers, build cache)", Bytes: total,
				Command: []string{"docker", "system", "prune", "-f"}})
		}
	}
	cacheDir := filepath.Join(env.Home, ".cache")
	for p, n := range t.Sizes {
		if filepath.Dir(p) != cacheDir || covered[p] || n < o.CacheMinMB*mb {
			continue
		}
		skip := false
		for c := range covered {
			if strings.HasPrefix(c, p+string(filepath.Separator)) {
				skip = true
			}
		}
		if !skip {
			out = append(out, Cache{Name: "~/.cache/" + filepath.Base(p), Path: p, Bytes: n})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

var dockerSizeRe = regexp.MustCompile(`^([0-9.]+)\s*([kKMGT]?B)`)

func parseDockerSize(s string) int64 {
	m := dockerSizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	mult := map[string]float64{"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m[2]]
	return int64(v * mult)
}

func group(id, title, hint string) *finding.Group {
	return &finding.Group{ID: id, Title: title, Hint: hint}
}

func f(check string, sev finding.Severity, subject, msg string, details []string, g *finding.Group) finding.Finding {
	return finding.Finding{Command: Command, Check: "files." + check, Kind: finding.Issue, Severity: sev, Subject: subject,
		Message: msg, Details: details, Group: g}
}

// Checks turns a files run's data into findings.
func Checks(d *Data, o Options) []finding.Finding {
	var out []finding.Finding
	home := o.Env.Home
	clean := "audit files clean"
	for _, c := range d.Caches {
		if c.Bytes < o.CacheMinMB*mb {
			continue
		}
		subject := c.Path
		if subject == "" {
			subject = c.Name
		}
		out = append(out, f("cache", finding.Info, subject, fmt.Sprintf("%s cache takes %s", c.Name, Human(c.Bytes)), nil,
			group("cache", "Clear large caches", clean)))
	}
	for _, b := range d.Build {
		out = append(out, f("build", finding.Info, b.Path, fmt.Sprintf("%s (%s, %s) unchanged since %s", shortHome(b.Path, home), b.Kind,
			Human(b.Bytes), b.ModTime.Format(time.DateOnly)), nil,
			group("build", "Remove build and dependency directories of idle projects", clean+"; they are rebuilt on demand")))
	}
	for _, x := range d.Orphans {
		out = append(out, f("orphaned", finding.Info, x.Path, fmt.Sprintf("%s (%s) matches no installed program", shortHome(x.Path, home),
			Human(x.Bytes)), nil, group("orphaned", "Review data of programs that look uninstalled",
			"check each before removing it with "+clean+"; ignore files.orphaned:PATH for false matches")))
	}
	for _, b := range d.Big {
		out = append(out, f("large", finding.Info, b.Path, fmt.Sprintf("%s is %s (last changed %s)", shortHome(b.Path, home), Human(b.Bytes),
			b.ModTime.Format(time.DateOnly)), nil, group("large", "Review the largest files", "delete or move them off this disk")))
	}
	if n := sum(d.Downloads); n > 0 && n >= o.DownloadsMinMB*mb {
		var details []string
		for i, x := range d.Downloads {
			if i == 10 {
				details = append(details, fmt.Sprintf("(%d more)", len(d.Downloads)-10))
				break
			}
			details = append(details, fmt.Sprintf("%s  %s  %s", Human(x.Bytes), x.ModTime.Format(time.DateOnly), shortHome(x.Path, home)))
		}
		out = append(out, f("downloads", finding.Notice, o.Downloads, fmt.Sprintf("%d download(s) older than %s take %s",
			len(d.Downloads), ageWords(o.OldDownloads), Human(n)), details, nil))
	}
	if d.Trash >= 1<<30 {
		out = append(out, f("trash", finding.Notice, d.TrashPath, "the trash holds "+Human(d.Trash), nil, nil))
	}
	for _, x := range d.Dups {
		out = append(out, f("duplicates", finding.Info, x.Paths[0], fmt.Sprintf("%d identical copies of %s (%s wasted)", len(x.Paths),
			Human(x.Bytes), Human(x.Bytes*int64(len(x.Paths)-1))), shortAll(x.Paths, home), group("duplicates", "Remove duplicate files", clean)))
	}
	if len(d.Empty) >= 20 {
		out = append(out, f("empty_dirs", finding.Info, "empty", fmt.Sprintf("%d empty directories", len(d.Empty)), first(shortAll(d.Empty, home), 20), nil))
	}
	if len(d.Broken) > 0 {
		out = append(out, f("broken_links", finding.Info, "broken", fmt.Sprintf("%d symlink(s) point at nothing", len(d.Broken)), first(shortAll(d.Broken, home), 30), nil))
	}
	for _, c := range d.Cores {
		out = append(out, f("core_dumps", finding.Notice, c.Path, fmt.Sprintf("core dump %s (%s)", shortHome(c.Path, home), Human(c.Bytes)), nil,
			group("core_dumps", "Delete old core dumps", clean)))
	}
	finding.Sort(out)
	return out
}

func sum(fs []File) int64 {
	var n int64
	for _, f := range fs {
		n += f.Bytes
	}
	return n
}

func shortAll(ps []string, home string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = shortHome(p, home)
	}
	return out
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("(%d more)", len(s)-n))
	}
	return s
}

func ageWords(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days%30 == 0 && days >= 30 {
		return fmt.Sprintf("%d months", days/30)
	}
	return fmt.Sprintf("%d days", days)
}
