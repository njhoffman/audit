// Package files measures where disk space goes under the configured roots
// and finds space that can be reclaimed: caches, stale build directories,
// data of programs no longer installed, large and old files, duplicates,
// empty directories and broken links.
package files

import (
	"container/heap"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Command is the audit subcommand name.
const Command = "files"

// File is one file with its allocated size.
type File struct {
	Path    string    `json:"path"`
	Bytes   int64     `json:"bytes"`
	ModTime time.Time `json:"mod_time,omitzero"`
}

// BuildDir is a dependency or build output directory inside a project.
type BuildDir struct {
	Path    string    `json:"path"`
	Kind    string    `json:"kind"`
	Bytes   int64     `json:"bytes"`
	ModTime time.Time `json:"mod_time"`
}

// WalkOptions control Walk.
type WalkOptions struct {
	Roots []string
	// Exclude are directories not descended into (prefix match).
	Exclude []string
	// Track reports whether a directory's total size is kept; depth counts
	// from its root (0).
	Track func(path string, depth int) bool
	// BigFiles is how many of the largest files are kept.
	BigFiles int
	// DupMin is the smallest file size grouped for duplicate detection.
	DupMin int64
	// Workers bounds concurrent directory reads; 0 uses twice the CPUs.
	Workers int
	// OnDir is called for each directory read (progress).
	OnDir func()
}

// Tree is what Walk found.
type Tree struct {
	Bytes int64            `json:"bytes"`
	Files int64            `json:"files"`
	Dirs  int64            `json:"dirs"`
	Sizes map[string]int64 `json:"sizes"`
	Big   []File           `json:"big"`
	// BySize groups files of DupMin bytes or more by size; only groups of
	// two or more are kept.
	BySize  map[int64][]string `json:"-"`
	Build   []BuildDir         `json:"build,omitempty"`
	Empty   []string           `json:"empty,omitempty"`
	Broken  []string           `json:"broken,omitempty"`
	Cores   []File             `json:"cores,omitempty"`
	Skipped int64              `json:"skipped,omitempty"`
}

// buildMarkers name build directories and the sibling file that proves the
// parent is a project of that kind ("" when the directory is proof itself).
var buildMarkers = map[string][2]string{
	"node_modules": {"node", "package.json"},
	"target":       {"rust", "Cargo.toml"},
	".venv":        {"python", ""},
	"venv":         {"python", ""},
	".tox":         {"python", "tox.ini"},
	".gradle":      {"gradle", ""},
	".next":        {"node", "package.json"},
	"__pycache__":  {"", ""},
}

func isBuildDir(path, name string) (string, bool) {
	m, ok := buildMarkers[name]
	if !ok || m[0] == "" {
		return "", false
	}
	switch {
	case name == ".venv" || name == "venv":
		if _, err := os.Stat(filepath.Join(path, "pyvenv.cfg")); err != nil {
			return "", false
		}
	case m[1] != "":
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), m[1])); err != nil {
			return "", false
		}
	}
	return m[0], true
}

var coreRe = func(name string) bool {
	if name == "core" {
		return true
	}
	rest, ok := strings.CutPrefix(name, "core.")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type fileHeap []File

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Bytes < h[j].Bytes }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(File)) }
func (h *fileHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type walker struct {
	o   WalkOptions
	sem chan struct{}
	mu  sync.Mutex
	t   *Tree
	big fileHeap
	// minBig is the smallest kept big file once the heap is full, read
	// without the lock to skip most files cheaply.
	minBig atomic.Int64

	files, dirs, skipped atomic.Int64
}

func allocated(info fs.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return info.Size()
}

func device(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Dev
	}
	return 0
}

// Walk measures the roots in parallel, staying on each root's filesystem.
// Directory sizes are allocated blocks, like du.
func Walk(ctx context.Context, o WalkOptions) *Tree {
	if o.Workers <= 0 {
		o.Workers = 2 * runtime.NumCPU()
	}
	w := &walker{o: o, sem: make(chan struct{}, o.Workers),
		t: &Tree{Sizes: map[string]int64{}, BySize: map[int64][]string{}}}
	seen := map[string]bool{}
	for _, root := range o.Roots {
		root = filepath.Clean(root)
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || seen[root] {
			continue
		}
		seen[root] = true
		w.t.Bytes += w.dir(ctx, root, 0, device(info), info)
	}
	sort.Slice(w.big, func(i, j int) bool { return w.big[i].Bytes > w.big[j].Bytes })
	w.t.Big = w.big
	for size, ps := range w.t.BySize {
		if len(ps) < 2 {
			delete(w.t.BySize, size)
		}
	}
	sort.Strings(w.t.Empty)
	sort.Strings(w.t.Broken)
	sort.Slice(w.t.Build, func(i, j int) bool { return w.t.Build[i].Bytes > w.t.Build[j].Bytes })
	w.t.Files, w.t.Dirs, w.t.Skipped = w.files.Load(), w.dirs.Load(), w.skipped.Load()
	return w.t
}

func (w *walker) excluded(p string) bool {
	for _, e := range w.o.Exclude {
		if p == e || strings.HasPrefix(p, e+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// dir returns the allocated size of path and everything below it.
func (w *walker) dir(ctx context.Context, path string, depth int, dev uint64, self fs.FileInfo) int64 {
	if ctx.Err() != nil {
		return 0
	}
	w.dirs.Add(1)
	if w.o.OnDir != nil {
		w.o.OnDir()
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		w.skipped.Add(1)
		return allocated(self)
	}
	total := allocated(self)
	name := filepath.Base(path)
	if kind, ok := isBuildDir(path, name); ok {
		defer func() {
			w.mu.Lock()
			w.t.Build = append(w.t.Build, BuildDir{Path: path, Kind: kind, Bytes: total, ModTime: self.ModTime()})
			w.mu.Unlock()
		}()
	}
	if len(entries) == 0 && name != ".git" {
		w.mu.Lock()
		w.t.Empty = append(w.t.Empty, path)
		w.mu.Unlock()
	}
	var wg sync.WaitGroup
	var sub atomic.Int64
	for _, e := range entries {
		p := filepath.Join(path, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			if _, err := os.Stat(p); err != nil {
				w.mu.Lock()
				w.t.Broken = append(w.t.Broken, p)
				w.mu.Unlock()
			}
			total += allocated(info)
		case e.IsDir():
			if w.excluded(p) || device(info) != dev {
				continue
			}
			select {
			case w.sem <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-w.sem }()
					sub.Add(w.dir(ctx, p, depth+1, dev, info))
				}()
			default:
				sub.Add(w.dir(ctx, p, depth+1, dev, info))
			}
		case info.Mode().IsRegular():
			w.files.Add(1)
			size := allocated(info)
			total += size
			w.file(File{Path: p, Bytes: size, ModTime: info.ModTime()}, e.Name())
		}
	}
	wg.Wait()
	total += sub.Load()
	if w.o.Track != nil && w.o.Track(path, depth) {
		w.mu.Lock()
		w.t.Sizes[path] = total
		w.mu.Unlock()
	}
	return total
}

func (w *walker) file(f File, name string) {
	core := coreRe(name) && f.Bytes > 1<<20
	if !core && (f.Bytes < w.o.DupMin || w.o.DupMin <= 0) && (w.o.BigFiles == 0 || f.Bytes <= w.minBig.Load()) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if core {
		w.t.Cores = append(w.t.Cores, f)
	}
	if w.o.DupMin > 0 && f.Bytes >= w.o.DupMin {
		w.t.BySize[f.Bytes] = append(w.t.BySize[f.Bytes], f.Path)
	}
	if w.o.BigFiles > 0 {
		if len(w.big) < w.o.BigFiles {
			heap.Push(&w.big, f)
		} else if f.Bytes > w.big[0].Bytes {
			w.big[0] = f
			heap.Fix(&w.big, 0)
		}
		if len(w.big) == w.o.BigFiles {
			w.minBig.Store(w.big[0].Bytes)
		}
	}
}
