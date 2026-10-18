package packages

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Golang collects `go install` binaries by reading their embedded build info
// with one `go version -m` over the bin dir.
type Golang struct{}

// Name implements Manager.
func (Golang) Name() string { return "go" }

// Binary implements Manager.
func (Golang) Binary() string { return "go" }

// parseVersionM parses `go version -m FILE...`. Each binary starts with
// "<path>: go1.x.y" followed by tab-indented path/mod lines; files without
// build info are reported on a line that does not name a go version.
func parseVersionM(text string) []Package {
	var pkgs []Package
	cur := -1
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "\t") {
			i := strings.LastIndex(line, ": ")
			if i < 0 || !strings.HasPrefix(line[i+2:], "go") {
				cur = -1
				continue
			}
			file := line[:i]
			exe := filepath.Base(file)
			pkgs = append(pkgs, Package{
				Manager: "go", Name: exe, Runtime: "go",
				RuntimeVersion: strings.TrimSpace(strings.TrimPrefix(line[i+2:], "go")),
				Location:       file, Executables: []string{exe},
			})
			cur = len(pkgs) - 1
			continue
		}
		if cur < 0 {
			continue
		}
		fields := strings.Split(strings.TrimSpace(line), "\t")
		switch {
		case fields[0] == "path" && len(fields) > 1:
			pkgs[cur].Source = fields[1]
		case fields[0] == "mod" && len(fields) > 2:
			// Name stays the executable (unique per bin dir, while one module
			// can ship several binaries); the module is what the proxy versions.
			pkgs[cur].Ident = fields[1]
			pkgs[cur].Version = fields[2]
		}
	}
	return pkgs
}

func (Golang) bin(env *exec.Env) string {
	if b := env.Get("GOBIN"); b != "" {
		return b
	}
	gopath := env.Get("GOPATH")
	if gopath == "" {
		gopath = filepath.Join(env.Home, "go")
	}
	first, _, _ := strings.Cut(gopath, string(os.PathListSeparator))
	return filepath.Join(first, "bin")
}

// BinDirs implements Manager.
func (g Golang) BinDirs(_ context.Context, env *exec.Env) []string {
	return []string{g.bin(env)}
}

// Runtime implements Manager.
func (Golang) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	r := env.Run(ctx, "go", []string{"env", "GOVERSION"}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		return nil
	}
	return &Runtime{
		Name:    "go",
		Version: strings.TrimPrefix(strings.TrimSpace(r.Stdout), "go"),
		Path:    env.Which("go"),
	}
}

// ManagerVersion implements Manager; go's version is its runtime's.
func (g Golang) ManagerVersion(ctx context.Context, env *exec.Env) string {
	if rt := g.Runtime(ctx, env); rt != nil {
		return rt.Version
	}
	return ""
}

// Collect implements Manager.
func (g Golang) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	dir := g.bin(env)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var files []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if isFile(p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	sort.Strings(files)
	// The exit status is non-zero when any file lacks build info; the output
	// for the rest is still valid, so it is parsed regardless.
	r := env.Run(ctx, "go", append([]string{"version", "-m"}, files...), exec.Options{Timeout: time.Minute})
	return parseVersionM(r.Stdout), nil
}
