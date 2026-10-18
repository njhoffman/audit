package packages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Pnpm collects pnpm globals via `pnpm ls -g --json`, with executables read
// from each package.json.
type Pnpm struct{}

// Name implements Manager.
func (Pnpm) Name() string { return "pnpm" }

// Binary implements Manager.
func (Pnpm) Binary() string { return "pnpm" }

// packageBins returns the executable names a package.json bin field declares.
func packageBins(name string, manifest map[string]any) []string {
	switch b := manifest["bin"].(type) {
	case string:
		return []string{name[strings.LastIndex(name, "/")+1:]}
	case map[string]any:
		out := make([]string, 0, len(b))
		for k := range b {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// pnpmDep is one entry of `pnpm ls -g --json --depth 0`.
type pnpmDep struct {
	Name, Version, Path string
}

// parseLs parses `pnpm ls -g --json --depth 0`, which is a list of roots or a
// single root object.
func parseLs(text string) ([]pnpmDep, error) {
	type dep struct {
		Version string `json:"version"`
		Path    string `json:"path"`
	}
	type root struct {
		Dependencies map[string]dep `json:"dependencies"`
	}
	var roots []root
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		var r root
		if err := json.Unmarshal([]byte(trimmed), &r); err != nil {
			return nil, fmt.Errorf("pnpm ls returned invalid JSON: %w", err)
		}
		roots = []root{r}
	} else if err := json.Unmarshal([]byte(trimmed), &roots); err != nil {
		return nil, fmt.Errorf("pnpm ls returned invalid JSON: %w", err)
	}
	var out []pnpmDep
	for _, r := range roots {
		names := make([]string, 0, len(r.Dependencies))
		for n := range r.Dependencies {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			d := r.Dependencies[n]
			out = append(out, pnpmDep{Name: n, Version: d.Version, Path: d.Path})
		}
	}
	return out, nil
}

// sourceFromVersion maps link:/file: versions to a path source.
func sourceFromVersion(version string) string {
	if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "file:") {
		_, rest, _ := strings.Cut(version, ":")
		return "path:" + rest
	}
	return "npm"
}

// BinDirs implements Manager.
func (Pnpm) BinDirs(ctx context.Context, env *exec.Env) []string {
	r := env.Run(ctx, "pnpm", []string{"bin", "-g"}, exec.Options{Timeout: 15 * time.Second})
	if out := strings.TrimSpace(r.Stdout); r.OK() && out != "" {
		lines := strings.Split(out, "\n")
		return []string{strings.TrimSpace(lines[len(lines)-1])}
	}
	if home := env.Get("PNPM_HOME"); home != "" {
		return []string{filepath.Join(home, "bin")}
	}
	return nil
}

// Runtime implements Manager.
func (Pnpm) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	node := env.Which("node")
	if node == "" {
		return nil
	}
	return &Runtime{Name: "node", Version: versionOf(ctx, env, node), Path: node}
}

// ManagerVersion implements Manager.
func (Pnpm) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "pnpm")
}

// Collect implements Manager.
func (p Pnpm) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	r := env.Run(ctx, "pnpm", []string{"ls", "-g", "--json", "--depth", "0"}, exec.Options{Timeout: time.Minute})
	if !r.OK() {
		return nil, errors.New("pnpm ls -g failed: " + truncate(r.Stderr, 300))
	}
	deps, err := parseLs(r.Stdout)
	if err != nil {
		return nil, err
	}
	var nodeVersion string
	if rt := p.Runtime(ctx, env); rt != nil {
		nodeVersion = rt.Version
	}
	pkgs := make([]Package, 0, len(deps))
	for _, d := range deps {
		var exes []string
		if d.Path != "" {
			if data, err := os.ReadFile(filepath.Join(d.Path, "package.json")); err == nil { // #nosec G304
				var manifest map[string]any
				if json.Unmarshal(data, &manifest) == nil {
					exes = packageBins(d.Name, manifest)
				}
			}
		}
		pkgs = append(pkgs, Package{
			Manager: "pnpm", Name: d.Name, Version: d.Version, Runtime: "node",
			RuntimeVersion: nodeVersion, Source: sourceFromVersion(d.Version),
			Location: d.Path, Executables: exes,
		})
	}
	return pkgs, nil
}
