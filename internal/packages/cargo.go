package packages

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Cargo collects `cargo install` crates from $CARGO_HOME/.crates2.json, so no
// subprocess runs per crate.
type Cargo struct{}

// Name implements Manager.
func (Cargo) Name() string { return "cargo" }

// Binary implements Manager.
func (Cargo) Binary() string { return "cargo" }

var (
	crateKey     = regexp.MustCompile(`^(\S+) (\S+) \((.+)\)$`)
	rustcRelease = regexp.MustCompile(`(?m)^release: (\S+)$`)
)

// describeSource shortens a cargo source id.
func describeSource(raw string) string {
	kind, rest, _ := strings.Cut(raw, "+")
	switch kind {
	case "registry", "sparse":
		if strings.Contains(rest, "crates.io") {
			return "crates.io"
		}
		return "registry:" + rest
	case "git":
		repo, _, _ := strings.Cut(rest, "#")
		return "git:" + repo
	case "path":
		return "path:" + strings.TrimPrefix(rest, "file://")
	}
	return raw
}

// parseCrates2 parses .crates2.json. Packages are sorted by name since the
// file is a JSON object.
func parseCrates2(text string) ([]Package, error) {
	var doc struct {
		Installs map[string]struct {
			Bins  []string `json:"bins"`
			Rustc string   `json:"rustc"`
		} `json:"installs"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf(".crates2.json is invalid: %w", err)
	}
	var pkgs []Package
	for key, info := range doc.Installs {
		m := crateKey.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		p := Package{
			Manager: "cargo", Name: m[1], Version: m[2], Runtime: "rust",
			Source: describeSource(m[3]), Executables: info.Bins,
		}
		if rm := rustcRelease.FindStringSubmatch(info.Rustc); rm != nil {
			p.RuntimeVersion = rm[1]
		}
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}

func (Cargo) home(env *exec.Env) string {
	if h := env.Get("CARGO_HOME"); h != "" {
		return h
	}
	return filepath.Join(env.Home, ".cargo")
}

// BinDirs implements Manager.
func (c Cargo) BinDirs(_ context.Context, env *exec.Env) []string {
	return []string{filepath.Join(c.home(env), "bin")}
}

// Runtime implements Manager.
func (Cargo) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	rustc := env.Which("rustc")
	if rustc == "" {
		return nil
	}
	rt := &Runtime{Name: "rust", Path: rustc}
	if r := env.Run(ctx, rustc, []string{"-vV"}, exec.Options{Timeout: 10 * time.Second}); r.OK() {
		if m := rustcRelease.FindStringSubmatch(r.Stdout); m != nil {
			rt.Version = m[1]
		}
	}
	return rt
}

// ManagerVersion implements Manager.
func (Cargo) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "cargo")
}

// Collect implements Manager.
func (c Cargo) Collect(_ context.Context, env *exec.Env) ([]Package, error) {
	path := filepath.Join(c.home(env), ".crates2.json")
	if !isFile(path) {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed file under CARGO_HOME
	if err != nil {
		return nil, err
	}
	pkgs, err := parseCrates2(string(data))
	if err != nil {
		return nil, err
	}
	bin := filepath.Join(c.home(env), "bin")
	for i := range pkgs {
		pkgs[i].Location = bin
	}
	return pkgs, nil
}
