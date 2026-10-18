package packages

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Gh collects gh CLI extensions via `gh extension list`.
type Gh struct{}

// Name implements Manager.
func (Gh) Name() string { return "gh" }

// Binary implements Manager.
func (Gh) Binary() string { return "gh" }

// parseExtensionList parses tab-separated `gh extension list` output:
// "gh NAME", OWNER/REPO, VERSION.
func parseExtensionList(text string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "gh ") {
			continue
		}
		command := strings.TrimSpace(strings.TrimPrefix(fields[0], "gh "))
		repo := strings.TrimSpace(fields[1])
		p := Package{
			Manager: "gh", Name: command, Runtime: "gh", Source: "github:" + repo,
			Ident: repo, Executables: []string{"gh " + command},
		}
		if len(fields) > 2 {
			p.Version = strings.TrimSpace(fields[2])
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// BinDirs implements Manager; extensions live inside gh, not on PATH.
func (Gh) BinDirs(context.Context, *exec.Env) []string { return nil }

// Runtime implements Manager.
func (Gh) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	r := env.Run(ctx, "gh", []string{"--version"}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		return nil
	}
	return &Runtime{Name: "gh", Version: FirstVersion(r.Stdout), Path: env.Which("gh")}
}

// ManagerVersion implements Manager.
func (Gh) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "gh")
}

// Collect implements Manager.
func (g Gh) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	r := env.Run(ctx, "gh", []string{"extension", "list"}, exec.Options{})
	if !r.OK() {
		return nil, errors.New("gh extension list failed: " + truncate(r.Stderr, 300))
	}
	pkgs := parseExtensionList(r.Stdout)
	if rt := g.Runtime(ctx, env); rt != nil {
		for i := range pkgs {
			pkgs[i].RuntimeVersion = rt.Version
		}
	}
	return pkgs, nil
}
