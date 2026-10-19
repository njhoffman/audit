package packages

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Manager is one package manager. Implementations only read local state.
type Manager interface {
	Name() string
	// Binary is the executable whose presence on PATH means the manager is
	// installed.
	Binary() string
	Runtime(ctx context.Context, env *exec.Env) *Runtime
	ManagerVersion(ctx context.Context, env *exec.Env) string
	// BinDirs are the directories the manager links executables into; they
	// are expected to be on PATH.
	BinDirs(ctx context.Context, env *exec.Env) []string
	Collect(ctx context.Context, env *exec.Env) ([]Package, error)
}

// Registry lists the supported managers in display order.
var Registry = []Manager{Uv{}, Pnpm{}, Cargo{}, Golang{}, Gem{}, Gh{}, Apt{}, Snap{}, Flatpak{}, Bins{}}

// Names returns the registered manager names.
func Names() []string {
	out := make([]string, len(Registry))
	for i, m := range Registry {
		out[i] = m.Name()
	}
	return out
}

// Resolve maps names to managers, keeping their order. No names selects all.
func Resolve(names []string) ([]Manager, error) {
	if len(names) == 0 {
		return append([]Manager(nil), Registry...), nil
	}
	byName := map[string]Manager{}
	for _, m := range Registry {
		byName[m.Name()] = m
	}
	var out []Manager
	var unknown []string
	for _, n := range names {
		m, ok := byName[n]
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		out = append(out, m)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown manager(s): %s (known: %s)",
			strings.Join(unknown, ", "), strings.Join(Names(), ", "))
	}
	return out, nil
}

// Collect inventories one manager. Failures are recorded in Inventory.Error
// so that one broken manager never aborts the others.
func Collect(ctx context.Context, env *exec.Env, m Manager) (inv Inventory) {
	start := time.Now()
	inv = Inventory{Manager: m.Name()}
	if m.Binary() != "" && env.Which(m.Binary()) == "" {
		return inv
	}
	inv.Available = true
	defer func() {
		if r := recover(); r != nil {
			inv.Error = fmt.Sprintf("panic: %v", r)
		}
		inv.Duration = time.Since(start)
	}()
	inv.Runtime = m.Runtime(ctx, env)
	inv.ManagerVersion = m.ManagerVersion(ctx, env)
	inv.BinDirs = m.BinDirs(ctx, env)
	pkgs, err := m.Collect(ctx, env)
	if err != nil {
		inv.Error = err.Error()
		return inv
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		return strings.ToLower(pkgs[i].Name) < strings.ToLower(pkgs[j].Name)
	})
	inv.Packages = pkgs
	return inv
}

// CollectAll inventories managers concurrently (each is mostly subprocess
// wait). onDone, when set, is called as each finishes; it may be called from
// several goroutines. Results keep the order of managers.
func CollectAll(ctx context.Context, env *exec.Env, managers []Manager, onDone func(Inventory)) []Inventory {
	out := make([]Inventory, len(managers))
	var wg sync.WaitGroup
	for i, m := range managers {
		wg.Add(1)
		go func(i int, m Manager) {
			defer wg.Done()
			out[i] = Collect(ctx, env, m)
			if onDone != nil {
				onDone(out[i])
			}
		}(i, m)
	}
	wg.Wait()
	return out
}

var versionRe = regexp.MustCompile(`\bv?(\d+(?:\.\d+)+(?:[-+.]?[0-9A-Za-z.]+)?)`)

// FirstVersion returns the first dotted version-looking token in text
// ("pnpm 12.1" gives "12.1"), or "".
func FirstVersion(text string) string {
	m := versionRe.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// versionOf runs "binary --version" and extracts the version.
func versionOf(ctx context.Context, env *exec.Env, binary string) string {
	r := env.Run(ctx, binary, []string{"--version"}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		return ""
	}
	return FirstVersion(r.Stdout)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
