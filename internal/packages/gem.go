package packages

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Gem collects user-installed gems (`gem install --user-install`) from their
// gemspecs. System gems belong to the distro and are out of scope.
// Dependencies are listed too; gems that ship executables are in practice the
// ones installed on purpose.
type Gem struct{}

// Name implements Manager.
func (Gem) Name() string { return "gem" }

// Binary implements Manager.
func (Gem) Binary() string { return "gem" }

var (
	gemSpecName    = regexp.MustCompile(`^(.+?)-(\d[^-]*)(?:-(.+))?\.gemspec$`)
	gemExecutables = regexp.MustCompile(`\.executables\s*=\s*\[([^\]]*)\]`)
	gemQuoted      = regexp.MustCompile(`"([^"]+)"`)
)

// parseSpecFilename splits "name-version[-platform].gemspec".
func parseSpecFilename(filename string) (name, version string, ok bool) {
	m := gemSpecName.FindStringSubmatch(filename)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// parseExecutables returns the executables a gemspec declares.
func parseExecutables(spec string) []string {
	m := gemExecutables.FindStringSubmatch(spec)
	if m == nil {
		return nil
	}
	var out []string
	for _, q := range gemQuoted.FindAllStringSubmatch(m[1], -1) {
		out = append(out, q[1])
	}
	return out
}

// versionLess compares dotted versions numerically; non-numeric parts sort
// before any number.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := versionPart(pa[i]), versionPart(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return len(pa) < len(pb)
}

func versionPart(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

func (Gem) userDir(ctx context.Context, env *exec.Env) string {
	r := env.Run(ctx, "ruby", []string{"-e", "print Gem.user_dir"}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		return ""
	}
	return strings.TrimSpace(r.Stdout)
}

// BinDirs implements Manager.
func (g Gem) BinDirs(ctx context.Context, env *exec.Env) []string {
	if d := g.userDir(ctx, env); d != "" {
		return []string{filepath.Join(d, "bin")}
	}
	return nil
}

// Runtime implements Manager.
func (Gem) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	r := env.Run(ctx, "ruby", []string{"--version"}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		return nil
	}
	return &Runtime{Name: "ruby", Version: FirstVersion(r.Stdout), Path: env.Which("ruby")}
}

// ManagerVersion implements Manager.
func (Gem) ManagerVersion(ctx context.Context, env *exec.Env) string {
	return versionOf(ctx, env, "gem")
}

// Collect implements Manager. When several versions of a gem coexist only
// the newest is reported.
func (g Gem) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	user := g.userDir(ctx, env)
	if user == "" {
		return nil, nil
	}
	specs, err := filepath.Glob(filepath.Join(user, "specifications", "*.gemspec"))
	if err != nil || len(specs) == 0 {
		return nil, nil
	}
	var rubyVersion string
	if rt := g.Runtime(ctx, env); rt != nil {
		rubyVersion = rt.Version
	}
	newest := map[string]Package{}
	for _, spec := range specs {
		name, version, ok := parseSpecFilename(filepath.Base(spec))
		if !ok {
			continue
		}
		if prev, seen := newest[name]; seen && !versionLess(prev.Version, version) {
			continue
		}
		var exes []string
		if data, err := os.ReadFile(spec); err == nil { // #nosec G304 -- gemspec under the gem user dir
			exes = parseExecutables(string(data))
		}
		newest[name] = Package{
			Manager: "gem", Name: name, Version: version, Runtime: "ruby",
			RuntimeVersion: rubyVersion, Source: "rubygems",
			Location: filepath.Join(user, "gems", name+"-"+version), Executables: exes,
		}
	}
	out := make([]Package, 0, len(newest))
	for _, p := range newest {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
