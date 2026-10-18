package packages

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/njhoffman/audit/internal/exec"
)

// Uv collects `uv tool` installs: versions from `uv tool list`, sources from
// each tool's receipt and the python version from its pyvenv.cfg.
type Uv struct{}

// Name implements Manager.
func (Uv) Name() string { return "uv" }

// Binary implements Manager.
func (Uv) Binary() string { return "uv" }

var uvToolLine = regexp.MustCompile(`^(\S+) v(\S+)`)

// uvTool is one entry of `uv tool list`.
type uvTool struct {
	Name, Version string
	Executables   []string
}

// parseToolList parses `uv tool list` output.
func parseToolList(text string) []uvTool {
	var tools []uvTool
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "- ") {
			if len(tools) > 0 {
				t := &tools[len(tools)-1]
				t.Executables = append(t.Executables, strings.TrimSpace(line[2:]))
			}
			continue
		}
		if m := uvToolLine.FindStringSubmatch(line); m != nil {
			tools = append(tools, uvTool{Name: m[1], Version: m[2]})
		}
	}
	return tools
}

// parsePyvenvVersion returns version_info from a pyvenv.cfg.
func parsePyvenvVersion(text string) string {
	for _, line := range strings.Split(text, "\n") {
		key, value, _ := strings.Cut(line, "=")
		if strings.TrimSpace(key) == "version_info" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type uvReceipt struct {
	Tool struct {
		Requirements []map[string]any `toml:"requirements"`
	} `toml:"tool"`
}

// receiptSource describes where a tool's primary requirement comes from.
func receiptSource(r uvReceipt) string {
	if len(r.Tool.Requirements) == 0 {
		return "pypi"
	}
	req := r.Tool.Requirements[0]
	for _, key := range []string{"directory", "path", "editable"} {
		if v, ok := req[key]; ok {
			return fmt.Sprintf("path:%v", v)
		}
	}
	if v, ok := req["git"]; ok {
		return fmt.Sprintf("git:%v", v)
	}
	if v, ok := req["url"]; ok {
		return fmt.Sprintf("url:%v", v)
	}
	return "pypi"
}

func readReceiptSource(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path under the uv tool dir
	if err != nil {
		return "pypi"
	}
	var r uvReceipt
	if err := toml.Unmarshal(data, &r); err != nil {
		return "unknown"
	}
	return receiptSource(r)
}

func (Uv) toolDir(ctx context.Context, env *exec.Env) string {
	r := env.Run(ctx, "uv", []string{"tool", "dir"}, exec.Options{Timeout: 10 * time.Second})
	if d := strings.TrimSpace(r.Stdout); r.OK() && d != "" {
		return d
	}
	return filepath.Join(env.XDG("XDG_DATA_HOME"), "uv", "tools")
}

// BinDirs implements Manager.
func (Uv) BinDirs(ctx context.Context, env *exec.Env) []string {
	r := env.Run(ctx, "uv", []string{"tool", "dir", "--bin"}, exec.Options{Timeout: 10 * time.Second})
	if d := strings.TrimSpace(r.Stdout); r.OK() && d != "" {
		return []string{d}
	}
	return nil
}

// Runtime implements Manager. It reports the interpreter new tools get, so an
// active venv or project is ignored.
func (Uv) Runtime(ctx context.Context, env *exec.Env) *Runtime {
	r := env.Run(ctx, "uv", []string{"python", "find", "--no-project"},
		exec.Options{Timeout: 10 * time.Second, Unset: []string{"VIRTUAL_ENV"}})
	if !r.OK() {
		return nil
	}
	path := strings.TrimSpace(r.Stdout)
	rt := &Runtime{Name: "python", Path: path}
	if v := env.Run(ctx, path, []string{"--version"}, exec.Options{Timeout: 10 * time.Second}); v.OK() {
		rt.Version = FirstVersion(v.Stdout)
	}
	return rt
}

// ManagerVersion implements Manager.
func (Uv) ManagerVersion(ctx context.Context, env *exec.Env) string { return versionOf(ctx, env, "uv") }

// Collect implements Manager.
func (u Uv) Collect(ctx context.Context, env *exec.Env) ([]Package, error) {
	r := env.Run(ctx, "uv", []string{"tool", "list"}, exec.Options{})
	if !r.OK() {
		return nil, errors.New("uv tool list failed: " + strings.TrimSpace(r.Stderr))
	}
	dir := u.toolDir(ctx, env)
	var pkgs []Package
	for _, t := range parseToolList(r.Stdout) {
		envDir := filepath.Join(dir, t.Name)
		p := Package{
			Manager: "uv", Name: t.Name, Version: t.Version, Runtime: "python",
			Source: "pypi", Location: envDir, Executables: t.Executables,
		}
		if data, err := os.ReadFile(filepath.Join(envDir, "pyvenv.cfg")); err == nil { // #nosec G304
			p.RuntimeVersion = parsePyvenvVersion(string(data))
		}
		if receipt := filepath.Join(envDir, "uv-receipt.toml"); isFile(receipt) {
			p.Source = readReceiptSource(receipt)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}
