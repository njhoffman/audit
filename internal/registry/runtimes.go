package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// RuntimeLooker finds a runtime's releases. *Client implements it.
type RuntimeLooker interface {
	LookupRuntime(ctx context.Context, name string) (packages.RuntimeMeta, error)
}

// rustupUpdates is rustup check's exit status when an update is available.
const rustupUpdates = 100

// LookupRuntime finds the releases of a runtime: python from uv's download
// list (no network), node and go from their release indexes, rust from
// `rustup check`. Ruby comes from the system package manager and has no
// lookup.
func (c *Client) LookupRuntime(ctx context.Context, name string) (packages.RuntimeMeta, error) {
	m := packages.RuntimeMeta{Name: name}
	var err error
	switch name {
	case packages.RuntimePython:
		err = c.python(ctx, &m)
	case packages.RuntimeNode:
		var body []byte
		if body, err = c.get(ctx, c.Base.Node); err == nil {
			m.Lines, m.Newest, err = packages.ParseNodeIndex(body)
		}
	case packages.RuntimeGo:
		var body []byte
		if body, err = c.get(ctx, c.Base.GoDL); err == nil {
			m.Lines, m.Newest, err = packages.ParseGoReleases(body)
		}
	case packages.RuntimeRust:
		r := c.Env.Run(ctx, "rustup", []string{"check"}, exec.Options{Timeout: c.Timeout})
		switch {
		case r.Code == exec.ExitNotFound:
			err = errors.New("rustup not found")
		case !r.OK() && r.Code != rustupUpdates:
			err = fmt.Errorf("rustup check exited %d: %s", r.Code, firstLine(r.Stderr))
		default:
			m.Toolchains = packages.ParseRustupCheck(r.Stdout)
			m.Lines = map[string]string{}
			for _, tc := range m.Toolchains {
				m.Lines[tc.Name] = tc.Installed
				if tc.Latest != "" {
					m.Lines[tc.Name] = tc.Latest
				}
			}
		}
	default:
		err = fmt.Errorf("no release lookup for %s", name)
	}
	return m, err
}

func (c *Client) python(ctx context.Context, m *packages.RuntimeMeta) error {
	opts := exec.Options{Timeout: c.Timeout, Unset: []string{"VIRTUAL_ENV"}}
	if r := c.Env.Run(ctx, "uv", []string{"python", "dir"}, opts); r.OK() {
		m.PythonDir = strings.TrimSpace(r.Stdout)
	}
	r := c.Env.Run(ctx, "uv", []string{"python", "list", "--output-format", "json"}, opts)
	if !r.OK() {
		return fmt.Errorf("uv python list exited %d: %s", r.Code, firstLine(r.Stderr))
	}
	lines, installs, err := packages.ParseUvPythonList(r.Stdout, m.PythonDir, c.Env.Home)
	if err != nil {
		return err
	}
	m.Lines, m.Installs = lines, installs
	newest := ""
	for _, v := range lines {
		if c, ok := packages.CompareVersions("", v, newest); newest == "" || ok && c > 0 {
			newest = v
		}
	}
	m.Newest = newest
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}

// RefreshRuntimes looks up the named runtimes whose cache entry is older
// than maxAge (all of them with force) and returns the new entries. A failed
// lookup keeps the previous answer with the error noted. Python is always
// looked up: it reads only uv's local list, and the installed interpreters
// it reports must be current.
func RefreshRuntimes(ctx context.Context, l RuntimeLooker, names []string, cache map[string]packages.RuntimeMeta,
	maxAge time.Duration, force bool, now time.Time, onDone func(string)) []packages.RuntimeMeta {
	var out []packages.RuntimeMeta
	for _, name := range names {
		if name == packages.RuntimeRuby {
			continue
		}
		prev, ok := cache[name]
		if ok && !force && name != packages.RuntimePython && prev.Error == "" && now.Sub(prev.CheckedAt) < maxAge {
			continue
		}
		if ctx.Err() != nil {
			return out
		}
		m, err := l.LookupRuntime(ctx, name)
		if ctx.Err() != nil {
			return out
		}
		m.CheckedAt = now
		if err != nil {
			if ok {
				prev.Error, prev.CheckedAt = err.Error(), now
				m = prev
			} else {
				m.Error = err.Error()
			}
		}
		out = append(out, m)
		if onDone != nil {
			onDone(name)
		}
	}
	return out
}
