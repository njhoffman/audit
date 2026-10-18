package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

var ctx = context.Background()

// Response bodies trimmed from the real registries.
var routes = map[string]string{
	"/pypi/ruff/json": `{"info":{"version":"0.9.2","summary":"An extremely fast Python linter.","home_page":"",
		"license":null,"license_expression":"MIT","keywords":"lint, python","classifiers":["Programming Language :: Rust"],
		"project_urls":{"Homepage":"https://docs.astral.sh/ruff","Source":"https://github.com/astral-sh/ruff"}},
		"releases":{"0.9.2":[{"upload_time_iso_8601":"2026-09-02T10:00:00.000000Z","yanked":false},
		{"upload_time_iso_8601":"2026-09-01T10:00:00.000000Z","yanked":false}],
		"0.9.0":[{"upload_time_iso_8601":"2026-08-01T10:00:00Z","yanked":true},{"upload_time_iso_8601":"2026-08-01T10:00:00Z","yanked":true}]}}`,
	"/pypi/old/json": `{"info":{"version":"1.0","summary":"old\n thing","license":"` + strings.Repeat("x", 200) + `",
		"classifiers":["Development Status :: 7 - Inactive"],"project_urls":{"Tracker":"https://gitlab.com/o/old/-/issues"}},
		"releases":{"1.0":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z","yanked":false}]}}`,
	"/npm/@biomejs%2Fbiome/latest": `{"version":"2.1.0","description":"Biome toolchain","homepage":"https://biomejs.dev",
		"repository":{"type":"git","url":"git+https://github.com/biomejs/biome.git","directory":"packages/@biomejs/biome"},
		"license":"MIT OR Apache-2.0","keywords":["format","lint"]}`,
	"/npm/@biomejs%2Fbiome": `{"time":{"2.0.0":"2026-06-01T00:00:00.000Z","2.1.0":"2026-07-01T12:00:00.000Z"}}`,
	"/npm/left-pad/latest":  `{"version":"1.3.0","repository":"stevemao/left-pad","license":{"type":"WTFPL"},"deprecated":"use String.prototype.padStart()"}`,
	"/index/ri/pg/ripgrep":  `{"name":"ripgrep","vers":"14.1.0","yanked":false}` + "\n" + `{"name":"ripgrep","vers":"14.1.1","yanked":false}` + "\n" + `{"name":"ripgrep","vers":"15.0.0-rc.1","yanked":false}` + "\n" + `{"name":"ripgrep","vers":"14.1.2","yanked":true}` + "\n",
	"/crates/api/v1/crates/ripgrep": `{"crate":{"description":"ripgrep is a line-oriented search tool","homepage":"https://github.com/BurntSushi/ripgrep",
		"repository":"https://github.com/BurntSushi/ripgrep","keywords":["regex","grep"]},
		"versions":[{"num":"14.1.1","created_at":"2024-09-08T22:24:21.000000+00:00","license":"Unlicense OR MIT"}]}`,
	"/goproxy/github.com/!burnt!sushi/toml/@latest": `{"Version":"v1.5.0","Time":"2025-03-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://github.com/BurntSushi/toml"}}`,
	"/node/index.json": `[{"version":"v26.12.0","lts":false},{"version":"v24.22.0","lts":"Krypton"},{"version":"v24.21.0","lts":"Krypton"}]`,
	"/go/dl":           `[{"version":"go1.27.2","stable":true},{"version":"go1.26.9","stable":true}]`,
	"/gems/api/v1/gems/rake.json": `{"version":"13.3.0","version_created_at":"2025-05-01T00:00:00.000Z","info":"Make-like program",
		"homepage_uri":"https://github.com/ruby/rake","source_code_uri":"","licenses":["MIT"]}`,
}

func newClient(t *testing.T) (*Client, *exec.Fake, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.UserAgent() != "audit/test" {
			http.Error(w, "no user agent", http.StatusForbidden)
			return
		}
		if r.URL.EscapedPath() == "/pypi/boom/json" {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		body, ok := routes[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	fake := &exec.Fake{}
	fake.AddOutput(`{"description":"A dashboard","homepage":"","html_url":"https://github.com/dlvhdr/gh-dash",
		"license":{"spdx_id":"MIT"},"topics":["gh-extension","tui"],"archived":false}`, "gh", "api", "repos/dlvhdr/gh-dash")
	fake.AddOutput(`{"tag_name":"v4.7.0","published_at":"2026-09-20T00:00:00Z"}`, "gh", "api", "repos/dlvhdr/gh-dash/releases/latest")
	fake.Add([]string{"gh", "api", "repos/me/gh-script/releases/latest"},
		exec.Result{Code: 1, Stdout: `{"message":"Not Found","status":"404"}`, Stderr: "gh: Not Found (HTTP 404)"})
	fake.AddOutput(`{"description":"mine","html_url":"https://github.com/me/gh-script","license":{"spdx_id":"NOASSERTION"},"archived":true}`,
		"gh", "api", "repos/me/gh-script")
	fake.AddOutput(`{"description":"TOML parser","html_url":"https://github.com/BurntSushi/toml","license":{"spdx_id":"MIT"},"topics":["toml"]}`,
		"gh", "api", "repos/BurntSushi/toml")
	c := NewClient(&exec.Env{Vars: map[string]string{}, Runner: fake}, "audit/test", 5*time.Second)
	c.Base = Bases{PyPI: srv.URL, Npm: srv.URL + "/npm", CratesIndex: srv.URL + "/index", CratesAPI: srv.URL + "/crates",
		GoProxy: srv.URL + "/goproxy", Rubygems: srv.URL + "/gems", Node: srv.URL + "/node/index.json", GoDL: srv.URL + "/go/dl"}
	c.Intervals = nil
	return c, fake, &hits
}

func TestLookup(t *testing.T) {
	c, _, _ := newClient(t)
	ts := func(s string) time.Time { tm, _ := time.Parse(time.RFC3339, s); return tm }
	tests := []struct {
		p    packages.Package
		want packages.Meta
	}{
		{
			packages.Package{Manager: "uv", Name: "ruff", Version: "0.9.0", Source: "pypi"},
			packages.Meta{Latest: "0.9.2", LatestAt: ts("2026-09-01T10:00:00Z"), InstalledYanked: true,
				Description: "An extremely fast Python linter.", Repo: "https://github.com/astral-sh/ruff",
				Homepage: "https://docs.astral.sh/ruff", License: "MIT", Keywords: []string{"lint", "python"}},
		},
		{
			packages.Package{Manager: "uv", Name: "old", Version: "1.0", Source: "pypi"},
			packages.Meta{Latest: "1.0", LatestAt: ts("2020-01-01T00:00:00Z"), Description: "old thing",
				Deprecated: `marked "Development Status :: 7 - Inactive" on PyPI`, Repo: "https://gitlab.com/o/old/-/issues"},
		},
		{
			packages.Package{Manager: "pnpm", Name: "@biomejs/biome", Version: "2.0.0", Source: "npm"},
			packages.Meta{Latest: "2.1.0", LatestAt: ts("2026-07-01T12:00:00Z"), Description: "Biome toolchain", Homepage: "https://biomejs.dev",
				Repo: "https://github.com/biomejs/biome", License: "MIT OR Apache-2.0", Keywords: []string{"format", "lint"}},
		},
		{
			packages.Package{Manager: "pnpm", Name: "left-pad", Version: "1.3.0", Source: "npm"},
			packages.Meta{Latest: "1.3.0", Repo: "https://github.com/stevemao/left-pad", License: "WTFPL",
				Deprecated: "use String.prototype.padStart()"},
		},
		{
			packages.Package{Manager: "cargo", Name: "ripgrep", Version: "14.1.2", Source: "crates.io"},
			packages.Meta{Latest: "14.1.1", LatestAt: ts("2024-09-08T22:24:21Z"), InstalledYanked: true,
				Description: "ripgrep is a line-oriented search tool", Homepage: "https://github.com/BurntSushi/ripgrep",
				Repo: "https://github.com/BurntSushi/ripgrep", License: "Unlicense OR MIT", Keywords: []string{"regex", "grep"}},
		},
		{
			packages.Package{Manager: "go", Name: "tomlv", Version: "v1.4.0", Ident: "github.com/BurntSushi/toml"},
			packages.Meta{Latest: "v1.5.0", LatestAt: ts("2025-03-01T00:00:00Z"), Description: "TOML parser",
				Repo: "https://github.com/BurntSushi/toml", License: "MIT", Keywords: []string{"toml"}},
		},
		{
			packages.Package{Manager: "gem", Name: "rake", Version: "13.0.0", Source: "rubygems"},
			packages.Meta{Latest: "13.3.0", LatestAt: ts("2025-05-01T00:00:00Z"), Description: "Make-like program",
				Homepage: "https://github.com/ruby/rake", Repo: "https://github.com/ruby/rake", License: "MIT"},
		},
		{
			packages.Package{Manager: "gh", Name: "gh-dash", Version: "v4.6.0", Ident: "dlvhdr/gh-dash"},
			packages.Meta{Latest: "v4.7.0", LatestAt: ts("2026-09-20T00:00:00Z"), Description: "A dashboard",
				Repo: "https://github.com/dlvhdr/gh-dash", License: "MIT", Keywords: []string{"gh-extension", "tui"}},
		},
		{
			// No releases: nothing to compare, but the repository is described.
			packages.Package{Manager: "gh", Name: "gh-script", Version: "abc1234", Ident: "me/gh-script"},
			packages.Meta{Description: "mine", Repo: "https://github.com/me/gh-script", Archived: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.p.Key(), func(t *testing.T) {
			got, described, err := c.Lookup(ctx, tt.p, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			if !described {
				t.Error("described = false")
			}
			got.LatestAt = got.LatestAt.UTC()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestLookupErrors(t *testing.T) {
	c, fake, _ := newClient(t)
	fake.Add([]string{"gh", "api", "repos/o/gh-x/releases/latest"},
		exec.Result{Code: 1, Stderr: "gh: Server Error (HTTP 500)\nmore"})
	cases := []struct {
		p    packages.Package
		env  map[string]string
		want string
	}{
		{packages.Package{Manager: "uv", Name: "nope", Source: "pypi"}, nil, "not found on PyPI"},
		{packages.Package{Manager: "uv", Name: "boom", Source: "pypi"}, nil, "HTTP 502"},
		{packages.Package{Manager: "uv", Name: "local", Source: "path:/x"}, nil, "not from a registry"},
		{packages.Package{Manager: "go", Name: "x", Version: "v1.0.0", Ident: "corp.example/x"}, map[string]string{"GOPRIVATE": "corp.example"}, "private module (GOPRIVATE)"},
		{packages.Package{Manager: "go", Name: "x", Version: "v1.0.0", Ident: "github.com/a/x"}, map[string]string{"GONOPROXY": "github.com/a/*"}, "private module (GONOPROXY)"},
		{packages.Package{Manager: "gh", Name: "gh-x", Ident: "o/gh-x"}, nil, "gh api repos/o/gh-x/releases/latest: gh: Server Error (HTTP 500)"},
		{packages.Package{Manager: "gh", Name: "gh-y", Ident: "o/gh-y"}, nil, "gh is not installed"},
	}
	for _, tt := range cases {
		t.Run(tt.p.Key(), func(t *testing.T) {
			c.Env.Vars = tt.env
			_, _, err := c.Lookup(ctx, tt.p, nil, true)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	c.Env.Vars = nil
	if _, _, err := c.Lookup(ctx, packages.Package{Manager: "uv", Name: "nope", Source: "pypi"}, nil, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("not found should wrap ErrNotFound: %v", err)
	}
}

func TestGoProxySelection(t *testing.T) {
	c := &Client{Env: &exec.Env{Vars: map[string]string{}}}
	for _, tt := range []struct{ goproxy, want, err string }{
		{"", "https://proxy.golang.org", ""},
		{"https://goproxy.io/,direct", "https://goproxy.io", ""},
		{"https://a.example|https://b.example", "https://a.example", ""},
		{"direct", "", "has no proxy"},
		{"off", "", "has no proxy"},
	} {
		c.Env.Vars["GOPROXY"] = tt.goproxy
		got, err := c.goProxy("github.com/a/b")
		if got != tt.want || (tt.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.err)) {
			t.Errorf("GOPROXY=%q: %q %v", tt.goproxy, got, err)
		}
	}
}

func TestCratesSkipsAPIWhenUnchanged(t *testing.T) {
	c, _, hits := newClient(t)
	p := packages.Package{Manager: "cargo", Name: "ripgrep", Version: "14.1.1", Source: "crates.io"}
	prev := &packages.Meta{Latest: "14.1.1"}
	m, described, err := c.Lookup(ctx, p, prev, false)
	if err != nil || described || m.Latest != "14.1.1" || hits.Load() != 1 {
		t.Errorf("index only: %+v described=%v err=%v hits=%d", m, described, err, hits.Load())
	}
	prev.Latest = "14.1.0"
	if _, described, _ := c.Lookup(ctx, p, prev, false); !described || hits.Load() != 3 {
		t.Errorf("a new release should ask the API: described=%v hits=%d", described, hits.Load())
	}
}

func TestNpmSkipsFullDocWhenDated(t *testing.T) {
	c, _, hits := newClient(t)
	p := packages.Package{Manager: "pnpm", Name: "@biomejs/biome", Version: "2.0.0", Source: "npm"}
	prev := &packages.Meta{Latest: "2.1.0", LatestAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)}
	if m, _, err := c.Lookup(ctx, p, prev, true); err != nil || !m.LatestAt.IsZero() || hits.Load() != 1 {
		t.Errorf("dated and unchanged: %+v err=%v hits=%d", m, err, hits.Load())
	}
	prev.LatestAt = time.Time{}
	if m, _, _ := c.Lookup(ctx, p, prev, true); m.LatestAt.IsZero() || hits.Load() != 3 {
		t.Errorf("an undated entry should fetch the full document: %+v hits=%d", m, hits.Load())
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://github.com/a/b.git":   "https://github.com/a/b",
		"git://github.com/a/b.git":         "https://github.com/a/b",
		"git@github.com:a/b.git":           "https://github.com/a/b",
		"ssh://git@github.com/a/b.git":     "https://github.com/a/b",
		"github:a/b":                       "https://github.com/a/b",
		"a/b":                              "https://github.com/a/b",
		"https://github.com/a/b/#readme":   "https://github.com/a/b",
		"https://gitlab.com/group/sub/pkg": "https://gitlab.com/group/sub/pkg",
		"":                                 "",
	} {
		if got := cleanRepo(in); got != want {
			t.Errorf("cleanRepo(%q) = %q, want %q", in, got, want)
		}
	}
	for name, want := range map[string]string{"a": "1/a", "ab": "2/ab", "abc": "3/a/abc", "Serde": "se/rd/serde", "ripgrep": "ri/pg/ripgrep"} {
		if got := CratesIndexPath(name); got != want {
			t.Errorf("CratesIndexPath(%q) = %q, want %q", name, got, want)
		}
	}
	for u, want := range map[string]string{"https://github.com/a/b.git": "a/b", "https://github.com/a/b/tree/x": "a/b", "https://github.com/a": "", "https://gitlab.com/a/b": ""} {
		if got := githubRepo(u); got != want {
			t.Errorf("githubRepo(%q) = %q, want %q", u, got, want)
		}
	}
	vs := []crateVersion{{Vers: "1.0.0-rc.1"}, {Vers: "0.9.0", Yanked: true}}
	if got := latestCrate(vs); got != "1.0.0-rc.1" {
		t.Errorf("only prereleases: %q", got)
	}
}

func TestRateLimit(t *testing.T) {
	c := &Client{Intervals: map[string]time.Duration{"h": 30 * time.Millisecond}}
	start := time.Now()
	for range 3 {
		if err := c.wait(ctx, "h"); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 60*time.Millisecond {
		t.Errorf("3 calls took %v, want >= 60ms", d)
	}
	if err := c.wait(ctx, "other"); err != nil {
		t.Error(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	c.Intervals["h"] = time.Hour
	_ = c.wait(ctx, "h")
	if err := c.wait(cctx, "h"); err == nil {
		t.Error("cancelled wait should fail")
	}
}

func TestGitHubUser(t *testing.T) {
	fake := &exec.Fake{}
	env := &exec.Env{Runner: fake}
	if _, err := GitHubUser(ctx, env); err == nil {
		t.Error("missing gh should fail")
	}
	fake.AddOutput("njhoffman\n", "gh", "api", "user")
	if u, err := GitHubUser(ctx, env); u != "njhoffman" || err != nil {
		t.Errorf("got %q %v", u, err)
	}
}
