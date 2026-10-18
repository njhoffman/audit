package packages

import (
	"reflect"
	"strings"
	"testing"
)

func TestFirstVersion(t *testing.T) {
	cases := map[string]string{
		"pnpm 12.14.0\n":                         "12.14.0",
		"uv 0.13.1 (x86_64-unknown-linux-gnu)":   "0.13.1",
		"cargo 1.101.0-nightly (abc 2026-01-01)": "1.101.0-nightly",
		"v24.22.0":                               "24.22.0",
		"gh version 2.52.0 (2024-06-24)":         "2.52.0",
		"no version here":                        "",
	}
	for in, want := range cases {
		if got := FirstVersion(in); got != want {
			t.Errorf("FirstVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseToolList(t *testing.T) {
	text := "assume v0.4.0\n- assume\n- jp.py\n" +
		"black v24.1.0 [required: <25]\n- black\n- blackd\n" +
		"warning: Ignoring malformed tool `broken` (run `uv tool uninstall broken`)\n" +
		"nobins v1.0\n"
	want := []uvTool{
		{"assume", "0.4.0", []string{"assume", "jp.py"}},
		{"black", "24.1.0", []string{"black", "blackd"}},
		{"nobins", "1.0", nil},
	}
	if got := parseToolList(text); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if got := parseToolList("- orphan\n"); len(got) != 0 {
		t.Errorf("leading executable line produced %+v", got)
	}
}

func TestParsePyvenvVersion(t *testing.T) {
	if got := parsePyvenvVersion("home = /x\nversion_info = 3.14.8\n"); got != "3.14.8" {
		t.Errorf("got %q", got)
	}
	if got := parsePyvenvVersion("home = /x\n"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestReceiptSource(t *testing.T) {
	cases := []struct {
		req  map[string]any
		want string
	}{
		{map[string]any{"name": "x"}, "pypi"},
		{map[string]any{"name": "x", "directory": "/src/x"}, "path:/src/x"},
		{map[string]any{"name": "x", "editable": "/src/x"}, "path:/src/x"},
		{map[string]any{"name": "x", "git": "https://github.com/a/x"}, "git:https://github.com/a/x"},
		{map[string]any{"name": "x", "url": "https://h/x.whl"}, "url:https://h/x.whl"},
	}
	for _, c := range cases {
		var r uvReceipt
		r.Tool.Requirements = []map[string]any{c.req}
		if got := receiptSource(r); got != c.want {
			t.Errorf("receiptSource(%v) = %q, want %q", c.req, got, c.want)
		}
	}
	if got := receiptSource(uvReceipt{}); got != "pypi" {
		t.Errorf("empty receipt = %q", got)
	}
}

func TestParseLs(t *testing.T) {
	text := `[{"path": "/g", "dependencies": {
		"eslint": {"version": "9.0.0", "path": "/g/a/node_modules/eslint"},
		"local": {"version": "link:../src/local"}}}]`
	got, err := parseLs(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []pnpmDep{{"eslint", "9.0.0", "/g/a/node_modules/eslint"}, {"local", "link:../src/local", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if got, err := parseLs("[]"); err != nil || len(got) != 0 {
		t.Errorf("empty list: %+v %v", got, err)
	}
	got, err = parseLs(`{"dependencies": {"a": {"version": "1"}}}`)
	if err != nil || !reflect.DeepEqual(got, []pnpmDep{{"a", "1", ""}}) {
		t.Errorf("object root: %+v %v", got, err)
	}
	if _, err := parseLs("not json"); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("invalid json err = %v", err)
	}
}

func TestPackageBins(t *testing.T) {
	cases := []struct {
		name     string
		manifest map[string]any
		want     []string
	}{
		{"eslint", map[string]any{"bin": "bin/eslint.js"}, []string{"eslint"}},
		{"@scope/tool", map[string]any{"bin": "cli.js"}, []string{"tool"}},
		{"ts-node", map[string]any{"bin": map[string]any{"ts-node-esm": "a", "ts-node": "b"}}, []string{"ts-node", "ts-node-esm"}},
		{"lib", map[string]any{}, nil},
	}
	for _, c := range cases {
		if got := packageBins(c.name, c.manifest); !reflect.DeepEqual(got, c.want) {
			t.Errorf("packageBins(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSourceFromVersion(t *testing.T) {
	for in, want := range map[string]string{"1.2.3": "npm", "link:/src/x": "path:/src/x", "file:/a": "path:/a", "": "npm"} {
		if got := sourceFromVersion(in); got != want {
			t.Errorf("sourceFromVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

const rustcVV = "rustc 1.90.0-nightly (ce5fdd7d4 2025-07-26)\nbinary: rustc\nrelease: 1.90.0-nightly\n"

func TestParseCrates2(t *testing.T) {
	text := `{"installs": {
		"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["rg"], "rustc": "` +
		strings.ReplaceAll(rustcVV, "\n", `\n`) + `"},
		"aichat 0.30.1 (git+https://github.com/me/aichat#2514c22)": {"bins": ["aichat"]},
		"garbage": {}}}`
	pkgs, err := parseCrates2(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Manager: "cargo", Name: "aichat", Version: "0.30.1", Runtime: "rust", Source: "git:https://github.com/me/aichat", Executables: []string{"aichat"}},
		{Manager: "cargo", Name: "ripgrep", Version: "14.1.0", Runtime: "rust", RuntimeVersion: "1.90.0-nightly", Source: "crates.io", Executables: []string{"rg"}},
	}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("got %+v", pkgs)
	}
	if _, err := parseCrates2("{"); err == nil {
		t.Error("invalid JSON accepted")
	}
}

func TestDescribeSource(t *testing.T) {
	cases := map[string]string{
		"registry+https://github.com/rust-lang/crates.io-index": "crates.io",
		"sparse+https://index.crates.io/":                       "crates.io",
		"registry+https://my.registry/index":                    "registry:https://my.registry/index",
		"git+ssh://git@github.com/me/x?branch=b#abc":            "git:ssh://git@github.com/me/x?branch=b",
		"path+file:///home/me/src/x":                            "path:/home/me/src/x",
		"weird":                                                 "weird",
	}
	for in, want := range cases {
		if got := describeSource(in); got != want {
			t.Errorf("describeSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseVersionM(t *testing.T) {
	text := "/home/u/go/bin/gopls: go1.26.5\n" +
		"\tpath\tgolang.org/x/tools/gopls\n" +
		"\tmod\tgolang.org/x/tools/gopls\tv0.20.0\th1:abc=\n" +
		"\tdep\tgolang.org/x/mod\tv0.1.0\th1:def=\n" +
		"\tbuild\t-compiler=gc\n" +
		"/home/u/go/bin/local: go1.25.7\n" +
		"\tpath\texample.com/local\n" +
		"\tmod\texample.com/local\t(devel)\t\n" +
		"/home/u/go/bin/script.sh: could not read Go build info\n" +
		"\tmod\tignored\tv1\n"
	pkgs := parseVersionM(text)
	if len(pkgs) != 2 {
		t.Fatalf("got %+v", pkgs)
	}
	p := pkgs[0]
	if p.Name != "gopls" || p.Version != "v0.20.0" || p.Ident != "golang.org/x/tools/gopls" ||
		p.Source != "golang.org/x/tools/gopls" || p.RuntimeVersion != "1.26.5" ||
		!reflect.DeepEqual(p.Executables, []string{"gopls"}) {
		t.Errorf("gopls = %+v", p)
	}
	if q := pkgs[1]; q.Name != "local" || q.Version != "(devel)" || q.RuntimeVersion != "1.25.7" {
		t.Errorf("local = %+v", q)
	}
}

func TestParseSpecFilename(t *testing.T) {
	cases := map[string][2]string{
		"rubocop-1.60.0.gemspec":               {"rubocop", "1.60.0"},
		"rubocop-ast-1.30.0.gemspec":           {"rubocop-ast", "1.30.0"},
		"nokogiri-1.16.0-x86_64-linux.gemspec": {"nokogiri", "1.16.0"},
		"bundler-2.5.0.pre.1.gemspec":          {"bundler", "2.5.0.pre.1"},
	}
	for in, want := range cases {
		n, v, ok := parseSpecFilename(in)
		if !ok || n != want[0] || v != want[1] {
			t.Errorf("parseSpecFilename(%q) = %q %q %v", in, n, v, ok)
		}
	}
	if _, _, ok := parseSpecFilename("README.md"); ok {
		t.Error("README.md parsed")
	}
}

func TestParseExecutables(t *testing.T) {
	spec := "s.bindir = \"exe\".freeze\n  s.executables = [\"bundle\".freeze, \"bundler\".freeze]\n"
	if got := parseExecutables(spec); !reflect.DeepEqual(got, []string{"bundle", "bundler"}) {
		t.Errorf("got %v", got)
	}
	if got := parseExecutables("s.name = 'x'"); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"13.0.9", "13.0.10", true},
		{"13.0.10", "13.0.9", false},
		{"2.5.0.pre.1", "2.5.0", false},
		{"2.5.0", "2.5.0.1", true},
		{"2.5.0.pre.1", "2.5.0.1", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestParseExtensionList(t *testing.T) {
	text := "gh dash\tdlvhdr/gh-dash\tv4.9.0\ngh star\tkeidarcy/gh-star\t8a116a7a\ngh local\tlocal/gh-local\t\njunk\n"
	pkgs := parseExtensionList(text)
	type row struct{ name, version, ident, exe string }
	var got []row
	for _, p := range pkgs {
		got = append(got, row{p.Name, p.Version, p.Ident, p.Executables[0]})
	}
	want := []row{
		{"dash", "v4.9.0", "dlvhdr/gh-dash", "gh dash"},
		{"star", "8a116a7a", "keidarcy/gh-star", "gh star"},
		{"local", "", "local/gh-local", "gh local"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}
