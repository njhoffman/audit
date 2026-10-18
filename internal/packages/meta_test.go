package packages

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

func TestRegistryAndSourceKind(t *testing.T) {
	cases := []struct {
		p              Package
		registry, kind string
	}{
		{Package{Manager: "uv", Name: "ruff", Source: "pypi"}, RegistryPyPI, "registry"},
		{Package{Manager: "uv", Name: "mine", Source: "path:/src/mine"}, "", "local"},
		{Package{Manager: "uv", Name: "x", Source: "git:https://github.com/a/x"}, "", "git"},
		{Package{Manager: "pnpm", Name: "tsc", Source: "npm"}, RegistryNpm, "registry"},
		{Package{Manager: "cargo", Name: "rg", Source: "crates.io"}, RegistryCrates, "registry"},
		{Package{Manager: "cargo", Name: "y", Source: "git:https://github.com/a/y"}, "", "git"},
		{Package{Manager: "go", Name: "gopls", Ident: "golang.org/x/tools/gopls", Version: "v0.20.0"}, RegistryGoProxy, "registry"},
		{Package{Manager: "go", Name: "dev", Ident: "example.com/dev", Version: "(devel)"}, "", "local"},
		{Package{Manager: "gem", Name: "rake", Source: "rubygems"}, RegistryRubygems, "registry"},
		{Package{Manager: "gh", Name: "dash", Ident: "dlvhdr/gh-dash", Source: "github:dlvhdr/gh-dash"}, RegistryGitHub, "registry"},
	}
	for _, c := range cases {
		if got := c.p.Registry(); got != c.registry {
			t.Errorf("%s:%s Registry = %q want %q", c.p.Manager, c.p.Name, got, c.registry)
		}
		if got := c.p.SourceKind(); got != c.kind {
			t.Errorf("%s:%s SourceKind = %q want %q", c.p.Manager, c.p.Name, got, c.kind)
		}
	}
	gopls := cases[6].p
	if gopls.ID() != "golang.org/x/tools/gopls" || gopls.Key() != "go:golang.org/x/tools/gopls" {
		t.Errorf("go id/key: %s %s", gopls.ID(), gopls.Key())
	}
}

func TestAutoTags(t *testing.T) {
	gh := Package{Manager: "gh", Name: "audit", Runtime: "gh", Ident: "njhoffman/gh-audit", Source: "github:njhoffman/gh-audit"}
	if got := AutoTags(gh, nil, "NJHoffman"); !reflect.DeepEqual(got, []string{"gh", "gh", "mine"}) {
		t.Errorf("gh tags: %v", got)
	}
	py := Package{Manager: "uv", Name: "tool", Runtime: "python", Source: "path:/src"}
	meta := &Meta{Repo: "https://github.com/someone/tool"}
	if got := AutoTags(py, meta, "njhoffman"); !reflect.DeepEqual(got, []string{"uv", "python", "local"}) {
		t.Errorf("uv tags: %v", got)
	}
	meta.Repo = "https://github.com/njhoffman/tool.git"
	if got := AutoTags(py, meta, "njhoffman"); got[len(got)-1] != "mine" {
		t.Errorf("repo owner should tag mine: %v", got)
	}
	if got := AutoTags(py, meta, ""); len(got) != 3 {
		t.Errorf("no user means no mine tag: %v", got)
	}
}

func TestAnnotateAndQuery(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	invs := []Inventory{
		{Manager: "pnpm", Available: true, Packages: []Package{
			{Manager: "pnpm", Name: "typescript", Version: "5.9.0", Runtime: "node", Source: "npm", Executables: []string{"tsc"}},
			{Manager: "pnpm", Name: "local-thing", Version: "1.0.0", Runtime: "node", Source: "path:/x"},
			{Manager: "pnpm", Name: "prettier", Version: "3.0.0", Runtime: "node", Source: "npm"},
		}},
		{Manager: "uv", Available: true, Packages: []Package{
			{Manager: "uv", Name: "ruff", Version: "0.9.0", Runtime: "python", Source: "pypi"},
		}},
	}
	metas := map[string]Meta{
		"pnpm:typescript": {Manager: "pnpm", ID: "typescript", Latest: "5.9.3", CheckedAt: now.Add(-2 * time.Hour),
			Description: "TypeScript is a language for application scale JavaScript"},
		"uv:ruff": {Manager: "uv", ID: "ruff", Latest: "0.9.0", CheckedAt: now.Add(-time.Hour)},
	}
	tags := map[string][]string{"pnpm:typescript": {"lsp", "devtools"}}
	as := Annotate(invs, metas, tags, "")

	ts := as[0].Items[0]
	if ts.Gap != GapPatch || ts.Meta == nil || !reflect.DeepEqual(ts.Tags, []string{"devtools", "lsp", "node", "pnpm"}) {
		t.Errorf("typescript item: %+v", ts)
	}
	if as[0].Unchecked != 1 || !as[0].CheckedAt.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("pnpm checked=%v unchecked=%d (local packages have no registry and do not count)", as[0].CheckedAt, as[0].Unchecked)
	}
	if as[1].Items[0].Gap != GapCurrent || as[1].Unchecked != 0 {
		t.Errorf("ruff: %+v", as[1])
	}

	names := func(q Query) []string {
		var out []string
		for _, a := range q.Filter(as) {
			for _, it := range a.Items {
				out = append(out, it.Name)
			}
		}
		return out
	}
	if got := names(Query{}); len(got) != 4 {
		t.Errorf("empty query keeps all: %v", got)
	}
	if got := names(Query{Tags: []string{"LSP"}}); !reflect.DeepEqual(got, []string{"typescript"}) {
		t.Errorf("tag query: %v", got)
	}
	if got := names(Query{Tags: []string{"node", "local"}}); !reflect.DeepEqual(got, []string{"local-thing"}) {
		t.Errorf("tags must all match: %v", got)
	}
	if got := names(Query{Find: "application scale"}); !reflect.DeepEqual(got, []string{"typescript"}) {
		t.Errorf("find by description: %v", got)
	}
	if got := names(Query{Find: "TSC"}); !reflect.DeepEqual(got, []string{"typescript"}) {
		t.Errorf("find by executable: %v", got)
	}
	if got := names(Query{Outdated: true}); !reflect.DeepEqual(got, []string{"typescript"}) {
		t.Errorf("outdated: %v", got)
	}
	if got := (Query{Find: "nothing-matches"}).Filter(as); len(got) != 0 {
		t.Errorf("managers with no match are dropped: %+v", got)
	}
}

func TestRefFind(t *testing.T) {
	invs := []Inventory{
		{Manager: "pnpm", Packages: []Package{{Manager: "pnpm", Name: "prettier"}}},
		{Manager: "uv", Packages: []Package{{Manager: "uv", Name: "prettier"}}},
		{Manager: "go", Packages: []Package{
			{Manager: "go", Name: "gopls", Ident: "golang.org/x/tools/gopls"},
			{Manager: "go", Name: "staticcheck", Ident: "honnef.co/go/tools"},
			{Manager: "go", Name: "structlayout", Ident: "honnef.co/go/tools"},
		}},
	}
	if got := ParseRef("pnpm:prettier").Find(invs); len(got) != 1 || got[0].Manager != "pnpm" {
		t.Errorf("qualified: %+v", got)
	}
	if got := ParseRef("prettier").Find(invs); len(got) != 2 {
		t.Errorf("bare name should match both managers: %+v", got)
	}
	if got := ParseRef("honnef.co/go/tools").Find(invs); len(got) != 1 {
		t.Errorf("module id collapses its binaries: %+v", got)
	}
	if r := ParseRef("weird:name"); r.Manager != "" || r.Name != "weird:name" || r.String() != "weird:name" {
		t.Errorf("unknown prefix is part of the name: %+v", r)
	}
	if got := ParseRef("absent").Find(invs); len(got) != 0 {
		t.Errorf("absent: %+v", got)
	}
}

func TestAge(t *testing.T) {
	day := 24 * time.Hour
	for d, want := range map[time.Duration]string{
		10 * time.Second: "1 minute", 5 * time.Minute: "5 minutes", 3 * time.Hour: "3 hours",
		day: "1 day", 45 * day: "1 month", 200 * day: "6 months", 800 * day: "2 years",
	} {
		if got := Age(d); got != want {
			t.Errorf("Age(%s) = %q want %q", d, got, want)
		}
	}
}

func registryState(now time.Time, metas ...Meta) *State {
	pkgs := map[string]Package{
		"pnpm:typescript": {Manager: "pnpm", Name: "typescript", Version: "5.9.0", Source: "npm"},
		"pnpm:eslint":     {Manager: "pnpm", Name: "eslint", Version: "8.57.0", Source: "npm"},
		"pnpm:request":    {Manager: "pnpm", Name: "request", Version: "2.88.2", Source: "npm"},
		"pnpm:local":      {Manager: "pnpm", Name: "local", Version: "1.0.0", Source: "path:/x"},
		"uv:ruff":         {Manager: "uv", Name: "ruff", Version: "0.9.0", Source: "pypi"},
		"uv:old":          {Manager: "uv", Name: "old", Version: "1.0", Source: "pypi"},
		"cargo:yanked":    {Manager: "cargo", Name: "yanked", Version: "1.2.0", Source: "crates.io"},
		"gh:a/gh-arch":    {Manager: "gh", Name: "arch", Version: "v1.0.0", Ident: "a/gh-arch"},
		"go:honnef.co/go/tools": {Manager: "go", Name: "staticcheck", Version: "v0.5.0",
			Ident: "honnef.co/go/tools", Source: "honnef.co/go/tools/cmd/staticcheck"},
	}
	byMgr := map[string]*Inventory{}
	var order []string
	for _, k := range []string{"pnpm:typescript", "pnpm:eslint", "pnpm:request", "pnpm:local", "uv:ruff", "uv:old",
		"cargo:yanked", "gh:a/gh-arch", "go:honnef.co/go/tools"} {
		p := pkgs[k]
		if byMgr[p.Manager] == nil {
			byMgr[p.Manager] = &Inventory{Manager: p.Manager, Available: true}
			order = append(order, p.Manager)
		}
		byMgr[p.Manager].Packages = append(byMgr[p.Manager].Packages, p)
	}
	// A second binary of the staticcheck module must not double its findings.
	byMgr["go"].Packages = append(byMgr["go"].Packages, Package{Manager: "go", Name: "structlayout", Version: "v0.5.0",
		Ident: "honnef.co/go/tools", Source: "honnef.co/go/tools/cmd/structlayout"})
	s := &State{Meta: map[string]Meta{}, Now: now, UnmaintainedAfter: 3 * 365 * 24 * time.Hour}
	for _, m := range order {
		s.Inventories = append(s.Inventories, *byMgr[m])
	}
	for _, m := range metas {
		s.Meta[m.Key()] = m
	}
	return s
}

func TestRegistryChecks(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	year := 365 * 24 * time.Hour
	s := registryState(now,
		Meta{Manager: "pnpm", ID: "typescript", Latest: "5.9.3", LatestAt: now.Add(-48 * time.Hour)},
		Meta{Manager: "pnpm", ID: "eslint", Latest: "9.37.0", LatestAt: now.Add(-24 * time.Hour)},
		Meta{Manager: "pnpm", ID: "request", Latest: "2.88.2", Deprecated: "request has been deprecated",
			LatestAt: now.Add(-6 * year)},
		Meta{Manager: "pnpm", ID: "local", Latest: "9.0.0"},
		Meta{Manager: "uv", ID: "ruff", Latest: "0.9.5"},
		Meta{Manager: "uv", ID: "old", Latest: "1.0", LatestAt: now.Add(-4 * year)},
		Meta{Manager: "cargo", ID: "yanked", Latest: "1.2.1", Installed: "1.2.0", InstalledYanked: true},
		Meta{Manager: "gh", ID: "a/gh-arch", Latest: "v1.0.0", Archived: true, Repo: "https://github.com/a/gh-arch",
			LatestAt: now.Add(-5 * year), Error: "HTTP 502"},
		Meta{Manager: "go", ID: "honnef.co/go/tools", Latest: "v0.6.1"},
	)
	fs := finding.RunChecks(Command, s, RegistryChecks)

	got := map[string][]string{}
	for _, f := range fs {
		got[f.Check] = append(got[f.Check], f.Subject)
	}
	want := map[string][]string{
		CheckOutdated:     {"cargo:yanked", "go:honnef.co/go/tools", "pnpm:typescript", "uv:ruff"},
		CheckMajorBehind:  {"pnpm:eslint"},
		CheckDeprecated:   {"pnpm:request"},
		CheckYanked:       {"cargo:yanked"},
		CheckArchived:     {"gh:a/gh-arch"},
		CheckUnmaintained: {"uv:old"},
		CheckFetchError:   {"gh:a/gh-arch"},
	}
	for check, subs := range want {
		if !reflect.DeepEqual(got[check], subs) {
			t.Errorf("%s = %v want %v", check, got[check], subs)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected checks: %v", got)
	}

	for _, f := range fs {
		switch f.Subject + " " + f.Check {
		case "pnpm:typescript " + CheckOutdated:
			if f.Severity != finding.Info || f.Group == nil || f.Group.Title != "Update 1 outdated pnpm package" ||
				f.Group.Hint != "pnpm update -g --latest" || f.Hint != "pnpm add -g typescript@latest" ||
				f.Message != "5.9.0 -> 5.9.3 (patch; released 2026-09-29)" {
				t.Errorf("typescript: %+v %+v", f, f.Group)
			}
		case "pnpm:eslint " + CheckMajorBehind:
			if f.Severity != finding.Notice || f.Group != nil || !strings.Contains(f.Message, "8.57.0 -> 9.37.0 (major") {
				t.Errorf("eslint: %+v", f)
			}
		case "go:honnef.co/go/tools " + CheckOutdated:
			if f.Hint != "go install honnef.co/go/tools/cmd/staticcheck@latest" {
				t.Errorf("go hint: %q", f.Hint)
			}
		case "uv:old " + CheckUnmaintained:
			if f.Kind != finding.Suggestion || !strings.Contains(f.Message, "no release since 2022-") {
				t.Errorf("unmaintained: %+v", f)
			}
		}
	}
}

func TestRegistryChecksEdgeCases(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// Yanked applies to the version checked, not one installed since; no
	// metadata means no findings; an unparseable version is not outdated.
	s := registryState(now,
		Meta{Manager: "cargo", ID: "yanked", Latest: "1.2.0", Installed: "1.1.0", InstalledYanked: true},
		Meta{Manager: "gh", ID: "a/gh-arch", Latest: "not-a-version"},
	)
	if fs := finding.RunChecks(Command, s, RegistryChecks); len(fs) != 0 {
		t.Errorf("want no findings, got %+v", fs)
	}
	s = registryState(now, Meta{Manager: "uv", ID: "old", Latest: "1.0", LatestAt: now.Add(-10 * 365 * 24 * time.Hour)})
	s.UnmaintainedAfter = 0
	if fs := finding.RunChecks(Command, s, RegistryChecks); len(fs) != 0 {
		t.Errorf("unmaintained_after 0 disables the check: %+v", fs)
	}
	s = registryState(now, Meta{Manager: "cargo", ID: "yanked", Latest: "1.2.0", Installed: "1.2.0", InstalledYanked: true})
	fs := finding.RunChecks(Command, s, RegistryChecks)
	if len(fs) != 1 || fs[0].Hint != "Install another version; this one was withdrawn." {
		t.Errorf("yanked latest: %+v", fs)
	}
}

func TestTagPromptAndAnswer(t *testing.T) {
	items := []Item{
		{Package: Package{Manager: "uv", Name: "ruff", Source: "pypi"}, Meta: &Meta{Description: "fast linter", Keywords: []string{"lint"}}},
		{Package: Package{Manager: "gh", Name: "gh-dash", Ident: "dlvhdr/gh-dash"}},
	}
	vocab := []string{"linter", "formatter", "github", "tui", "cli"}
	prompt := TagPrompt(items, vocab)
	for _, want := range []string{"linter, formatter, github, tui, cli", "uv:ruff | fast linter | lint", "gh:dlvhdr/gh-dash | (no description) |"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q:\n%s", want, prompt)
		}
	}

	answer := "Here you go:\n```json\n" + `{"uv:ruff": ["Linter", "linter", "python", "formatter"],
		"gh:dlvhdr/gh-dash": ["github", "tui", "cli", "formatter", "linter"], "pnpm:other": ["cli"]}` + "\n```"
	got, err := ParseTagAnswer(answer, items, vocab)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"uv:ruff": {"linter", "formatter"}, "gh:dlvhdr/gh-dash": {"github", "tui", "cli", "formatter"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got, err := ParseTagAnswer(`{"uv:ruff": []}`, items, vocab); err != nil || len(got) != 1 || len(got["uv:ruff"]) != 0 {
		t.Errorf("empty list should be kept as answered: %v %v", got, err)
	}
	for _, bad := range []string{"no json here", `{"uv:ruff": "linter"}`, `}{`} {
		if _, err := ParseTagAnswer(bad, items, vocab); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestLatestCellsAndRegistryNote(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	pypi := Package{Manager: "uv", Name: "x", Version: "1.0", Source: "pypi"}
	cases := []struct {
		it             Item
		latest, relAge string
	}{
		{Item{Package: Package{Manager: "uv", Name: "x", Source: "git+https://x"}}, "", ""},
		{Item{Package: pypi}, "unchecked", ""},
		{Item{Package: pypi, Meta: &Meta{CheckedAt: now, Error: "HTTP 502"}}, "lookup failed", ""},
		{Item{Package: pypi, Meta: &Meta{CheckedAt: now, Latest: "1.0", Installed: "1.0", InstalledYanked: true,
			Deprecated: "gone", LatestAt: now.Add(-400 * 24 * time.Hour)}}, "1.0 (deprecated, yanked)", "1 year ago"},
		{Item{Package: pypi, Meta: &Meta{CheckedAt: now, Latest: "1.1", Installed: "0.9", InstalledYanked: true}}, "1.1", ""},
		{Item{Package: pypi, Meta: &Meta{CheckedAt: now, Archived: true}}, "no releases (archived)", ""},
	}
	for _, c := range cases {
		if l, r := LatestCells(c.it, now); l != c.latest || r != c.relAge {
			t.Errorf("%+v: got %q %q, want %q %q", c.it.Meta, l, r, c.latest, c.relAge)
		}
	}
	if got := RegistryNote(Annotated{Unchecked: 2}, now); !strings.Contains(got, "never checked") {
		t.Errorf("never: %q", got)
	}
	if got := RegistryNote(Annotated{}, now); got != "" {
		t.Errorf("no registry packages: %q", got)
	}
}
