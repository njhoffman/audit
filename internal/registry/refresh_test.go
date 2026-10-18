package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

// fakeLooker answers from a table and records what it was asked.
type fakeLooker struct {
	mu      sync.Mutex
	answers map[string]packages.Meta
	errs    map[string]error
	asked   map[string]bool // key -> describe
}

func (f *fakeLooker) Lookup(_ context.Context, p packages.Package, _ *packages.Meta, describe bool) (packages.Meta, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[p.Key()] = describe
	if err := f.errs[p.Key()]; err != nil {
		return packages.Meta{}, false, err
	}
	return f.answers[p.Key()], describe, nil
}

func TestRefresh(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	hour := time.Hour
	ruff := packages.Package{Manager: "uv", Name: "ruff", Version: "0.9.0", Source: "pypi"}
	black := packages.Package{Manager: "uv", Name: "black", Version: "24.1", Source: "pypi"}
	rg := packages.Package{Manager: "cargo", Name: "rg", Version: "14.1.0", Source: "crates.io"}
	toml := packages.Package{Manager: "go", Name: "tomlv", Version: "v1.4.0", Ident: "github.com/BurntSushi/toml"}
	tomlFmt := packages.Package{Manager: "go", Name: "tomlfmt", Version: "v1.4.0", Ident: "github.com/BurntSushi/toml"}
	local := packages.Package{Manager: "uv", Name: "mine", Source: "path:/src/mine"}
	upgraded := packages.Package{Manager: "pnpm", Name: "ts", Version: "5.9.3", Source: "npm"}
	broken := packages.Package{Manager: "pnpm", Name: "broken", Version: "1.0", Source: "npm"}

	cache := map[string]packages.Meta{
		// fresh: skipped
		ruff.Key(): {Manager: "uv", ID: "ruff", Latest: "0.9.1", Installed: "0.9.0", CheckedAt: now.Add(-hour), DescribedAt: now.Add(-hour)},
		// stale version data, recent descriptions: looked up without describe
		rg.Key(): {Manager: "cargo", ID: "rg", Latest: "14.1.0", LatestAt: now.Add(-100 * hour), Installed: "14.1.0",
			CheckedAt: now.Add(-48 * hour), DescribedAt: now.Add(-48 * hour), Description: "search", Archived: true,
			TaggedAt: now.Add(-hour), Repo: "https://github.com/BurntSushi/ripgrep"},
		// fresh but the installed version changed
		upgraded.Key(): {Manager: "pnpm", ID: "ts", Latest: "5.9.3", Installed: "5.9.0", CheckedAt: now.Add(-hour), DescribedAt: now.Add(-hour)},
		// lookup fails: keeps the old answer
		broken.Key(): {Manager: "pnpm", ID: "broken", Latest: "2.0", Installed: "1.0", Description: "kept", CheckedAt: now.Add(-48 * hour)},
	}
	l := &fakeLooker{
		answers: map[string]packages.Meta{
			black.Key():    {Latest: "25.1", Description: "formatter"},
			rg.Key():       {Latest: "14.1.0"},
			toml.Key():     {Latest: "v1.5.0", Description: "TOML parser"},
			upgraded.Key(): {Latest: "5.9.3", Description: "TypeScript"},
		},
		errs:  map[string]error{broken.Key(): errors.New("HTTP 502")},
		asked: map[string]bool{},
	}
	var done int
	var mu sync.Mutex
	opts := Options{MaxAge: 24 * hour, MetadataMaxAge: 168 * hour, Concurrency: 3, Now: now,
		OnDone: func(packages.Package, error) { mu.Lock(); done++; mu.Unlock() }}
	got, st := Refresh(ctx, l, []packages.Package{ruff, black, rg, toml, tomlFmt, local, upgraded, broken}, cache, opts)

	if st != (Stats{Checked: 5, Failed: 1, Fresh: 1}) || done != 5 {
		t.Errorf("stats = %+v, OnDone calls = %d", st, done)
	}
	byKey := map[string]packages.Meta{}
	for _, m := range got {
		byKey[m.Key()] = m
	}
	if len(byKey) != 5 || byKey[ruff.Key()].Manager != "" || byKey[local.Key()].Manager != "" {
		t.Fatalf("updated %d entries: %+v", len(byKey), byKey)
	}
	wantDescribe := map[string]bool{black.Key(): true, rg.Key(): false, toml.Key(): true, upgraded.Key(): false, broken.Key(): true}
	for k, d := range wantDescribe {
		if l.asked[k] != d {
			t.Errorf("%s asked with describe=%v, want %v", k, l.asked[k], d)
		}
	}

	b := byKey[black.Key()]
	if b.Registry != packages.RegistryPyPI || b.Installed != "24.1" || !b.CheckedAt.Equal(now) || !b.DescribedAt.Equal(now) || b.ID != "black" {
		t.Errorf("new entry: %+v", b)
	}
	r := byKey[rg.Key()]
	if r.Description != "search" || !r.Archived || !r.DescribedAt.Equal(now.Add(-48*hour)) || !r.LatestAt.Equal(now.Add(-100*hour)) ||
		!r.TaggedAt.Equal(now.Add(-hour)) || r.Repo == "" || !r.CheckedAt.Equal(now) {
		t.Errorf("undescribed lookup should keep cached descriptions, dates and tagging: %+v", r)
	}
	if u := byKey[upgraded.Key()]; u.Installed != "5.9.3" {
		t.Errorf("installed should follow the inventory: %+v", u)
	}
	br := byKey[broken.Key()]
	if br.Error != "HTTP 502" || br.Latest != "2.0" || br.Description != "kept" || !br.CheckedAt.Equal(now) {
		t.Errorf("failed lookup: %+v", br)
	}

	// Force refetches the fresh one and describes everything.
	l.asked = map[string]bool{}
	opts.Force = true
	_, st = Refresh(ctx, l, []packages.Package{ruff}, cache, opts)
	if st.Checked != 1 || !l.asked[ruff.Key()] {
		t.Errorf("force: %+v %v", st, l.asked)
	}

	// A failure with nothing cached still records the error.
	got, _ = Refresh(ctx, l, []packages.Package{broken}, nil, opts)
	if len(got) != 1 || got[0].Error == "" || got[0].Installed != "1.0" || got[0].Registry != packages.RegistryNpm {
		t.Errorf("uncached failure: %+v", got)
	}
}

func TestRefreshCancelled(t *testing.T) {
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	l := &fakeLooker{errs: map[string]error{"uv:a": context.Canceled}, asked: map[string]bool{}}
	got, st := Refresh(cctx, l, []packages.Package{{Manager: "uv", Name: "a", Source: "pypi"}}, nil, Options{Concurrency: 1})
	if len(got) != 0 || st.Checked != 0 {
		t.Errorf("cancelled refresh should change nothing: %+v %+v", got, st)
	}
}
