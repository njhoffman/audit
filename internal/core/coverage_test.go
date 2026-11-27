package core

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/scan/programs"
	"github.com/njhoffman/audit/internal/system"
)

type carriedStore struct {
	invs  []packages.Inventory
	err   error
	asked []string
}

func (c *carriedStore) LatestInventories(_ context.Context, managers []string) ([]packages.Inventory, error) {
	c.asked = managers
	return c.invs, c.err
}

func TestPackagesCarriesSkippedSystemManagers(t *testing.T) {
	env := fakepmPath(t)
	from := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	cs := &carriedStore{invs: []packages.Inventory{{Manager: "apt", Available: true, CarriedFrom: from,
		Packages: []packages.Package{{Manager: "apt", Name: "curl", Version: "8"}}}}}
	s := &PackagesScanner{Env: env, Managers: []packages.Manager{envManager{}}, SkipSystem: []string{"apt", "snap"}, Carried: cs}
	out, data := scanPackages(t, s)
	if !slices.Equal(cs.asked, []string{"apt", "snap"}) {
		t.Errorf("asked for %v", cs.asked)
	}
	if !slices.Equal(data.Skipped, []string{"snap"}) || len(data.Inventories) != 2 || data.Inventories[1].Manager != "apt" {
		t.Errorf("apt is carried, snap has nothing to carry: skipped %v, %d inventories", data.Skipped, len(data.Inventories))
	}
	if got := stat(out, "apt"); !strings.Contains(got, "not rescanned; checked") {
		t.Errorf("apt stat %q", got)
	}
	if got := stat(out, "snap"); got != "not scanned" {
		t.Errorf("snap stat %q", got)
	}

	s.Carried = nil
	if _, data = scanPackages(t, s); !slices.Equal(data.Skipped, []string{"apt", "snap"}) {
		t.Errorf("without a store every skipped manager is listed: %v", data.Skipped)
	}
	s.Carried = &carriedStore{err: errors.New("disk")}
	if _, err := s.Scan(context.Background(), progress.Nop); err == nil || !strings.Contains(err.Error(), "load saved system packages") {
		t.Errorf("a store failure fails the scan: %v", err)
	}
}

func TestHistoryScanner(t *testing.T) {
	cfg := defaultConfig(t)
	home := t.TempDir()
	env := &exec.Env{Vars: map[string]string{"SESSION": "7"}, Home: home}
	if err := os.WriteFile(filepath.Join(home, "hist"), []byte(": 1:0;ls\n: 2:0;pwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(home, "histdb.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE places (id INTEGER PRIMARY KEY, host TEXT)",
		"CREATE TABLE history (id INTEGER PRIMARY KEY, session INTEGER, place_id INTEGER)",
		"INSERT INTO places VALUES (1, 'box'), (2, 'other')",
		"INSERT INTO history(session, place_id) VALUES (7, 1), (7, 1), (3, 2)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	_ = db.Close()
	cfg.ShellHistory.Files = []string{"hist", "missing"}
	cfg.ShellHistory.HistDB = "~/histdb.db"
	cfg.ShellHistory.Formats = nil
	s := NewHistory(cfg, env)
	s.Options.Host = "box"
	if s.Command() != "history" || s.Scope() != "" || s.Options.Session != 7 {
		t.Errorf("command %q scope %q session %d", s.Command(), s.Scope(), s.Options.Session)
	}
	out, err := s.Scan(context.Background(), progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"files": "1", "entries": "2", "histdb total entries": "3",
		"histdb this host": "2", "histdb this session": "2", "format " + filepath.Join(home, "hist"): "zsh | detected"} {
		if got := stat(out, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if len(out.Findings) != 1 || out.Findings[0].Check != "history.histdb_behind" {
		t.Errorf("histdb has more entries than the files: %+v", out.Findings)
	}

	s.Options.Session = 0
	if out, _ = s.Scan(context.Background(), progress.Nop); !strings.HasPrefix(stat(out, "histdb this session"), "unavailable") {
		t.Errorf("no SESSION: %q", stat(out, "histdb this session"))
	}
	s.Options.HistDB = filepath.Join(home, "hist")
	if out, _ = s.Scan(context.Background(), progress.Nop); len(out.Errors) != 1 || !strings.HasPrefix(out.Errors[0], "histdb: ") {
		t.Errorf("an unreadable histdb is an error line: %q", out.Errors)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, progress.Nop); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestSystemScannerScan(t *testing.T) {
	cfg := defaultConfig(t)
	s, err := NewSystem(cfg, osEnv(t.TempDir()), []string{"users"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Scan(context.Background(), progress.Nop)
	if err != nil || len(out.Stats) == 0 || len(out.Data) == 0 {
		t.Fatalf("users scan: %v, %d stats", err, len(out.Stats))
	}
	if s.Command() != "system" || s.Scope() != "users" {
		t.Errorf("command %q scope %q", s.Command(), s.Scope())
	}
}

type programStore struct {
	carriedStore
	metas map[string]packages.Meta
}

func (p *programStore) PackageMeta(context.Context) (map[string]packages.Meta, error) {
	return p.metas, nil
}
func (p *programStore) SavePackageMeta(context.Context, []packages.Meta) error { return nil }

func TestSystemProgramPackages(t *testing.T) {
	sbin, home := t.TempDir(), t.TempDir()
	local := filepath.Join(home, "bin")
	for _, d := range []string{sbin, local} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "cron"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	env := &exec.Env{Vars: map[string]string{"PATH": sbin + ":" + local}, Home: home}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	st := &programStore{carriedStore: carriedStore{invs: []packages.Inventory{
		{Manager: "apt", Available: true, Packages: []packages.Package{{Manager: "apt", Name: "cron", Version: "3.0pl1-196", Available: "3.0pl1-197"}}},
		{Manager: "bins", Available: true, Packages: []packages.Package{{Manager: "bins", Name: "cron", Version: "4.1", Location: filepath.Join(local, "cron")}}},
	}}}
	s := &SystemScanner{Env: env, Packages: st, Now: now, Dpkg: func(p string) string {
		if p == filepath.Join(sbin, "cron") {
			return "cron"
		}
		return ""
	}}
	res := &system.Result{Data: system.Data{Parts: map[string]map[string]any{"programs": {
		"per_program": []programs.ProgramResult{{Program: programs.ProgramCron}, {Program: programs.ProgramNginx, Skipped: true}},
	}}}}
	pps := s.programPackages(context.Background(), res, now)
	if len(pps) != 1 || len(pps[0].Copies) != 2 {
		t.Fatalf("cron matched twice, nginx skipped: %+v", pps)
	}
	var stat string
	for _, x := range res.Stats {
		if x.Name == "cron package" {
			stat = x.Value + " | " + x.Note
		}
	}
	if !strings.HasPrefix(stat, "cron 3.0pl1-196 (apt) | patch update to 3.0pl1-197; audit packages update -M apt") ||
		!strings.Contains(stat, "also "+filepath.Join(local, "cron")+": bins cron 4.1, shadowed") {
		t.Errorf("stat %q", stat)
	}
	if len(res.Findings) != 1 || res.Findings[0].Check != CheckProgramShadowed || !strings.Contains(res.Findings[0].Message, "is newer (bins cron 4.1)") {
		t.Errorf("the newer shadowed copy is a finding: %+v", res.Findings)
	}

	// No saved packages run: one stat says how to get one.
	res = &system.Result{Data: system.Data{Parts: map[string]map[string]any{"programs": {"per_program": []programs.ProgramResult{{Program: programs.ProgramCron}}}}}}
	s.Packages = &programStore{}
	if pps := s.programPackages(context.Background(), res, now); pps != nil || len(res.Stats) != 1 || res.Stats[0].Value != "unknown" {
		t.Errorf("no inventories: %+v %+v", pps, res.Stats)
	}
	s.Packages = &programStore{carriedStore: carriedStore{err: errors.New("disk")}}
	if s.programPackages(context.Background(), res, now); !slices.ContainsFunc(res.Errors, func(e string) bool { return strings.Contains(e, "read saved packages") }) {
		t.Errorf("a store error is reported: %v", res.Errors)
	}
}

func TestDpkgOwner(t *testing.T) {
	f := &exec.Fake{}
	// /usr/sbin/cron was unpacked as /sbin/cron (merged /usr); a diversion
	// line and a package listing another path are passed over.
	f.Add([]string{"dpkg-query", "-S", "/usr/sbin/cron"}, exec.Result{Code: 1})
	f.AddOutput("diversion by x from: /sbin/cron\nother: /sbin/cronx\ncron, cron-daemon: /sbin/cron\n", "dpkg-query", "-S", "/sbin/cron")
	env := &exec.Env{Runner: f}
	if got := dpkgOwner(context.Background(), env, "/usr/sbin/cron"); got != "cron" {
		t.Errorf("owner %q", got)
	}
	f.AddOutput("tool: /usr/bin/tool\n", "dpkg-query", "-S", "/usr/bin/tool")
	if got := dpkgOwner(context.Background(), env, "/bin/tool"); got != "tool" {
		t.Errorf("a /bin path tries /usr/bin: %q", got)
	}
	if got := dpkgOwner(context.Background(), env, "/opt/x"); got != "" {
		t.Errorf("unknown path: %q", got)
	}
}

func TestCopyOwner(t *testing.T) {
	it := &packages.Item{Package: packages.Package{Name: "cron", Version: "4.1"}}
	for _, tc := range []struct {
		c     packages.ProgramCopy
		owner string
		ver   string
	}{
		{packages.ProgramCopy{Manager: "bins", Item: it}, "bins cron", " 4.1"},
		{packages.ProgramCopy{Manager: "apt"}, "apt", ""},
		{packages.ProgramCopy{}, "no package", ""},
	} {
		if got := copyOwner(tc.c); got != tc.owner {
			t.Errorf("owner %q, want %q", got, tc.owner)
		}
		if got := versionOf(tc.c); got != tc.ver {
			t.Errorf("version %q, want %q", got, tc.ver)
		}
	}
}
