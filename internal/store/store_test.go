package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var ctx = context.Background()

func sampleRun(cmd string, at time.Time, fs ...finding.Finding) *run.Run {
	return &run.Run{
		Command: cmd, Host: "h", StartedAt: at.Add(-2 * time.Second), FinishedAt: at,
		Findings: fs, Stats: []run.Stat{{Name: "packages", Value: "3"}}, Data: json.RawMessage(`{"x":1}`),
	}
}

func TestRunRoundTrip(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := sampleRun("packages", at,
		finding.Finding{Command: "packages", Check: "exe.conflict", Severity: finding.Warning, Kind: finding.Issue,
			Subject: "tsc", Message: "m", Hint: "h", Details: []string{"a", "b"}},
		finding.Finding{Command: "packages", Check: "exe.missing", Severity: finding.Error, Kind: finding.Issue, Subject: "x"},
	)
	r.Scope = "all"
	if err := s.SaveRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r.ID == 0 {
		t.Fatal("ID not set")
	}
	if full, err := s.LatestRun(ctx, "packages", ""); full != nil || err != nil {
		t.Errorf("a scoped run is not a full run: %v %v", full, err)
	}
	got, err := s.LatestRun(ctx, "packages", "all")
	if err != nil || got == nil {
		t.Fatalf("LatestRun: %v %v", got, err)
	}
	if !got.FinishedAt.Equal(at) || got.Duration() != 2*time.Second || got.Scope != "all" {
		t.Errorf("times/scope wrong: %+v", got)
	}
	if len(got.Findings) != 2 || got.Findings[0].Details[1] != "b" || got.Findings[1].Details != nil {
		t.Errorf("findings wrong: %+v", got.Findings)
	}
	if string(got.Data) != `{"x":1}` || got.Stats[0].Value != "3" || got.Analysis != nil {
		t.Errorf("payload wrong: %+v", got)
	}
	if none, err := s.LatestRun(ctx, "packages", "other-scope"); none != nil || err != nil {
		t.Errorf("scope filter: %v %v", none, err)
	}
	if none, err := s.LatestRun(ctx, "repos", ""); none != nil || err != nil {
		t.Errorf("missing command should be nil, nil: %v %v", none, err)
	}
	a := &run.Analysis{Text: "looks fine", Model: "m", CreatedAt: at}
	if err := s.UpdateAnalysis(ctx, r.ID, a); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRun(ctx, r.ID)
	if got.Analysis == nil || got.Analysis.Text != "looks fine" {
		t.Errorf("analysis not stored: %+v", got.Analysis)
	}
	if missing, err := s.GetRun(ctx, 999); missing != nil || err != nil {
		t.Errorf("GetRun missing: %v %v", missing, err)
	}
}

func TestHistoryLatestAndPrune(t *testing.T) {
	s := open(t)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		fs := make([]finding.Finding, i)
		for j := range fs {
			fs[j] = finding.Finding{Command: "system", Check: "c", Severity: finding.Warning, Subject: "s"}
		}
		if err := s.SaveRun(ctx, sampleRun("system", base.Add(time.Duration(i)*time.Hour), fs...)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveRun(ctx, sampleRun("packages", base, finding.Finding{Command: "packages", Severity: finding.Error})); err != nil {
		t.Fatal(err)
	}
	h, err := s.History(ctx, "system", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].Counts[finding.Warning] != 3 || h[1].Counts[finding.Warning] != 2 {
		t.Errorf("history wrong: %+v", h)
	}
	latest, err := s.LatestPerCommand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest["packages"].Counts[finding.Error] != 1 || latest["system"].Counts.Total() != 3 {
		t.Errorf("latest wrong: %+v", latest)
	}
	if err := s.Prune(ctx, "system", 2); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.History(ctx, "system", 0); len(h) != 2 {
		t.Errorf("prune kept %d runs", len(h))
	}
	if h, _ = s.History(ctx, "packages", 0); len(h) != 1 {
		t.Error("prune touched another command")
	}
}

func TestTodosCRUD(t *testing.T) {
	s := open(t)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ts := []todo.Todo{
		{Key: "packages:a:1", Command: "packages", Title: "a", Priority: todo.High, Status: todo.Open, Source: todo.FromFinding,
			Details: []string{"d"}, CreatedAt: now, UpdatedAt: now, LastSeenAt: now},
		{Key: NextManualKey("", now), Command: "manual", Title: "write docs", Priority: todo.Low, Status: todo.Open,
			Source: todo.Manual, CreatedAt: now, UpdatedAt: now, LastSeenAt: now},
	}
	if err := s.SaveTodos(ctx, ts); err != nil {
		t.Fatal(err)
	}
	if ts[0].ID == 0 || ts[1].ID == 0 {
		t.Fatal("ids not written back")
	}
	later := now.Add(time.Hour)
	note := "fixing"
	got, err := s.SetTodoStatus(ctx, ts[0].ID, todo.InProgress, &note, later)
	if err != nil || got.Status != todo.InProgress || got.Note != "fixing" {
		t.Fatalf("SetTodoStatus: %+v %v", got, err)
	}
	if got, _ = s.SetTodoStatus(ctx, ts[0].ID, todo.Done, nil, later); !got.ResolvedAt.Equal(later) || got.Note != "fixing" {
		t.Errorf("done should set resolved_at and keep note: %+v", got)
	}
	if got, _ = s.SetTodoNote(ctx, ts[0].ID, "n2", later); got.Note != "n2" {
		t.Errorf("note: %+v", got)
	}
	all, err := s.Todos(ctx, "packages")
	if err != nil || len(all) != 1 || all[0].Details[0] != "d" || !all[0].CreatedAt.Equal(now) {
		t.Errorf("Todos: %+v %v", all, err)
	}
	if err := s.DeleteTodo(ctx, ts[0].ID); err == nil {
		t.Error("deleting a scanner task must fail")
	}
	if err := s.DeleteTodo(ctx, ts[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTodo(ctx, ts[1].ID); err == nil {
		t.Error("manual task not deleted")
	}
	dup := []todo.Todo{{Key: "packages:a:1", Command: "packages", Title: "dup", Priority: todo.Low, Status: todo.Open, Source: todo.FromFinding}}
	if err := s.SaveTodos(ctx, dup); err == nil {
		t.Error("duplicate key must be rejected")
	}
}

func TestCache(t *testing.T) {
	s := open(t)
	if c, err := s.CacheGet(ctx, "h"); c != nil || err != nil {
		t.Fatalf("empty cache: %v %v", c, err)
	}
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := s.CachePut(ctx, "h", CachedResponse{Model: "m", Text: "t1", CostUSD: 0.5, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CachePut(ctx, "h", CachedResponse{Model: "m", Text: "t2", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	c, err := s.CacheGet(ctx, "h")
	if err != nil || c.Text != "t2" || !c.CreatedAt.Equal(now) {
		t.Errorf("cache: %+v %v", c, err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRun(ctx, sampleRun("files", time.Now())); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if r, _ := s.LatestRun(ctx, "files", ""); r == nil {
		t.Error("run lost after reopen")
	}
}

func TestChanges(t *testing.T) {
	s := open(t)
	before, err := s.Changes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Todos(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Changes(ctx); n != before {
		t.Errorf("a read changed the count: %d -> %d", before, n)
	}
	if err := s.SetSetting(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Changes(ctx); n <= before {
		t.Errorf("a write did not change the count: %d -> %d", before, n)
	}
}

// TestMigrateV1 opens a version 1 database whose update_items has no kind
// column and checks it is upgraded in place, keeping its rows.
func TestMigrateV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO meta VALUES ('schema_version', '1')`,
		`CREATE TABLE updates (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL DEFAULT '',
			started_at TEXT NOT NULL, finished_at TEXT NOT NULL)`,
		`CREATE TABLE update_items (update_id INTEGER NOT NULL REFERENCES updates(id) ON DELETE CASCADE,
			seq INTEGER NOT NULL, manager TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL,
			from_version TEXT NOT NULL DEFAULT '', to_version TEXT NOT NULL DEFAULT '', latest TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL, command TEXT NOT NULL DEFAULT '', code INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', output TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (update_id, seq))`,
		`INSERT INTO updates(host, started_at, finished_at) VALUES ('h', '2026-10-01T12:00:00Z', '2026-10-01T12:00:00Z')`,
		`INSERT INTO update_items(update_id, seq, manager, id, name, status) VALUES (1, 0, 'uv', 'ruff', 'ruff', 'updated')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	_ = db.Close()

	for range 2 {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := s.Setting(ctx, "schema_version"); v != strconv.Itoa(schemaVersion) {
			t.Errorf("schema_version = %q", v)
		}
		u, err := s.LastUpdate(ctx)
		if err != nil || u == nil || u.Items[0].Kind != "package" {
			t.Errorf("old rows read as packages: %+v %v", u, err)
		}
		_ = s.Close()
	}

	db, _ = sql.Open("sqlite", "file:"+path)
	newer := strconv.Itoa(schemaVersion + 1)
	_, _ = db.Exec(`UPDATE meta SET value=? WHERE key='schema_version'`, newer)
	_ = db.Close()
	if _, err := Open(path); err == nil || err.Error() != fmt.Sprintf("database schema version %s is not supported (want %d)", newer, schemaVersion) {
		t.Errorf("a newer database is refused: %v", err)
	}
}

func TestTrackedBins(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if err := s.SaveTrackedBin(ctx, packages.TrackedBin{Name: "bat", Repo: "sharkdp/bat"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveTrackedBin(ctx, packages.TrackedBin{Name: "bat", Repo: "sharkdp/bat", Asset: "*musl*", Version: "v0.26.1",
		SHA256: "abc", InstalledAt: at}); err != nil {
		t.Fatal(err)
	}
	got, err := s.TrackedBins(ctx)
	if err != nil || len(got) != 1 || got["bat"].Asset != "*musl*" || got["bat"].Version != "v0.26.1" || !got["bat"].InstalledAt.Equal(at) {
		t.Errorf("tracked: %+v %v", got, err)
	}
	if ok, err := s.DeleteTrackedBin(ctx, "bat"); !ok || err != nil {
		t.Errorf("delete: %v %v", ok, err)
	}
	if ok, _ := s.DeleteTrackedBin(ctx, "bat"); ok {
		t.Error("deleting twice")
	}
}

func TestRepoMetaAndTags(t *testing.T) {
	s := open(t)
	at := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	if err := s.SaveRepoMeta(ctx, []repos.Meta{{Key: "github.com/o/r", Topics: []string{"cli"}, Moved: "o/r2", CheckedAt: at}}); err != nil {
		t.Fatal(err)
	}
	m, err := s.RepoMeta(ctx)
	if err != nil || m["github.com/o/r"].Moved != "o/r2" || m["github.com/o/r"].Topics[0] != "cli" || !m["github.com/o/r"].CheckedAt.Equal(at) {
		t.Errorf("meta: %+v %v", m, err)
	}
	if err := s.SetRepoTags(ctx, "github.com/o/r", []string{"work", "go"}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRepoTags(ctx, "github.com/o/r", []string{"go"}, true); err != nil {
		t.Fatal(err)
	}
	tags, err := s.RepoTags(ctx)
	if err != nil || len(tags["github.com/o/r"]) != 1 || tags["github.com/o/r"][0] != "work" {
		t.Errorf("tags: %v %v", tags, err)
	}
}

func TestPruneCache(t *testing.T) {
	s := open(t)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for hash, age := range map[string]time.Duration{"old": 100 * 24 * time.Hour, "edge": 90*24*time.Hour + time.Minute, "new": time.Hour} {
		if err := s.CachePut(ctx, hash, CachedResponse{Model: "m", Text: hash, CreatedAt: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneCache(ctx, now.Add(-90*24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d %v, want 2", n, err)
	}
	for hash, kept := range map[string]bool{"old": false, "edge": false, "new": true} {
		if c, err := s.CacheGet(ctx, hash); err != nil || (c != nil) != kept {
			t.Errorf("%s: %+v %v, kept should be %v", hash, c, err, kept)
		}
	}
}

func TestMigrationLadder(t *testing.T) {
	if schemaVersion != len(migrations)+1 {
		t.Fatalf("schemaVersion %d needs %d migrations, have %d", schemaVersion, schemaVersion-1, len(migrations))
	}
	s := open(t)
	version := func() string {
		var v string
		if err := s.db.QueryRow(`SELECT value FROM meta WHERE key='schema_version'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := s.db.Exec(`UPDATE meta SET value='1' WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	var ran []int
	step := func(n int) func(*sql.Tx) error {
		return func(tx *sql.Tx) error {
			ran = append(ran, n)
			_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS ladder (n INTEGER)`)
			return err
		}
	}
	boom := func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE half_done (n INTEGER)`); err != nil {
			return err
		}
		return errors.New("boom")
	}
	if err := migrate(s.db, 1, []func(*sql.Tx) error{step(2), boom}); err == nil || !strings.Contains(err.Error(), "version 3: boom") {
		t.Fatalf("failing step: %v", err)
	}
	if version() != "2" {
		t.Errorf("the step before the failure stays applied: version %s", version())
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='half_done'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a failed step is rolled back: %d %v", n, err)
	}
	ran = nil
	if err := migrate(s.db, 2, []func(*sql.Tx) error{step(2), step(3)}); err != nil || version() != "3" || len(ran) != 1 || ran[0] != 3 {
		t.Errorf("resuming at version 2 runs only the later step: %v ran %v version %s", err, ran, version())
	}
}

func TestPreviousRun(t *testing.T) {
	s := open(t)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	first := sampleRun("packages", base, finding.Finding{Command: "packages", Check: "a", Severity: finding.Notice})
	scoped := sampleRun("packages", base.Add(time.Hour))
	scoped.Scope = "uv"
	other := sampleRun("system", base.Add(2*time.Hour))
	second := sampleRun("packages", base.Add(3*time.Hour))
	for _, r := range []*run.Run{first, scoped, other, second} {
		if err := s.SaveRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	prev, err := s.PreviousRun(ctx, second)
	if err != nil || prev == nil || prev.ID != first.ID || len(prev.Findings) != 1 {
		t.Fatalf("the previous full packages run, with findings: %+v %v", prev, err)
	}
	if prev, err := s.PreviousRun(ctx, first); err != nil || prev != nil {
		t.Errorf("the first run has none: %+v %v", prev, err)
	}
	if prev, err := s.PreviousRun(ctx, scoped); err != nil || prev != nil {
		t.Errorf("a scoped run compares with its own scope only: %+v %v", prev, err)
	}
}

func TestMigrateV2AddsInstalledAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO meta VALUES ('schema_version', '2')`,
		`CREATE TABLE package_meta (manager TEXT NOT NULL, id TEXT NOT NULL, registry TEXT NOT NULL DEFAULT '',
			latest TEXT NOT NULL DEFAULT '', latest_at TEXT NOT NULL DEFAULT '', installed TEXT NOT NULL DEFAULT '',
			installed_yanked INTEGER NOT NULL DEFAULT 0, deprecated TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0,
			description TEXT NOT NULL DEFAULT '', repo TEXT NOT NULL DEFAULT '', homepage TEXT NOT NULL DEFAULT '',
			license TEXT NOT NULL DEFAULT '', keywords TEXT NOT NULL DEFAULT '[]', checked_at TEXT NOT NULL DEFAULT '',
			described_at TEXT NOT NULL DEFAULT '', tagged_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (manager, id))`,
		`INSERT INTO package_meta(manager, id, latest, installed) VALUES ('uv', 'ruff', '0.9.0', '0.8.0')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	_ = db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ms, err := s.PackageMeta(ctx)
	if err != nil || ms["uv:ruff"].Latest != "0.9.0" || !ms["uv:ruff"].InstalledAt.IsZero() {
		t.Fatalf("old rows read with no installed date: %+v %v", ms, err)
	}
	at := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	m := ms["uv:ruff"]
	m.InstalledAt = at
	if err := s.SavePackageMeta(ctx, []packages.Meta{m}); err != nil {
		t.Fatal(err)
	}
	if ms, _ = s.PackageMeta(ctx); !ms["uv:ruff"].InstalledAt.Equal(at) {
		t.Errorf("installed_at round trip: %v", ms["uv:ruff"].InstalledAt)
	}
}
