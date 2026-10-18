package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/finding"
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
	got, err := s.LatestRun(ctx, "packages", "")
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
		if v, _ := s.Setting(ctx, "schema_version"); v != "2" {
			t.Errorf("schema_version = %q", v)
		}
		u, err := s.LastUpdate(ctx)
		if err != nil || u == nil || u.Items[0].Kind != "package" {
			t.Errorf("old rows read as packages: %+v %v", u, err)
		}
		_ = s.Close()
	}

	db, _ = sql.Open("sqlite", "file:"+path)
	_, _ = db.Exec(`UPDATE meta SET value='3' WHERE key='schema_version'`)
	_ = db.Close()
	if _, err := Open(path); err == nil || err.Error() != "database schema version 3 is not supported (want 2)" {
		t.Errorf("a newer database is refused: %v", err)
	}
}
