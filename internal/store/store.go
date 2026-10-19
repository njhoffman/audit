// Package store persists runs, findings, tasks and the LLM response cache in a
// single SQLite database.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// schemaVersion 2 added update_items.kind.
const schemaVersion = 2

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	command TEXT NOT NULL,
	scope TEXT NOT NULL DEFAULT '',
	host TEXT NOT NULL DEFAULT '',
	started_at TEXT NOT NULL,
	finished_at TEXT NOT NULL,
	ignored INTEGER NOT NULL DEFAULT 0,
	stats TEXT NOT NULL DEFAULT '[]',
	errors TEXT NOT NULL DEFAULT '[]',
	data BLOB,
	analysis TEXT
);
CREATE INDEX IF NOT EXISTS runs_command ON runs(command, finished_at);
CREATE TABLE IF NOT EXISTS findings (
	run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	command TEXT NOT NULL,
	check_id TEXT NOT NULL,
	severity TEXT NOT NULL,
	kind TEXT NOT NULL,
	subject TEXT NOT NULL,
	message TEXT NOT NULL,
	hint TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '[]',
	PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS todos (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	key TEXT NOT NULL UNIQUE,
	command TEXT NOT NULL,
	check_id TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL,
	hint TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '[]',
	priority TEXT NOT NULL,
	status TEXT NOT NULL,
	source TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	last_seen_at TEXT NOT NULL,
	resolved_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS package_meta (
	manager TEXT NOT NULL,
	id TEXT NOT NULL,
	registry TEXT NOT NULL DEFAULT '',
	latest TEXT NOT NULL DEFAULT '',
	latest_at TEXT NOT NULL DEFAULT '',
	installed TEXT NOT NULL DEFAULT '',
	installed_yanked INTEGER NOT NULL DEFAULT 0,
	deprecated TEXT NOT NULL DEFAULT '',
	archived INTEGER NOT NULL DEFAULT 0,
	description TEXT NOT NULL DEFAULT '',
	repo TEXT NOT NULL DEFAULT '',
	homepage TEXT NOT NULL DEFAULT '',
	license TEXT NOT NULL DEFAULT '',
	keywords TEXT NOT NULL DEFAULT '[]',
	checked_at TEXT NOT NULL DEFAULT '',
	described_at TEXT NOT NULL DEFAULT '',
	tagged_at TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (manager, id)
);
CREATE TABLE IF NOT EXISTS package_tags (
	manager TEXT NOT NULL,
	id TEXT NOT NULL,
	tag TEXT NOT NULL,
	source TEXT NOT NULL,
	PRIMARY KEY (manager, id, tag)
);
CREATE TABLE IF NOT EXISTS updates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host TEXT NOT NULL DEFAULT '',
	started_at TEXT NOT NULL,
	finished_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS update_items (
	update_id INTEGER NOT NULL REFERENCES updates(id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	manager TEXT NOT NULL,
	id TEXT NOT NULL,
	name TEXT NOT NULL,
	from_version TEXT NOT NULL DEFAULT '',
	to_version TEXT NOT NULL DEFAULT '',
	latest TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	command TEXT NOT NULL DEFAULT '',
	code INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	reason TEXT NOT NULL DEFAULT '',
	output TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL DEFAULT 'package',
	PRIMARY KEY (update_id, seq)
);
CREATE TABLE IF NOT EXISTS runtime_meta (
	name TEXT PRIMARY KEY,
	data TEXT NOT NULL,
	checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bins (
	name TEXT PRIMARY KEY,
	repo TEXT NOT NULL,
	asset TEXT NOT NULL DEFAULT '',
	version TEXT NOT NULL DEFAULT '',
	sha256 TEXT NOT NULL DEFAULT '',
	installed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS llm_cache (
	hash TEXT PRIMARY KEY,
	model TEXT NOT NULL,
	text TEXT NOT NULL,
	cost_usd REAL NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL
);
`

// Store is an open audit database. Its tables are created with IF NOT EXISTS,
// so tables added later appear in an existing database without a version
// bump; only changes to existing tables need one.
type Store struct {
	db *sql.DB
}

// Open creates (if needed) and opens the database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema in %s: %w", path, err)
	}
	if err := checkVersion(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func checkVersion(db *sql.DB) error {
	var v string
	err := db.QueryRow(`SELECT value FROM meta WHERE key='schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = db.Exec(`INSERT INTO meta(key, value) VALUES ('schema_version', ?)`, fmt.Sprint(schemaVersion))
		return err
	}
	if err != nil {
		return err
	}
	if v == "1" {
		if err := migrateV2(db); err != nil {
			return fmt.Errorf("upgrade database schema to version 2: %w", err)
		}
		v = "2"
	}
	if v != fmt.Sprint(schemaVersion) {
		return fmt.Errorf("database schema version %s is not supported (want %d)", v, schemaVersion)
	}
	return nil
}

// migrateV2 adds update_items.kind. A version 1 database whose update_items
// table was created by this binary's schema already has the column.
func migrateV2(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('update_items') WHERE name='kind'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE update_items ADD COLUMN kind TEXT NOT NULL DEFAULT 'package'`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE meta SET value='2' WHERE key='schema_version'`); err != nil {
		return err
	}
	return tx.Commit()
}

// Changes counts the rows this store has written since it was opened. The
// pool holds a single connection, so SQLite's per-connection total covers
// every write.
func (s *Store) Changes(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&n)
	return n, err
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.Local()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// SaveRun inserts r with its findings and sets r.ID.
func (s *Store) SaveRun(ctx context.Context, r *run.Run) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var analysis any
	if r.Analysis != nil {
		analysis = mustJSON(r.Analysis)
	}
	stats := r.Stats
	if stats == nil {
		stats = []run.Stat{}
	}
	errs := r.Errors
	if errs == nil {
		errs = []string{}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO runs(command, scope, host, started_at, finished_at, ignored, stats, errors, data, analysis)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Command, r.Scope, r.Host, fmtTime(r.StartedAt), fmtTime(r.FinishedAt), r.Ignored,
		mustJSON(stats), mustJSON(errs), []byte(r.Data), analysis)
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(run_id, seq, command, check_id, severity, kind, subject, message, hint, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for i, f := range r.Findings {
		details := f.Details
		if details == nil {
			details = []string{}
		}
		if _, err := stmt.ExecContext(ctx, id, i, f.Command, f.Check, string(f.Severity), string(f.Kind),
			f.Subject, f.Message, f.Hint, mustJSON(details)); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.ID = id
	return nil
}

// UpdateAnalysis attaches an LLM analysis to a saved run.
func (s *Store) UpdateAnalysis(ctx context.Context, runID int64, a *run.Analysis) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET analysis=? WHERE id=?`, mustJSON(a), runID)
	return err
}

// Prune keeps the newest keep runs of command and deletes the rest.
func (s *Store) Prune(ctx context.Context, command string, keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE command=? AND id NOT IN
		(SELECT id FROM runs WHERE command=? ORDER BY finished_at DESC, id DESC LIMIT ?)`, command, command, keep)
	return err
}

const runCols = `id, command, scope, host, started_at, finished_at, ignored, stats, errors, data, analysis`

func scanRun(row interface{ Scan(...any) error }) (*run.Run, error) {
	var (
		r                 run.Run
		started, finished string
		stats, errs       string
		data              []byte
		analysis          sql.NullString
	)
	if err := row.Scan(&r.ID, &r.Command, &r.Scope, &r.Host, &started, &finished, &r.Ignored, &stats, &errs, &data, &analysis); err != nil {
		return nil, err
	}
	r.StartedAt, r.FinishedAt = parseTS(started), parseTS(finished)
	_ = json.Unmarshal([]byte(stats), &r.Stats)
	_ = json.Unmarshal([]byte(errs), &r.Errors)
	if len(data) > 0 {
		r.Data = data
	}
	if analysis.Valid && analysis.String != "" {
		r.Analysis = &run.Analysis{}
		if err := json.Unmarshal([]byte(analysis.String), r.Analysis); err != nil {
			r.Analysis = nil
		}
	}
	return &r, nil
}

func (s *Store) loadFindings(ctx context.Context, r *run.Run) error {
	rows, err := s.db.QueryContext(ctx, `SELECT command, check_id, severity, kind, subject, message, hint, details
		FROM findings WHERE run_id=? ORDER BY seq`, r.ID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	r.Findings = []finding.Finding{}
	for rows.Next() {
		var f finding.Finding
		var sev, kind, details string
		if err := rows.Scan(&f.Command, &f.Check, &sev, &kind, &f.Subject, &f.Message, &f.Hint, &details); err != nil {
			return err
		}
		f.Severity, f.Kind = finding.Severity(sev), finding.Kind(kind)
		_ = json.Unmarshal([]byte(details), &f.Details)
		if len(f.Details) == 0 {
			f.Details = nil
		}
		r.Findings = append(r.Findings, f)
	}
	return rows.Err()
}

// LatestRun returns the newest run of command, optionally restricted to a
// scope. It returns nil, nil when there is none.
func (s *Store) LatestRun(ctx context.Context, command, scope string) (*run.Run, error) {
	q := `SELECT ` + runCols + ` FROM runs WHERE command=?`
	args := []any{command}
	if scope != "" {
		q += ` AND scope=?`
		args = append(args, scope)
	}
	q += ` ORDER BY finished_at DESC, id DESC LIMIT 1`
	r, err := scanRun(s.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, s.loadFindings(ctx, r)
}

// GetRun returns one run by id, or nil, nil when absent.
func (s *Store) GetRun(ctx context.Context, id int64) (*run.Run, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, s.loadFindings(ctx, r)
}

// RunInfo is a run's headline numbers without its payload.
type RunInfo struct {
	ID         int64
	Command    string
	Scope      string
	FinishedAt time.Time
	Duration   time.Duration
	Counts     finding.Counts
	Ignored    int
}

// History lists the newest runs of command (all commands when ""), newest first.
func (s *Store) History(ctx context.Context, command string, limit int) ([]RunInfo, error) {
	q := `SELECT r.id, r.command, r.scope, r.started_at, r.finished_at, r.ignored,
		COALESCE((SELECT json_group_object(severity, n) FROM
			(SELECT severity, COUNT(*) AS n FROM findings WHERE run_id=r.id GROUP BY severity)), '{}')
		FROM runs r`
	var args []any
	if command != "" {
		q += ` WHERE r.command=?`
		args = append(args, command)
	}
	q += ` ORDER BY r.finished_at DESC, r.id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RunInfo
	for rows.Next() {
		var ri RunInfo
		var started, finished, counts string
		if err := rows.Scan(&ri.ID, &ri.Command, &ri.Scope, &started, &finished, &ri.Ignored, &counts); err != nil {
			return nil, err
		}
		ri.FinishedAt = parseTS(finished)
		ri.Duration = ri.FinishedAt.Sub(parseTS(started))
		raw := map[string]int{}
		_ = json.Unmarshal([]byte(counts), &raw)
		ri.Counts = finding.Counts{}
		for k, v := range raw {
			ri.Counts[finding.Severity(k)] = v
		}
		out = append(out, ri)
	}
	return out, rows.Err()
}

// LatestPerCommand returns the newest RunInfo of each command that has run.
func (s *Store) LatestPerCommand(ctx context.Context) (map[string]RunInfo, error) {
	all, err := s.History(ctx, "", 0)
	if err != nil {
		return nil, err
	}
	out := map[string]RunInfo{}
	for _, ri := range all {
		if _, ok := out[ri.Command]; !ok {
			out[ri.Command] = ri
		}
	}
	return out, nil
}

const todoCols = `id, key, command, check_id, title, hint, details, priority, status, source, note, created_at, updated_at, last_seen_at, resolved_at`

func scanTodo(row interface{ Scan(...any) error }) (todo.Todo, error) {
	var t todo.Todo
	var details, prio, status, source, created, updated, seen, resolved string
	err := row.Scan(&t.ID, &t.Key, &t.Command, &t.Check, &t.Title, &t.Hint, &details, &prio, &status, &source,
		&t.Note, &created, &updated, &seen, &resolved)
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal([]byte(details), &t.Details)
	if len(t.Details) == 0 {
		t.Details = nil
	}
	t.Priority, t.Status, t.Source = todo.Priority(prio), todo.Status(status), todo.Source(source)
	t.CreatedAt, t.UpdatedAt, t.LastSeenAt, t.ResolvedAt = parseTS(created), parseTS(updated), parseTS(seen), parseTS(resolved)
	return t, nil
}

// Todos returns every task of command (all commands when "").
func (s *Store) Todos(ctx context.Context, command string) ([]todo.Todo, error) {
	q := `SELECT ` + todoCols + ` FROM todos`
	var args []any
	if command != "" {
		q += ` WHERE command=?`
		args = append(args, command)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []todo.Todo
	for rows.Next() {
		t, err := scanTodo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTodo returns one task by id.
func (s *Store) GetTodo(ctx context.Context, id int64) (todo.Todo, error) {
	t, err := scanTodo(s.db.QueryRowContext(ctx, `SELECT `+todoCols+` FROM todos WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, fmt.Errorf("no task with id %d", id)
	}
	return t, err
}

// SaveTodos inserts tasks without an id and updates the rest, in one
// transaction. Ids of inserted tasks are written back into todos.
func (s *Store) SaveTodos(ctx context.Context, todos []todo.Todo) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i := range todos {
		t := &todos[i]
		details := t.Details
		if details == nil {
			details = []string{}
		}
		if t.ID == 0 {
			res, err := tx.ExecContext(ctx, `INSERT INTO todos(key, command, check_id, title, hint, details, priority, status, source, note, created_at, updated_at, last_seen_at, resolved_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				t.Key, t.Command, t.Check, t.Title, t.Hint, mustJSON(details), string(t.Priority), string(t.Status), string(t.Source),
				t.Note, fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt), fmtTime(t.LastSeenAt), fmtTime(t.ResolvedAt))
			if err != nil {
				return fmt.Errorf("insert task %s: %w", t.Key, err)
			}
			if t.ID, err = res.LastInsertId(); err != nil {
				return err
			}
			continue
		}
		_, err := tx.ExecContext(ctx, `UPDATE todos SET key=?, command=?, check_id=?, title=?, hint=?, details=?, priority=?, status=?, source=?, note=?,
			created_at=?, updated_at=?, last_seen_at=?, resolved_at=? WHERE id=?`,
			t.Key, t.Command, t.Check, t.Title, t.Hint, mustJSON(details), string(t.Priority), string(t.Status), string(t.Source),
			t.Note, fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt), fmtTime(t.LastSeenAt), fmtTime(t.ResolvedAt), t.ID)
		if err != nil {
			return fmt.Errorf("update task %d: %w", t.ID, err)
		}
	}
	return tx.Commit()
}

// SetTodoStatus changes a task's status (and note, when note is non-nil).
func (s *Store) SetTodoStatus(ctx context.Context, id int64, status todo.Status, note *string, now time.Time) (todo.Todo, error) {
	t, err := s.GetTodo(ctx, id)
	if err != nil {
		return t, err
	}
	t.Status, t.UpdatedAt = status, now
	if status == todo.Resolved || status == todo.Done {
		t.ResolvedAt = now
	} else {
		t.ResolvedAt = time.Time{}
	}
	if note != nil {
		t.Note = *note
	}
	return t, s.SaveTodos(ctx, []todo.Todo{t})
}

// SetTodoNote replaces a task's note.
func (s *Store) SetTodoNote(ctx context.Context, id int64, note string, now time.Time) (todo.Todo, error) {
	t, err := s.GetTodo(ctx, id)
	if err != nil {
		return t, err
	}
	t.Note, t.UpdatedAt = note, now
	return t, s.SaveTodos(ctx, []todo.Todo{t})
}

// DeleteTodo removes a manual task. Scanner-made tasks would be recreated by
// the next scan, so they are closed with a status instead.
func (s *Store) DeleteTodo(ctx context.Context, id int64) error {
	t, err := s.GetTodo(ctx, id)
	if err != nil {
		return err
	}
	if t.Source != todo.Manual {
		return fmt.Errorf("task %d comes from a scan; set it to won't-do instead of deleting it", id)
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM todos WHERE id=?`, id)
	return err
}

// CachedResponse is one LLM cache entry.
type CachedResponse struct {
	Model     string
	Text      string
	CostUSD   float64
	CreatedAt time.Time
}

// CacheGet returns the cached response for hash, if any.
func (s *Store) CacheGet(ctx context.Context, hash string) (*CachedResponse, error) {
	var c CachedResponse
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT model, text, cost_usd, created_at FROM llm_cache WHERE hash=?`, hash).
		Scan(&c.Model, &c.Text, &c.CostUSD, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = parseTS(created)
	return &c, nil
}

// CachePut stores a response under hash.
func (s *Store) CachePut(ctx context.Context, hash string, c CachedResponse) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO llm_cache(hash, model, text, cost_usd, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET model=excluded.model, text=excluded.text, cost_usd=excluded.cost_usd, created_at=excluded.created_at`,
		hash, c.Model, c.Text, c.CostUSD, fmtTime(c.CreatedAt))
	return err
}

// NextManualKey returns a unique key for a hand-written task.
func NextManualKey(command string, now time.Time) string {
	if command == "" {
		command = "manual"
	}
	return strings.Join([]string{command, "manual", fmt.Sprint(now.UnixNano())}, ":")
}
