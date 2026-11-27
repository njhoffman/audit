package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/todo"
)

// Activity is one thing audit or the user got done: a task closing or
// reopening, or an action step that succeeded. Rows are never pruned with
// runs, tasks or updates, so they outlive them. No command text is kept.
type Activity struct {
	ID int64     `json:"id"`
	At time.Time `json:"at"`
	// Kind is "task" or an update kind (package, runtime, migration, sync,
	// clean, history).
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Check   string `json:"check,omitempty"`
	// Subject is the task key, or manager:name for an action step.
	Subject string `json:"subject"`
	Title   string `json:"title"`
	// Action is resolved, done, wont_do or reopened for tasks, else the
	// step's status (updated).
	Action   string        `json:"action"`
	Priority todo.Priority `json:"priority,omitempty"`
	// From and To are the versions (or counts) an action step moved
	// between; empty for tasks.
	From    string   `json:"from,omitempty"`
	To      string   `json:"to,omitempty"`
	Details []string `json:"details,omitempty"`
}

const activitySchema = `CREATE TABLE IF NOT EXISTS activity (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	at TEXT NOT NULL,
	kind TEXT NOT NULL,
	command TEXT NOT NULL DEFAULT '',
	check_id TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	priority TEXT NOT NULL DEFAULT '',
	from_value TEXT NOT NULL DEFAULT '',
	to_value TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS activity_at ON activity(at);
`

func insertActivity(ctx context.Context, tx *sql.Tx, a Activity) error {
	details := a.Details
	if details == nil {
		details = []string{}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO activity(at, kind, command, check_id, subject, title, action, priority, from_value, to_value, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, fmtTime(a.At), a.Kind, a.Command, a.Check, a.Subject, a.Title, a.Action,
		string(a.Priority), a.From, a.To, mustJSON(details))
	if err != nil {
		return fmt.Errorf("record activity: %w", err)
	}
	return nil
}

// taskTransition is the activity of a task moving from old to t, if the
// move closed or reopened it.
func taskTransition(old todo.Status, t todo.Todo) (Activity, bool) {
	a := Activity{At: t.UpdatedAt, Kind: "task", Command: t.Command, Check: t.Check, Subject: t.Key, Title: t.Title,
		Priority: t.Priority, Details: t.Details}
	switch {
	case !old.Closed() && t.Status.Closed():
		a.Action = string(t.Status)
		if t.Status == todo.Resolved && !t.ResolvedAt.IsZero() {
			a.At = t.ResolvedAt
		}
	case old.Closed() && !t.Status.Closed():
		a.Action = "reopened"
	default:
		return a, false
	}
	if a.At.IsZero() {
		a.At = time.Now()
	}
	return a, true
}

// updateActivities are the succeeded steps of u as activities.
func updateActivities(u *packages.Update) []Activity {
	var out []Activity
	for _, it := range u.Items {
		if it.Status != packages.UpdateOK {
			continue
		}
		out = append(out, Activity{At: u.FinishedAt, Kind: it.KindOrDefault(), Command: activityCommand(it.KindOrDefault()),
			Subject: it.Manager + ":" + it.Name, Title: it.Name, Action: it.Status, From: it.From, To: it.To})
	}
	return out
}

// activityCommand is the audit command whose action a step kind belongs to.
func activityCommand(kind string) string {
	switch kind {
	case "sync":
		return "repos"
	case "clean":
		// files clean and configs clean share the kind; the subject's
		// manager tells them apart.
		return ""
	case "history":
		return "history"
	}
	return packages.Command
}

// Activities returns the activity since t (zero for all), newest first, at
// most limit rows (0 for all).
func (s *Store) Activities(ctx context.Context, since time.Time, limit int) ([]Activity, error) {
	q := `SELECT id, at, kind, command, check_id, subject, title, action, priority, from_value, to_value, details FROM activity`
	var args []any
	if !since.IsZero() {
		q += ` WHERE at >= ?`
		args = append(args, fmtTime(since))
	}
	q += ` ORDER BY at DESC, id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Activity
	for rows.Next() {
		var a Activity
		var at, prio, details string
		if err := rows.Scan(&a.ID, &at, &a.Kind, &a.Command, &a.Check, &a.Subject, &a.Title, &a.Action, &prio, &a.From, &a.To, &details); err != nil {
			return nil, err
		}
		a.At, a.Priority = parseTS(at), todo.Priority(prio)
		_ = json.Unmarshal([]byte(details), &a.Details)
		if len(a.Details) == 0 {
			a.Details = nil
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PreviousFix is the last time the task with key closed (resolved or
// done), or nil.
func (s *Store) PreviousFix(ctx context.Context, key string) (*Activity, error) {
	var a Activity
	var at, prio string
	err := s.db.QueryRowContext(ctx, `SELECT id, at, kind, command, check_id, subject, title, action, priority, from_value, to_value
		FROM activity WHERE kind='task' AND subject=? AND action IN ('resolved','done') ORDER BY at DESC, id DESC LIMIT 1`, key).
		Scan(&a.ID, &at, &a.Kind, &a.Command, &a.Check, &a.Subject, &a.Title, &a.Action, &prio, &a.From, &a.To)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.At, a.Priority = parseTS(at), todo.Priority(prio)
	return &a, nil
}
