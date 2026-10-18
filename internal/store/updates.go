package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/njhoffman/audit/internal/packages"
)

const updateItemCols = `manager, id, name, from_version, to_version, latest, status, command, code, duration_ms, reason, output`

// SaveUpdate stores an update run with its results and sets u.ID.
func (s *Store) SaveUpdate(ctx context.Context, u *packages.Update) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO updates(host, started_at, finished_at) VALUES (?, ?, ?)`,
		u.Host, fmtTime(u.StartedAt), fmtTime(u.FinishedAt))
	if err != nil {
		return fmt.Errorf("insert update: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for i, it := range u.Items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO update_items(update_id, seq, `+updateItemCols+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, i, it.Manager, it.ID, it.Name, it.From, it.To, it.Latest, it.Status, it.Command, it.Code,
			it.Duration.Milliseconds(), it.Reason, it.Output); err != nil {
			return fmt.Errorf("insert update item %s: %w", it.Key(), err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	u.ID = id
	return nil
}

// LastUpdate returns the newest update run, or nil when there is none.
func (s *Store) LastUpdate(ctx context.Context) (*packages.Update, error) {
	var u packages.Update
	var started, finished string
	err := s.db.QueryRowContext(ctx, `SELECT id, host, started_at, finished_at FROM updates
		ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&u.ID, &u.Host, &started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.StartedAt, u.FinishedAt = parseTS(started), parseTS(finished)
	rows, err := s.db.QueryContext(ctx, `SELECT `+updateItemCols+` FROM update_items WHERE update_id=? ORDER BY seq`, u.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var it packages.UpdateResult
		var ms int64
		if err := rows.Scan(&it.Manager, &it.ID, &it.Name, &it.From, &it.To, &it.Latest, &it.Status, &it.Command,
			&it.Code, &ms, &it.Reason, &it.Output); err != nil {
			return nil, err
		}
		it.Duration = time.Duration(ms) * time.Millisecond
		u.Items = append(u.Items, it)
	}
	return &u, rows.Err()
}

// UpdateFailures returns, by package key, the last update attempt of each
// package whose last attempt (skips aside) failed.
func (s *Store) UpdateFailures(ctx context.Context) (map[string]packages.UpdateFailure, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.manager, i.id, i.status, i.from_version, i.reason, u.finished_at
		FROM update_items i JOIN updates u ON u.id = i.update_id
		WHERE i.status != ? ORDER BY u.finished_at DESC, u.id DESC, i.seq`, packages.UpdateSkipped)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]packages.UpdateFailure{}
	seen := map[string]bool{}
	for rows.Next() {
		var manager, id, status, from, reason, at string
		if err := rows.Scan(&manager, &id, &status, &from, &reason, &at); err != nil {
			return nil, err
		}
		k := packages.MetaKey(manager, id)
		if seen[k] {
			continue
		}
		seen[k] = true
		if status == packages.UpdateFailed {
			out[k] = packages.UpdateFailure{At: parseTS(at), From: from, Reason: reason}
		}
	}
	return out, rows.Err()
}

// PruneUpdates keeps the newest keep update runs.
func (s *Store) PruneUpdates(ctx context.Context, keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM updates WHERE id NOT IN
		(SELECT id FROM updates ORDER BY finished_at DESC, id DESC LIMIT ?)`, keep)
	return err
}
