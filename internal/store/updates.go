package store

import (
	"context"
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
	us, err := s.Updates(ctx, 1)
	if err != nil || len(us) == 0 {
		return nil, err
	}
	return &us[0], nil
}

// Updates returns the newest limit update runs with their results, newest
// first.
func (s *Store) Updates(ctx context.Context, limit int) ([]packages.Update, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, started_at, finished_at FROM updates
		ORDER BY finished_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	var us []packages.Update
	for rows.Next() {
		var u packages.Update
		var started, finished string
		if err := rows.Scan(&u.ID, &u.Host, &started, &finished); err != nil {
			_ = rows.Close()
			return nil, err
		}
		u.StartedAt, u.FinishedAt = parseTS(started), parseTS(finished)
		us = append(us, u)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range us {
		if us[i].Items, err = s.updateItems(ctx, us[i].ID); err != nil {
			return nil, err
		}
	}
	return us, nil
}

func (s *Store) updateItems(ctx context.Context, id int64) ([]packages.UpdateResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+updateItemCols+` FROM update_items WHERE update_id=? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []packages.UpdateResult
	for rows.Next() {
		var it packages.UpdateResult
		var ms int64
		if err := rows.Scan(&it.Manager, &it.ID, &it.Name, &it.From, &it.To, &it.Latest, &it.Status, &it.Command,
			&it.Code, &ms, &it.Reason, &it.Output); err != nil {
			return nil, err
		}
		it.Duration = time.Duration(ms) * time.Millisecond
		out = append(out, it)
	}
	return out, rows.Err()
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
