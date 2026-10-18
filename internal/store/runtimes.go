package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/njhoffman/audit/internal/packages"
)

// RuntimeMeta returns the cached runtime lookups by runtime name.
func (s *Store) RuntimeMeta(ctx context.Context) (map[string]packages.RuntimeMeta, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, data FROM runtime_meta`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]packages.RuntimeMeta{}
	for rows.Next() {
		var name, data string
		if err := rows.Scan(&name, &data); err != nil {
			return nil, err
		}
		var m packages.RuntimeMeta
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			return nil, fmt.Errorf("runtime cache entry %s: %w", name, err)
		}
		out[name] = m
	}
	return out, rows.Err()
}

// SaveRuntimeMeta replaces the cached lookups of the given runtimes.
func (s *Store) SaveRuntimeMeta(ctx context.Context, ms []packages.RuntimeMeta) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range ms {
		if _, err := tx.ExecContext(ctx, `INSERT INTO runtime_meta(name, data, checked_at) VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET data=excluded.data, checked_at=excluded.checked_at`,
			m.Name, mustJSON(m), fmtTime(m.CheckedAt)); err != nil {
			return fmt.Errorf("save runtime cache %s: %w", m.Name, err)
		}
	}
	return tx.Commit()
}
