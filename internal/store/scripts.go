package store

import (
	"context"
	"time"
)

// ScriptDescriptions returns the cached AI descriptions by content hash.
func (s *Store) ScriptDescriptions(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sha256, description FROM script_desc`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var sha, d string
		if err := rows.Scan(&sha, &d); err != nil {
			return nil, err
		}
		out[sha] = d
	}
	return out, rows.Err()
}

// SaveScriptDescription stores the description of a script's content.
func (s *Store) SaveScriptDescription(ctx context.Context, sha, desc, model string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO script_desc(sha256, description, model, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(sha256) DO UPDATE SET description=excluded.description, model=excluded.model, created_at=excluded.created_at`,
		sha, desc, model, fmtTime(at))
	return err
}
