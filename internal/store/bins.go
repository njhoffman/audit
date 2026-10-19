package store

import (
	"context"

	"github.com/njhoffman/audit/internal/packages"
)

// TrackedBins returns the tracked loose binaries by name.
func (s *Store) TrackedBins(ctx context.Context) (map[string]packages.TrackedBin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, repo, asset, version, sha256, installed_at FROM bins`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]packages.TrackedBin{}
	for rows.Next() {
		var b packages.TrackedBin
		var at string
		if err := rows.Scan(&b.Name, &b.Repo, &b.Asset, &b.Version, &b.SHA256, &at); err != nil {
			return nil, err
		}
		if at != "" {
			b.InstalledAt = parseTS(at)
		}
		out[b.Name] = b
	}
	return out, rows.Err()
}

// SaveTrackedBin inserts or replaces a tracked binary.
func (s *Store) SaveTrackedBin(ctx context.Context, b packages.TrackedBin) error {
	at := ""
	if !b.InstalledAt.IsZero() {
		at = fmtTime(b.InstalledAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bins(name, repo, asset, version, sha256, installed_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET repo=excluded.repo, asset=excluded.asset, version=excluded.version,
		sha256=excluded.sha256, installed_at=excluded.installed_at`, b.Name, b.Repo, b.Asset, b.Version, b.SHA256, at)
	return err
}

// DeleteTrackedBin stops tracking name; ok is false when it was not tracked.
func (s *Store) DeleteTrackedBin(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM bins WHERE name=?`, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
