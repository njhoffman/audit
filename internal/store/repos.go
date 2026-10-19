package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/njhoffman/audit/internal/repos"
)

// RepoMeta returns the cached GitHub data by repo key.
func (s *Store) RepoMeta(ctx context.Context) (map[string]repos.Meta, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, data FROM repo_meta`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]repos.Meta{}
	for rows.Next() {
		var key, data string
		if err := rows.Scan(&key, &data); err != nil {
			return nil, err
		}
		var m repos.Meta
		if err := json.Unmarshal([]byte(data), &m); err != nil {
			return nil, fmt.Errorf("repo cache entry %s: %w", key, err)
		}
		out[key] = m
	}
	return out, rows.Err()
}

// SaveRepoMeta replaces the cached entries of ms.
func (s *Store) SaveRepoMeta(ctx context.Context, ms []repos.Meta) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range ms {
		if _, err := tx.ExecContext(ctx, `INSERT INTO repo_meta(key, data, checked_at) VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET data=excluded.data, checked_at=excluded.checked_at`,
			m.Key, mustJSON(m), fmtTime(m.CheckedAt)); err != nil {
			return fmt.Errorf("save repo cache %s: %w", m.Key, err)
		}
	}
	return tx.Commit()
}

// RepoTags returns the user's repo tags by repo key, sorted.
func (s *Store) RepoTags(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, tag FROM repo_tags ORDER BY key, tag`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var key, tag string
		if err := rows.Scan(&key, &tag); err != nil {
			return nil, err
		}
		out[key] = append(out[key], tag)
	}
	return out, rows.Err()
}

// SetRepoTags adds (or with remove, deletes) tags of the repo key.
func (s *Store) SetRepoTags(ctx context.Context, key string, tags []string, remove bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range tags {
		q := `INSERT OR IGNORE INTO repo_tags(key, tag) VALUES (?, ?)`
		if remove {
			q = `DELETE FROM repo_tags WHERE key=? AND tag=?`
		}
		if _, err := tx.ExecContext(ctx, q, key, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}
