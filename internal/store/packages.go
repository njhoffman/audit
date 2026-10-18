package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/njhoffman/audit/internal/packages"
)

const metaCols = `manager, id, registry, latest, latest_at, installed, installed_yanked, deprecated, archived,
	description, repo, homepage, license, keywords, checked_at, described_at, tagged_at, error`

// PackageMeta returns every cached registry entry by packages.Meta.Key.
func (s *Store) PackageMeta(ctx context.Context) (map[string]packages.Meta, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+metaCols+` FROM package_meta`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]packages.Meta{}
	for rows.Next() {
		var m packages.Meta
		var latestAt, keywords, checked, described, tagged string
		if err := rows.Scan(&m.Manager, &m.ID, &m.Registry, &m.Latest, &latestAt, &m.Installed, &m.InstalledYanked,
			&m.Deprecated, &m.Archived, &m.Description, &m.Repo, &m.Homepage, &m.License, &keywords,
			&checked, &described, &tagged, &m.Error); err != nil {
			return nil, err
		}
		m.LatestAt, m.CheckedAt, m.DescribedAt, m.TaggedAt = parseTS(latestAt), parseTS(checked), parseTS(described), parseTS(tagged)
		_ = json.Unmarshal([]byte(keywords), &m.Keywords)
		if len(m.Keywords) == 0 {
			m.Keywords = nil
		}
		out[m.Key()] = m
	}
	return out, rows.Err()
}

// SavePackageMeta inserts or replaces registry entries in one transaction.
func (s *Store) SavePackageMeta(ctx context.Context, ms []packages.Meta) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO package_meta(`+metaCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for _, m := range ms {
		kw := m.Keywords
		if kw == nil {
			kw = []string{}
		}
		if _, err := stmt.ExecContext(ctx, m.Manager, m.ID, m.Registry, m.Latest, fmtTime(m.LatestAt), m.Installed,
			m.InstalledYanked, m.Deprecated, m.Archived, m.Description, m.Repo, m.Homepage, m.License, mustJSON(kw),
			fmtTime(m.CheckedAt), fmtTime(m.DescribedAt), fmtTime(m.TaggedAt), m.Error); err != nil {
			return fmt.Errorf("save meta %s: %w", m.Key(), err)
		}
	}
	return tx.Commit()
}

// PackageTags returns every stored tag, ordered by package and tag.
func (s *Store) PackageTags(ctx context.Context) ([]packages.Tag, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT manager, id, tag, source FROM package_tags ORDER BY manager, id, tag`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []packages.Tag
	for rows.Next() {
		var t packages.Tag
		if err := rows.Scan(&t.Manager, &t.ID, &t.Tag, &t.Source); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TagsByKey groups tags by packages.MetaKey.
func TagsByKey(tags []packages.Tag) map[string][]string {
	out := map[string][]string{}
	for _, t := range tags {
		k := packages.MetaKey(t.Manager, t.ID)
		out[k] = append(out[k], t.Tag)
	}
	return out
}

// AddPackageTags stores tags. A tag the package already has keeps its
// original source, so a user tag is never downgraded to an AI one.
func (s *Store) AddPackageTags(ctx context.Context, tags []packages.Tag) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO package_tags(manager, id, tag, source) VALUES (?, ?, ?, ?)`,
			t.Manager, t.ID, t.Tag, t.Source); err != nil {
			return fmt.Errorf("add tag %s to %s: %w", t.Tag, packages.MetaKey(t.Manager, t.ID), err)
		}
	}
	return tx.Commit()
}

// RemovePackageTags deletes tags from one package whatever their source and
// reports how many were removed.
func (s *Store) RemovePackageTags(ctx context.Context, manager, id string, tags []string) (int, error) {
	n := 0
	for _, tag := range tags {
		res, err := s.db.ExecContext(ctx, `DELETE FROM package_tags WHERE manager=? AND id=? AND tag=?`, manager, id, tag)
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, nil
}

// ReplaceAITags swaps the AI tags of one package for tags, leaving user tags
// alone.
func (s *Store) ReplaceAITags(ctx context.Context, manager, id string, tags []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM package_tags WHERE manager=? AND id=? AND source=?`,
		manager, id, packages.TagAI); err != nil {
		return err
	}
	for _, tag := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO package_tags(manager, id, tag, source) VALUES (?, ?, ?, ?)`,
			manager, id, tag, packages.TagAI); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Setting reads a value from the meta table ("" when unset).
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting writes a value to the meta table.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
