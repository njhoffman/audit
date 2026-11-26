package history

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Backup is one copy prune, sync or restore made of a history before
// replacing it (.NAME.audit-backup-* beside it). It holds the old commands,
// removed secrets included; only its path, size and record count are read
// out of it here.
type Backup struct {
	Path      string    `json:"path"`
	Of        string    `json:"of"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	Records   int       `json:"records"`
}

// backupGlob matches the backups of the history at path.
func backupGlob(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".audit-backup-*")
}

// ListBackups finds the backups of every configured history, newest first
// within each history, in o.Files order. Files that are not regular or not
// the user's are skipped, since audit did not write them.
func ListBackups(o Options) ([]Backup, error) {
	var out []Backup
	seen := map[string]bool{}
	for _, path := range o.Files {
		if seen[path] {
			continue
		}
		seen[path] = true
		matches, err := filepath.Glob(backupGlob(path))
		if err != nil {
			return nil, err
		}
		var bs []Backup
		for _, m := range matches {
			info, err := os.Lstat(m)
			if err != nil || !ownRegular(info) {
				continue
			}
			b := Backup{Path: m, Of: path, Size: info.Size(), CreatedAt: info.ModTime()}
			if body, err := readBackup(m, o.MaxBytes); err == nil {
				b.Records = len(parse(string(body), o.format(path, body)))
			}
			bs = append(bs, b)
		}
		sort.SliceStable(bs, func(i, j int) bool { return bs[i].CreatedAt.After(bs[j].CreatedAt) })
		out = append(out, bs...)
	}
	return out, nil
}

func ownRegular(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && ok && st.Uid == uint32(os.Getuid()) // #nosec G115 -- user IDs are nonnegative
}

func readBackup(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a backup found beside a configured history
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("exceeds shell_history.max_mb")
	}
	return body, nil
}

// SelectBackups picks the backups to remove: those older than olderThan
// (0: no age limit) and, per history, all but the newest keep (0: no count
// limit). With neither limit nothing is picked. bs is ListBackups' order.
func SelectBackups(bs []Backup, olderThan time.Duration, keep int, now time.Time) []Backup {
	if olderThan <= 0 && keep <= 0 {
		return nil
	}
	var out []Backup
	rank := map[string]int{}
	for _, b := range bs {
		rank[b.Of]++
		if (olderThan > 0 && now.Sub(b.CreatedAt) > olderThan) || (keep > 0 && rank[b.Of] > keep) {
			out = append(out, b)
		}
	}
	return out
}

// RemoveBackups deletes bs, rechecking each is still a regular file of the
// user's, and returns one error line per failure.
func RemoveBackups(bs []Backup) []string {
	var errs []string
	for _, b := range bs {
		info, err := os.Lstat(b.Path)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("%s: %v", b.Path, err))
		case !ownRegular(info):
			errs = append(errs, b.Path+": no longer a regular file of yours; left alone")
		default:
			if err := os.Remove(b.Path); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", b.Path, err))
			}
		}
	}
	return errs
}

// RestorePlan describes putting a backup back over its history, by counts
// only: Missing are records in the backup the current file lacks (they
// come back), Extra are records only the current file has (they go).
type RestorePlan struct {
	Path        string `json:"path"`
	Backup      string `json:"backup"`
	Current     int    `json:"current_records"`
	FromBackup  int    `json:"backup_records"`
	Missing     int    `json:"missing"`
	Extra       int    `json:"extra"`
	original    []byte
	replacement []byte
	info        os.FileInfo
}

// PlanRestore reads backup (which must be one of a configured history's)
// and the current history and counts what restoring it would change.
func PlanRestore(o Options, backup string) (RestorePlan, error) {
	backup = filepath.Clean(backup)
	var of string
	for _, path := range o.Files {
		if ok, _ := filepath.Match(backupGlob(path), backup); ok {
			of = path
		}
	}
	if of == "" {
		return RestorePlan{}, fmt.Errorf("%s is not a backup of a configured history (shell_history.files)", backup)
	}
	binfo, err := os.Lstat(backup)
	if err != nil {
		return RestorePlan{}, err
	}
	if !ownRegular(binfo) {
		return RestorePlan{}, fmt.Errorf("%s is not a regular file of yours", backup)
	}
	body, err := readBackup(backup, o.MaxBytes)
	if err != nil {
		return RestorePlan{}, fmt.Errorf("%s: %w", backup, err)
	}
	info, err := os.Lstat(of)
	if err != nil {
		return RestorePlan{}, err
	}
	if err := safeHistory(info); err != nil {
		return RestorePlan{}, fmt.Errorf("%s: %w", of, err)
	}
	current, err := readBackup(of, o.MaxBytes)
	if err != nil {
		return RestorePlan{}, fmt.Errorf("%s: %w", of, err)
	}
	format := o.format(of, current)
	count := func(es []entry) map[string]int {
		m := map[string]int{}
		for _, e := range es {
			m[strings.TrimSpace(e.text)]++
		}
		return m
	}
	be, ce := parse(string(body), format), parse(string(current), format)
	bm, cm := count(be), count(ce)
	p := RestorePlan{Path: of, Backup: backup, Current: len(ce), FromBackup: len(be),
		original: current, replacement: body, info: info}
	for k, n := range bm {
		p.Missing += max(0, n-cm[k])
	}
	for k, n := range cm {
		p.Extra += max(0, n-bm[k])
	}
	return p, nil
}

// ApplyRestore replaces the history with the backup under the same checks
// and locks as prune; the current file is backed up first, so a restore
// can itself be undone. It returns that new backup's path.
func ApplyRestore(ctx context.Context, p RestorePlan) (string, error) {
	if p.info == nil {
		return "", errors.New("restore plan was not made by PlanRestore")
	}
	return replaceHistory(ctx, p.Path, p.info, p.original, p.replacement)
}
