package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/njhoffman/audit/internal/finding"
)

// PrunePlan describes whole records removed from one history file. Raw text
// stays private in memory and is never serialized.
type PrunePlan struct {
	Path        string `json:"path"`
	Remove      int    `json:"remove"`
	Keep        int    `json:"keep"`
	Lines       []int  `json:"lines"`
	original    []byte
	replacement []byte
	info        os.FileInfo
}

// PlanPrune rereads current files, applying the same checks as Scan. Categories
// are duplicates, multiline and patterns; duplicates retain the first entry.
// Ignore rules suppress removal, and locations are never taken from old runs.
func PlanPrune(ctx context.Context, o Options, categories, ignore []string) ([]PrunePlan, error) {
	for _, category := range categories {
		if !slices.Contains([]string{"duplicates", "multiline", "patterns"}, category) {
			return nil, fmt.Errorf("unknown history prune category %q", category)
		}
	}
	ig := finding.NewIgnorer(ignore)
	var plans []PrunePlan
	seenPaths := map[string]bool{}
	for _, path := range o.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seenPaths[path] {
			continue
		}
		seenPaths[path] = true
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := safeHistory(info); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		f, err := os.Open(path) // #nosec G304 -- configured history path
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(f, o.MaxBytes+1))
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > o.MaxBytes {
			return nil, fmt.Errorf("%s: exceeds shell_history.max_mb", path)
		}
		format := formatOf(path, body)
		es := parse(string(body), format)
		// Map command locations back to byte ranges, including bash timestamps
		// and fish metadata. Retained records are copied byte for byte.
		lines := strings.SplitAfter(string(body), "\n")
		offsets := make([]int, len(lines)+1)
		for i, line := range lines {
			offsets[i+1] = offsets[i] + len(line)
		}
		starts := make([]int, len(es)+1)
		for i, e := range es {
			line := e.line - 1
			if format == "bash" {
				candidate := line
				for candidate > 0 && strings.TrimSuffix(strings.TrimSuffix(lines[candidate-1], "\n"), "\r") == "" {
					candidate--
				}
				if candidate > 0 && timestamp.MatchString(strings.TrimSuffix(lines[candidate-1], "\n")) {
					line = candidate - 1
				}
			}
			starts[i] = offsets[line]
		}
		starts[len(es)] = len(body)
		plan := PrunePlan{Path: path, original: body, info: info, Lines: []int{}}
		var out bytes.Buffer
		if len(es) > 0 {
			out.Write(body[:starts[0]])
		} else {
			out.Write(body)
		}
		seen := map[string]bool{}
		for i, e := range es {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			text := strings.TrimSpace(e.text)
			remove := false
			allowed := func(category, check, subject string) bool {
				return slices.Contains(categories, category) && !ig.Ignored(finding.Finding{Command: "history", Check: check, Subject: subject})
			}
			if text != "" {
				remove = seen[text] && allowed("duplicates", "history.duplicates", path)
				seen[text] = true
				remove = remove || (strings.Count(e.text, "\n")+1 >= o.MaxLines && allowed("multiline", "history.multiline", path))
				for j, pattern := range o.Patterns {
					if pattern != "" && strings.Contains(e.text, pattern) && allowed("patterns", "history.pattern", fmt.Sprintf("%s:pattern-%d", path, j+1)) {
						remove = true
					}
				}
			}
			if remove {
				plan.Remove++
				plan.Lines = append(plan.Lines, e.line)
			} else {
				plan.Keep++
				out.Write(body[starts[i]:starts[i+1]])
			}
		}
		if plan.Remove > 0 {
			plan.replacement = out.Bytes()
			plans = append(plans, plan)
		}
	}
	return plans, nil
}

func safeHistory(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("pruning requires a regular file, not a symlink")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
		return errors.New("pruning requires a file owned by you with no hard links")
	} // #nosec G115 -- user IDs are nonnegative
	return nil
}

// ApplyPrune checks that the preview still matches, writes a private backup
// beside the history, then atomically replaces it while holding an advisory lock.
// A shell that ignores locks may still write later; close other sessions first.
func ApplyPrune(ctx context.Context, p PrunePlan) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.Remove == 0 || p.info == nil {
		return "", errors.New("empty history prune plan")
	}
	f, err := os.OpenFile(p.Path, os.O_RDWR|unix.O_NOFOLLOW, 0) // #nosec G304 -- configured history path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return "", fmt.Errorf("history is locked: %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	unchanged := func() error {
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(p.info, opened) {
			return errors.New("history changed after preview; run prune again")
		}
		info, err := os.Lstat(p.Path)
		if err != nil {
			return err
		}
		if err := safeHistory(info); err != nil {
			return err
		}
		if !os.SameFile(p.info, info) || info.Mode() != p.info.Mode() || info.Size() != int64(len(p.original)) {
			return errors.New("history changed after preview; run prune again")
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(f, int64(len(p.original))+1))
		if err != nil {
			return err
		}
		if sha256.Sum256(body) != sha256.Sum256(p.original) {
			return errors.New("history changed after preview; run prune again")
		}
		return nil
	}
	if err := unchanged(); err != nil {
		return "", err
	}
	dir := filepath.Dir(p.Path)
	backup, err := os.CreateTemp(dir, "."+filepath.Base(p.Path)+".audit-backup-*")
	if err != nil {
		return "", err
	}
	backupPath := backup.Name()
	if _, err = backup.Write(p.original); err == nil {
		err = backup.Sync()
	}
	closeErr := backup.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(backupPath)
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".audit-history-*")
	if err != nil {
		return backupPath, err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(p.replacement); err != nil {
		return backupPath, err
	}
	if err := tmp.Chmod(p.info.Mode().Perm()); err != nil {
		return backupPath, err
	}
	if err := tmp.Sync(); err != nil {
		return backupPath, err
	}
	if err := tmp.Close(); err != nil {
		return backupPath, err
	}
	if err := ctx.Err(); err != nil {
		return backupPath, err
	}
	if err := unchanged(); err != nil {
		return backupPath, err
	}
	if err := os.Rename(tmp.Name(), p.Path); err != nil {
		return backupPath, err
	}
	return backupPath, nil
}
