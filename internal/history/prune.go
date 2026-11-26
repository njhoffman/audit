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
	"syscall"
	"time"

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
		if !slices.Contains(Categories, category) {
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
		rs := records(body, o.format(path, body))
		plan := PrunePlan{Path: path, original: body, info: info, Lines: []int{}}
		var out bytes.Buffer
		if len(rs) > 0 {
			out.Write(body[:rs[0].start])
		} else {
			out.Write(body)
		}
		allowed := func(category, check, subject string) bool {
			return slices.Contains(categories, category) && !ig.Ignored(finding.Finding{Command: "history", Check: check, Subject: subject})
		}
		c := newClassifier(o)
		for _, r := range rs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			m := c.classify(r.entry)
			remove := (m.duplicate && allowed(CategoryDuplicates, "history.duplicates", path)) ||
				(m.multiline && allowed(CategoryMultiline, "history.multiline", path))
			for _, i := range m.patterns {
				remove = remove || allowed(CategoryPatterns, "history.pattern", patternSubject(path, i))
			}
			if remove {
				plan.Remove++
				plan.Lines = append(plan.Lines, r.line)
			} else {
				plan.Keep++
				out.Write(body[r.start:r.end])
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

// zshLockStale is the age at which zsh itself breaks a $HISTFILE.LOCK.
const zshLockStale = 10 * time.Second

// beforeRename runs between the last unchanged check and the rename; tests
// use it to write into that window.
var beforeRename = func(string) {}

// ApplyPrune checks that the preview still matches, writes a private backup
// beside the history, then atomically replaces it while holding the locks
// shells take, and syncs the directory so the rename survives a crash.
//
// The locks, as measured against zsh 5.9: $HISTFILE.LOCK, which zsh takes by
// default (it waits for one up to 10 seconds old, then breaks it); an fcntl
// write lock, which zsh takes with HIST_FCNTL_LOCK; and a flock against
// other audit runs (zsh ignores flock). A zsh blocked on either lock opens
// the file by name once it gets it, so it appends to the new file.
//
// bash takes no lock. Lines it appends to the old file between the last
// check and the rename are copied onto the new file afterwards; a write in
// the instant of that copy, or a bash that rewrites the whole file on exit
// (histappend off), can still undo or lose lines, so close other sessions
// first.
func ApplyPrune(ctx context.Context, p PrunePlan) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.Remove == 0 || p.info == nil {
		return "", errors.New("empty history prune plan")
	}
	return replaceHistory(ctx, p.Path, p.info, p.original, p.replacement)
}

// replaceHistory replaces the history at path, which must still hold
// original (with info's identity, mode and size), with replacement: under
// the locks described at ApplyPrune, after writing a private backup beside
// it. It returns the backup's path.
func replaceHistory(ctx context.Context, path string, pinfo os.FileInfo, original, replacement []byte) (string, error) {
	p := struct {
		Path                  string
		info                  os.FileInfo
		original, replacement []byte
	}{path, pinfo, original, replacement}
	unlockZsh, err := zshLock(p.Path)
	if err != nil {
		return "", err
	}
	defer unlockZsh()
	f, err := os.OpenFile(p.Path, os.O_RDWR|unix.O_NOFOLLOW, 0) // #nosec G304 -- configured history path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) // #nosec G115 -- file descriptors fit in int
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return "", fmt.Errorf("history is locked: %w", err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	// An open file description lock conflicts with zsh's classic fcntl lock
	// but, unlike one, is not dropped when any other descriptor this process
	// has on the file is closed.
	wr := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart}
	if err := unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &wr); err != nil {
		return "", fmt.Errorf("history is locked by a shell (fcntl): %w", err)
	}
	defer func() {
		un := unix.Flock_t{Type: unix.F_UNLCK, Whence: io.SeekStart}
		_ = unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &un)
	}()
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
	beforeRename(p.Path)
	if err := os.Rename(tmp.Name(), p.Path); err != nil {
		return backupPath, err
	}
	if err := salvageAppended(f, int64(len(p.original)), p.Path); err != nil {
		return backupPath, fmt.Errorf("history replaced, but lines written during the replace may be lost (they are in %s only if written before it): %w", backupPath, err)
	}
	if err := syncDir(dir); err != nil {
		return backupPath, err
	}
	return backupPath, nil
}

// zshLock takes $HISTFILE.LOCK the way zsh does, so a zsh in its default
// locking mode waits. One younger than zshLockStale is a live lock; an older
// one is broken, as zsh would. The returned func removes it.
func zshLock(path string) (func(), error) {
	lock := path + ".LOCK"
	for range 2 {
		l, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600) // #nosec G304 -- beside the configured history
		if err == nil {
			_, _ = fmt.Fprintf(l, "%d\n", os.Getpid())
			_ = l.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, serr := os.Lstat(lock)
		if serr != nil {
			continue // removed meanwhile; try again
		}
		if age := time.Since(info.ModTime()); age < zshLockStale {
			return nil, fmt.Errorf("history is locked by a shell (%s, %s old); try again", lock, age.Round(time.Second))
		}
		if err := os.Remove(lock); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not take %s.LOCK", path)
}

// salvageAppended copies onto the history at path whatever a lock-ignoring
// writer appended to the old file (still open as old) past size before the
// rename moved it aside.
func salvageAppended(old *os.File, size int64, path string) error {
	info, err := old.Stat()
	if err != nil || info.Size() <= size {
		return err
	}
	extra := make([]byte, info.Size()-size)
	if _, err := old.ReadAt(extra, size); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0) // #nosec G304 -- configured history path
	if err != nil {
		return err
	}
	if _, err := f.Write(extra); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the history's directory
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
