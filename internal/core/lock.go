package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/njhoffman/audit/internal/progress"
)

// lockPoll is how often a scan waiting for another one of its command
// tries the lock again.
var lockPoll = 250 * time.Millisecond

// lockCommand takes the scan lock of command under dir, waiting while
// another audit process scans the same command (the schedule timer and a
// scan from the terminal, say), so the two do not both do the full work
// and reconcile the tasks from what each read before the other saved. The
// lock is a flock, released when the process exits however it ends. While
// it waits, rep says so; ctx ends the wait. It returns the release.
func lockCommand(ctx context.Context, dir, command string, rep progress.Reporter) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("scan lock: %w", err)
	}
	path := filepath.Join(dir, command+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- a fixed name in audit's own directory
	if err != nil {
		return nil, fmt.Errorf("scan lock: %w", err)
	}
	fd := int(f.Fd()) // #nosec G115 -- fd fits in int
	waiting := false
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("scan lock %s: %w", path, err)
		}
		if !waiting {
			waiting = true
			rep.Phase("waiting for another audit "+command+" scan to finish", 0)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
