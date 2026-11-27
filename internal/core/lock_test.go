package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/progress"
)

// countingScanner counts its scans atomically, since the lock it waits on
// is not a Go synchronization the race detector knows.
type countingScanner struct {
	*fakeScanner
	n atomic.Int32
}

func (c *countingScanner) Scan(context.Context, progress.Reporter) (*Outcome, error) {
	c.n.Add(1)
	return &Outcome{}, nil
}

// phases records the phases a reporter is told.
type phases struct {
	mu   sync.Mutex
	seen []string
}

func (p *phases) Phase(name string, _ int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, name)
}
func (*phases) Step(string) {}
func (*phases) Done()       {}

func (p *phases) has(sub string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.seen {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestLockCommand(t *testing.T) {
	old := lockPoll
	lockPoll = 10 * time.Millisecond
	t.Cleanup(func() { lockPoll = old })
	dir := t.TempDir() + "/locks"
	ctx := context.Background()
	release, err := lockCommand(ctx, dir, "system", &phases{})
	if err != nil {
		t.Fatal(err)
	}
	// Another command's lock is free.
	other, err := lockCommand(ctx, dir, "repos", &phases{})
	if err != nil {
		t.Fatal(err)
	}
	other()

	// The same command waits, says so, and gives up with its context.
	rep := &phases{}
	cctx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if _, err := lockCommand(cctx, dir, "system", rep); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("held lock: %v", err)
	}
	if !rep.has("waiting for another audit system scan") {
		t.Errorf("phases %v", rep.seen)
	}

	// Released, the waiter gets it.
	done := make(chan error, 1)
	go func() {
		r, err := lockCommand(ctx, dir, "system", &phases{})
		if err == nil {
			r()
		}
		done <- err
	}()
	time.Sleep(30 * time.Millisecond)
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter never got the released lock")
	}
}

func TestExecuteTakesTheLock(t *testing.T) {
	old := lockPoll
	lockPoll = 10 * time.Millisecond
	t.Cleanup(func() { lockPoll = old })
	e, _ := engine(t)
	e.LockDir = t.TempDir()
	ctx := context.Background()
	release, err := lockCommand(ctx, e.LockDir, "system", &phases{})
	if err != nil {
		t.Fatal(err)
	}
	s := &countingScanner{fakeScanner: &fakeScanner{command: "system"}}
	rep := &phases{}
	done := make(chan error, 1)
	go func() {
		_, err := e.Execute(ctx, s, rep)
		done <- err
	}()
	time.Sleep(60 * time.Millisecond)
	if s.n.Load() != 0 || !rep.has("waiting for another audit system scan") {
		t.Fatalf("scanned while another held the lock: %d scans", s.n.Load())
	}
	release()
	if err := <-done; err != nil || s.n.Load() != 1 {
		t.Fatalf("after the release: %v, %d scans", err, s.n.Load())
	}
	// Execute released its own lock.
	r, err := lockCommand(ctx, e.LockDir, "system", &phases{})
	if err != nil {
		t.Fatal(err)
	}
	r()
}
