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

func TestLockIsReusedByExecute(t *testing.T) {
	old := lockPoll
	lockPoll = 10 * time.Millisecond
	t.Cleanup(func() { lockPoll = old })
	e, _ := engine(t)
	e.LockDir = t.TempDir()
	ctx, unlock, err := e.Lock(context.Background(), "system", &phases{})
	if err != nil {
		t.Fatal(err)
	}
	// A scan under the action's context does not wait on its own lock.
	s := &countingScanner{fakeScanner: &fakeScanner{command: "system"}}
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := e.Execute(sctx, s, &phases{}); err != nil || s.n.Load() != 1 {
		t.Fatalf("scan under the held lock: %v, %d scans", err, s.n.Load())
	}
	// Locking again under it is a no-op; another command still locks.
	inner, innerUnlock, err := e.Lock(ctx, "system", &phases{})
	if err != nil || inner != ctx {
		t.Fatalf("relock: %v", err)
	}
	innerUnlock()
	both, otherUnlock, err := e.Lock(ctx, "repos", &phases{})
	if err != nil || !held(both, "system") || !held(both, "repos") {
		t.Fatalf("second command: %v", err)
	}
	otherUnlock()

	// Another process's scan (a context without the lock) waits for it.
	rep := &phases{}
	wctx, wcancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer wcancel()
	if _, err := e.Execute(wctx, s, rep); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("scan outside the action: %v", err)
	}
	if !rep.has("waiting for another audit system scan or action") {
		t.Errorf("phases %v", rep.seen)
	}
	unlock()
	if _, err := e.Execute(context.Background(), s, &phases{}); err != nil {
		t.Fatalf("after the action: %v", err)
	}
}

func TestLockWithoutDir(t *testing.T) {
	e, _ := engine(t)
	ctx := context.Background()
	got, unlock, err := e.Lock(ctx, "system", nil)
	if err != nil || got != ctx {
		t.Fatalf("no LockDir: %v", err)
	}
	unlock()
}
