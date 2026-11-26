package history

import (
	"bufio"
	"context"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// planDup writes body to a history and plans removing its duplicates.
func planDup(t *testing.T, name, body string) PrunePlan {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanPrune(context.Background(), Options{Files: []string{path}, MaxBytes: 1 << 20, MaxLines: 10}, []string{"duplicates"}, nil)
	if err != nil || len(plans) != 1 {
		t.Fatalf("%+v %v", plans, err)
	}
	return plans[0]
}

func setBeforeRename(t *testing.T, f func(string)) {
	t.Helper()
	old := beforeRename
	beforeRename = f
	t.Cleanup(func() { beforeRename = old })
}

func TestPruneSalvagesAppendBeforeRename(t *testing.T) {
	p := planDup(t, ".bash_history", "ls\nls\npwd\n")
	// A writer that takes no lock (bash) appends in the last window.
	setBeforeRename(t, func(path string) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("late\n")
		_ = f.Close()
	})
	if _, err := ApplyPrune(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p.Path); string(got) != "ls\npwd\nlate\n" {
		t.Fatalf("the late line is kept after the pruned history: %q", got)
	}
	if _, err := os.Lstat(p.Path + ".LOCK"); !os.IsNotExist(err) {
		t.Errorf("the .LOCK file is removed afterwards: %v", err)
	}
}

func TestPruneHonorsZshDotLock(t *testing.T) {
	p := planDup(t, ".zsh_history", "ls\nls\n")
	lock := p.Path + ".LOCK"
	if err := os.WriteFile(lock, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPrune(context.Background(), p); err == nil || !strings.Contains(err.Error(), ".LOCK") {
		t.Fatalf("a live .LOCK must stop the prune: %v", err)
	}
	if got, _ := os.ReadFile(p.Path); string(got) != "ls\nls\n" {
		t.Fatalf("history changed under a live lock: %q", got)
	}
	if _, err := os.Lstat(lock); err != nil {
		t.Fatal("someone else's live lock must be left alone")
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPrune(context.Background(), p); err != nil {
		t.Fatalf("a stale .LOCK is broken, as zsh does: %v", err)
	}
	if _, err := os.Lstat(lock); !os.IsNotExist(err) {
		t.Errorf("lock left behind: %v", err)
	}
}

// TestHelperHoldFcntlLock is run as a child process by
// TestPruneHonorsFcntlLock: fcntl locks conflict only between processes.
func TestHelperHoldFcntlLock(t *testing.T) {
	path := os.Getenv("AUDIT_TEST_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("locked\n")
	_, _ = io.Copy(io.Discard, os.Stdin) // hold until the parent closes stdin
}

func TestPruneHonorsFcntlLock(t *testing.T) {
	p := planDup(t, ".zsh_history", "ls\nls\n")
	cmd := osexec.Command(os.Args[0], "-test.run=^TestHelperHoldFcntlLock$") // #nosec G204 -- the test binary
	cmd.Env = append(os.Environ(), "AUDIT_TEST_HOLD_LOCK="+p.Path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "locked\n" {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("helper did not take the lock: %q", line)
	}
	_, err = ApplyPrune(context.Background(), p)
	_ = stdin.Close()
	_ = cmd.Wait()
	if err == nil || !strings.Contains(err.Error(), "fcntl") {
		t.Fatalf("an fcntl lock (zsh HIST_FCNTL_LOCK) must stop the prune: %v", err)
	}
	if _, err := os.Lstat(p.Path + ".LOCK"); !os.IsNotExist(err) {
		t.Errorf("our .LOCK is removed when the prune is refused: %v", err)
	}
	if _, err := ApplyPrune(context.Background(), p); err != nil {
		t.Fatalf("once released: %v", err)
	}
}

// A real zsh that saves while a prune runs waits for it and appends to the
// new file, in both of its locking modes.
func TestPruneWithRealZshWriter(t *testing.T) {
	zsh, err := osexec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not installed")
	}
	for _, mode := range []string{"", "setopt HIST_FCNTL_LOCK; "} {
		t.Run("mode="+strings.TrimSpace(mode), func(t *testing.T) {
			p := planDup(t, ".zsh_history", "ls\nls\npwd\n")
			var done chan error
			setBeforeRename(t, func(path string) {
				script := "HISTFILE=" + path + "; SAVEHIST=100; HISTSIZE=100; " + mode + "print -s from-zsh; fc -AI"
				c := osexec.Command(zsh, "-fic", script) // #nosec G204 -- test
				c.Stdin, c.Dir = nil, filepath.Dir(path)
				done = make(chan error, 1)
				if err := c.Start(); err != nil {
					t.Fatal(err)
				}
				go func() { done <- c.Wait() }()
				go func() { time.Sleep(20 * time.Second); _ = c.Process.Kill() }() // interactive zsh ignores SIGTERM
				// Give zsh time to reach its lock wait.
				time.Sleep(500 * time.Millisecond)
				if got, _ := os.ReadFile(path); strings.Contains(string(got), "from-zsh") {
					t.Error("zsh wrote while the prune held its locks")
				}
			})
			if _, err := ApplyPrune(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("zsh: %v", err)
			}
			if got, _ := os.ReadFile(p.Path); string(got) != "ls\npwd\nfrom-zsh\n" {
				t.Fatalf("zsh's line belongs after the pruned history: %q", got)
			}
		})
	}
}
