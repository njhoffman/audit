package history

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupsListSelectRemoveRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zsh_history")
	original := ": 1:0;ls\n: 2:0;ls\n: 3:0;pwd\n: 4:0;pwd\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Options{Files: []string{path, path}, MaxBytes: 1 << 20, MaxLines: 10}
	ctx := context.Background()
	prune := func() string {
		t.Helper()
		plans, err := PlanPrune(ctx, o, []string{CategoryDuplicates}, nil)
		if err != nil || len(plans) != 1 {
			t.Fatalf("%+v %v", plans, err)
		}
		b, err := ApplyPrune(ctx, plans[0])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := prune()
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(first, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(": 5:0;a\n: 6:0;a\n: 7:0;b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := prune()
	// Something else beside the history is not a backup.
	if err := os.WriteFile(filepath.Join(dir, ".zsh_history.other"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	bs, err := ListBackups(o)
	if err != nil || len(bs) != 2 || bs[0].Path != second || bs[1].Path != first || bs[1].Records != 4 || bs[0].Of != path {
		t.Fatalf("newest first, records counted: %+v %v", bs, err)
	}
	now := time.Now()
	if got := SelectBackups(bs, 0, 0, now); got != nil {
		t.Errorf("no limits pick nothing: %+v", got)
	}
	if got := SelectBackups(bs, 24*time.Hour, 0, now); len(got) != 1 || got[0].Path != first {
		t.Errorf("by age: %+v", got)
	}
	if got := SelectBackups(bs, 0, 1, now); len(got) != 1 || got[0].Path != first {
		t.Errorf("by count: %+v", got)
	}

	// Restoring the first backup brings the pruned duplicates back and
	// drops what the second file holds; the current file is backed up.
	p, err := PlanRestore(o, first)
	if err != nil || p.FromBackup != 4 || p.Current != 2 || p.Missing != 4 || p.Extra != 2 {
		t.Fatalf("restore plan: %+v %v", p, err)
	}
	made, err := ApplyRestore(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != original { // #nosec G304 -- test file
		t.Errorf("restored: %q", b)
	}
	if b, _ := os.ReadFile(made); string(b) != ": 5:0;a\n: 7:0;b\n" { // #nosec G304 -- test file
		t.Errorf("the replaced file is backed up: %q", b)
	}

	if errs := RemoveBackups(SelectBackups(bs, 24*time.Hour, 0, now)); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Error("the old backup is removed")
	}
	if errs := RemoveBackups([]Backup{{Path: first}}); len(errs) != 1 {
		t.Errorf("removing a missing backup is reported: %v", errs)
	}

	if _, err := PlanRestore(o, filepath.Join(dir, ".zsh_history.other")); err == nil || !strings.Contains(err.Error(), "not a backup of a configured history") {
		t.Errorf("not a backup: %v", err)
	}
	if _, err := ApplyRestore(ctx, RestorePlan{}); err == nil {
		t.Error("a hand-made plan is refused")
	}
}
