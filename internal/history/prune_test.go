package history

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrunePreservesRecords(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{".zsh_history", ": 1:0;echo one\\\necho two\n: 2:0;ls\n: 3:0;echo one\\\necho two\n: 4:0;pwd", ": 1:0;echo one\\\necho two\n: 2:0;ls\n: 4:0;pwd"},
		{".bash_history", "#100\necho one\necho two\n#200\nls\n#300\necho one\necho two\n#400\npwd\n", "#100\necho one\necho two\n#200\nls\n#400\npwd\n"},
		{"fish_history", "- cmd: echo one\\necho two\n  when: 1\n  paths:\n    - /tmp\n- cmd: ls\n  when: 2\n- cmd: echo one\\necho two\n  when: 3\n- cmd: pwd\n  when: 4\n", "- cmd: echo one\\necho two\n  when: 1\n  paths:\n    - /tmp\n- cmd: ls\n  when: 2\n- cmd: pwd\n  when: 4\n"},
		{"plain", "\nls\npwd\nls\n", "\nls\npwd\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			plans, err := PlanPrune(context.Background(), Options{Files: []string{path}, MaxBytes: 1 << 20, MaxLines: 10}, []string{"duplicates"}, nil)
			if err != nil || len(plans) != 1 || plans[0].Remove != 1 {
				t.Fatalf("%+v %v", plans, err)
			}
			backup, err := ApplyPrune(context.Background(), plans[0])
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, want %q: %v", got, tc.want, err)
			}
			original, err := os.ReadFile(backup)
			if err != nil || string(original) != tc.body {
				t.Fatalf("bad backup: %q %v", original, err)
			}
			info, err := os.Stat(backup)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("backup permissions", err)
			}
			info, err = os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("history permissions", err)
			}
		})
	}
}

func TestPruneCategoriesIgnorePrivacyAndNoLimitOnRemovals(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zsh_history")
	body := ": 1:0;private-pattern\n: 2:0;one\\\ntwo\\\nthree\n" + strings.Repeat(": 3:0;ls\n", 150)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Options{Files: []string{path, path}, Patterns: []string{"private-pattern"}, MaxBytes: 1 << 20, MaxLines: 3}
	plans, err := PlanPrune(context.Background(), o, []string{"duplicates", "multiline", "patterns"}, nil)
	if err != nil || len(plans) != 1 || plans[0].Remove != 151 || plans[0].Keep != 1 {
		t.Fatalf("%+v %v", plans, err)
	}
	preview, err := json.Marshal(plans)
	if err != nil || strings.Contains(string(preview), "private-pattern") || strings.Contains(string(preview), "three") {
		t.Fatalf("preview leaked text: %s %v", preview, err)
	}
	plans, err = PlanPrune(context.Background(), o, []string{"patterns", "multiline"}, []string{"history.pattern"})
	if err != nil || len(plans) != 1 || plans[0].Remove != 1 {
		t.Fatalf("ignore rules: %+v %v", plans, err)
	}
	if _, err := PlanPrune(context.Background(), o, []string{"typo"}, nil); err == nil {
		t.Fatal("unknown category accepted")
	}
}

func TestPruneRefusesChangedOrLinkedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bash_history")
	body := "ls\nls\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Options{Files: []string{path}, MaxBytes: 100, MaxLines: 10}
	plans, err := PlanPrune(context.Background(), o, []string{"duplicates"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same-size changes must also invalidate the preview.
	if err := os.WriteFile(path, []byte("ps\nps\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPrune(context.Background(), plans[0]); err == nil {
		t.Fatal("changed history overwritten")
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	o.Files = []string{link}
	if _, err := PlanPrune(context.Background(), o, []string{"duplicates"}, nil); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Link(path, path+"-hardlink"); err != nil {
		t.Fatal(err)
	}
	o.Files = []string{path}
	if _, err := PlanPrune(context.Background(), o, []string{"duplicates"}, nil); err == nil {
		t.Fatal("hardlink accepted")
	}
}

func TestPruneRefusesLockAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bash_history")
	if err := os.WriteFile(path, []byte("ls\nls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanPrune(context.Background(), Options{Files: []string{path}, MaxBytes: 100}, []string{"duplicates"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPrune(context.Background(), plans[0]); err == nil {
		t.Fatal("locked history overwritten")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ApplyPrune(ctx, plans[0]); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestPruneBashTimestampWithLeadingBlankLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bash_history")
	if err := os.WriteFile(path, []byte("#100\n\nremove\n#200\nkeep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanPrune(context.Background(), Options{Files: []string{path}, Patterns: []string{"remove"}, MaxBytes: 100}, []string{"patterns"}, nil)
	if err != nil || len(plans) != 1 {
		t.Fatalf("%v %v", plans, err)
	}
	if _, err := ApplyPrune(context.Background(), plans[0]); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "#200\nkeep\n" {
		t.Fatalf("orphaned timestamp: %q %v", body, err)
	}
}
