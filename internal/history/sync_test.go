package history

import (
	"context"
	"database/sql"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// histdb writes a zsh-histdb database holding commands, one second apart.
func histdb(t *testing.T, commands ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zsh-history.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE commands (id INTEGER PRIMARY KEY, argv TEXT)",
		"CREATE TABLE places (id INTEGER PRIMARY KEY, host TEXT)",
		"CREATE TABLE history (id INTEGER PRIMARY KEY, session INTEGER, command_id INTEGER, place_id INTEGER, start_time INTEGER, duration INTEGER)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range commands {
		if _, err := db.Exec("INSERT INTO commands (id, argv) VALUES (?, ?)", i+1, c); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO history (session, command_id, place_id, start_time, duration) VALUES (1, ?, 1, ?, 2)", i+1, 1000+i); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMetafyMatchesZsh(t *testing.T) {
	// Bytes as zsh 5.9 wrote them for the same commands.
	for in, want := range map[string]string{
		"echo → é": "echo \xe2\x83\xa6\x83\xb2 \xc3\xa9",
		"ă":        "\xc4\x83\xa3",
		"plain":    "plain",
		"\xc2\xa2": "\xc2\x83\x82", // 0xa2 is the last escaped byte
		"\xc2\xa3": "\xc2\xa3",
	} {
		if got := metafy(in); got != want {
			t.Errorf("metafy(%q) = % x, want % x", in, got, want)
		}
	}
}

func TestUnmetafyAndPatternMatch(t *testing.T) {
	for _, in := range []string{"echo → ă é", "plain", "\xc2\xa2"} {
		if got := unmetafy(metafy(in)); got != in {
			t.Errorf("round trip %q: %q", in, got)
		}
	}
	// A zsh history as zsh writes it: a non-ASCII pattern matches its record.
	path := filepath.Join(t.TempDir(), ".zsh_history")
	body := ": 1:0;" + metafy("ssh → prod") + "\n: 2:0;ls\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	plans, err := PlanPrune(context.Background(), Options{Files: []string{path}, Patterns: []string{"→ prod"}, MaxBytes: 1 << 20, MaxLines: 10}, []string{"patterns"}, nil)
	if err != nil || len(plans) != 1 || plans[0].Remove != 1 {
		t.Fatalf("the pattern matches the unescaped command: %+v %v", plans, err)
	}
	if _, err := ApplyPrune(context.Background(), plans[0]); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != ": 2:0;ls\n" {
		t.Errorf("the record's escaped bytes go with it: %q", got)
	}
}

func TestSyncRefusalsAndForce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), ".zsh_history")
	body := ": 1:0;one\n: 2:0;two\n: 3:0;three\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	empty, err := PlanSync(ctx, histdb(t), path)
	if err != nil || empty.HistDB != 0 || empty.File != 3 || !strings.Contains(empty.Refusal, "no entries") {
		t.Fatalf("empty histdb: %+v %v", empty, err)
	}
	if _, err := ApplySync(ctx, empty, true); err == nil {
		t.Fatal("an empty histdb never replaces the file, even with force")
	}

	fewer, err := PlanSync(ctx, histdb(t, "one", "two"), path)
	if err != nil || fewer.HistDB != 2 || !strings.Contains(fewer.Refusal, "drop the 1") {
		t.Fatalf("fewer: %+v %v", fewer, err)
	}
	if _, err := ApplySync(ctx, fewer, false); err == nil {
		t.Fatal("fewer histdb entries than the file need force")
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Fatal("a refused sync changed the file")
	}
	backup, err := ApplySync(ctx, fewer, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != ": 1000:2;one\n: 1001:2;two\n" {
		t.Errorf("forced sync: %q", got)
	}
	if got, _ := os.ReadFile(backup); string(got) != body {
		t.Errorf("backup %s holds %q", backup, got)
	}
	if info, _ := os.Stat(path); !info.ModTime().After(old.Add(time.Minute)) {
		t.Error("the new file keeps a fresh mtime; restoring the old one hides the change from shells")
	}

	more, err := PlanSync(ctx, histdb(t, "a", "multi\nline", "c", "d"), path)
	if err != nil || more.Refusal != "" {
		t.Fatalf("more histdb entries need no force: %+v %v", more, err)
	}
	if _, err := ApplySync(ctx, more, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), ": 1001:2;multi\\\nline\n") {
		t.Errorf("multiline entries keep zsh's backslash continuation: %q", got)
	}
}

// A file sync writes reads back in real zsh as the commands histdb holds.
func TestSyncRoundTripsThroughZsh(t *testing.T) {
	zsh, err := osexec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not installed")
	}
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, ".zsh_history")
	if err := os.WriteFile(path, []byte(": 1:0;x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "echo → ă é"
	p, err := PlanSync(ctx, histdb(t, want), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplySync(ctx, p, false); err != nil {
		t.Fatal(err)
	}
	c := osexec.Command(zsh, "-fic", "HISTFILE="+path+"; HISTSIZE=10; SAVEHIST=10; fc -R; fc -ln -1") // #nosec G204 -- test
	c.Dir = dir
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("zsh reads back %q (% x), want %q", got, got, want)
	}
}
