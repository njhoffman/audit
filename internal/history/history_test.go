package history

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, body, format string
		want               []entry
	}{
		{"plain", "echo one\necho two\n", "bash", []entry{{"echo one", 1}, {"echo two", 2}}},
		{"bash timestamps", "#1700000000\necho one\necho two\n#1700000010\nls\n", "bash", []entry{{"echo one\necho two", 2}, {"ls", 5}}},
		{"zsh", ": 1700000000:0;echo one\\\necho two\n: 1700000010:0;ls\n", "zsh", []entry{{"echo one\necho two", 1}, {"ls", 3}}},
		{"zsh plain", "echo one\\\necho two\nls\n", "zsh", []entry{{"echo one\necho two", 1}, {"ls", 3}}},
		{"fish", "- cmd: echo one\\necho two\n  when: 1700000000\n- cmd: echo \\\\n\n  when: 1700000010\n", "fish", []entry{{"echo one\necho two", 1}, {`echo \n`, 3}}},
		{"empty", "", "bash", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parse(tc.body, tc.format); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestScanFindingsAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zsh_history")
	secret := "secret-pattern-value"
	body := ": 1:0;echo " + secret + "\n: 2:0;ls\n: 3:0;ls\n: 4:0;echo a\\\necho b\\\necho c\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, files, entries, errs, err := Scan(context.Background(), Options{Files: []string{path, path}, Patterns: []string{secret, "ABSENT"}, MaxLines: 3, MaxBytes: 1 << 20})
	if err != nil || len(errs) != 0 || files != 1 || entries != 4 || len(fs) != 3 {
		t.Fatalf("%+v, %d %d %v %v", fs, files, entries, errs, err)
	}
	want := map[string]int{"history.duplicates": 3, "history.multiline": 4, "history.pattern": 1}
	for _, f := range fs {
		if !strings.HasSuffix(f.Details[0], fmt.Sprintf(":%d", want[f.Check])) {
			t.Errorf("unexpected location: %+v", f)
		}
	}
	encoded, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "echo a") {
		t.Fatalf("command text leaked: %s", encoded)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != body {
		t.Fatal("history changed", err)
	}
}

func TestScanLimitsMissingAndCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bash_history")
	if err := os.WriteFile(path, []byte("long command\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, files, _, errs, err := Scan(context.Background(), Options{Files: []string{path, dir, filepath.Join(dir, "missing")}, MaxBytes: 2, MaxLines: 10})
	if err != nil || files != 0 || len(errs) != 2 {
		t.Fatalf("%d %v %v", files, errs, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := Scan(ctx, Options{Files: []string{path}}); err != context.Canceled {
		t.Fatal(err)
	}
}
