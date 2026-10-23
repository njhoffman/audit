package cmd

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/run"
)

func TestHistoryPrunePreviewConfirmAndApply(t *testing.T) {
	cfgHome, _ := env(t)
	path := filepath.Join(t.TempDir(), ".bash_history")
	secret := "private-command-value"
	body := "ls\nls\n" + secret + "\npwd\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "shell_history:\n  files: [" + path + "]\n  patterns: [" + secret + "]\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runArgs(t, "history", "prune", "-N", "-j", "-O", "all")
	if r.e != nil || !strings.Contains(r.out, `"remove": 2`) || strings.Contains(r.out, secret) {
		t.Fatalf("preview: %s %v", r.out, r.e)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != body {
		t.Fatal("dry run changed history", err)
	}
	r = runArgs(t, "history", "prune")
	if r.e == nil || !strings.Contains(r.e.Error(), "--yes") {
		t.Fatal("pruned without confirmation", r.e)
	}
	for _, args := range [][]string{{"history", "prune", "-N", "-O", "all,typo"}, {"history", "prune", "-N", path + "-unknown"}} {
		if r := runArgs(t, args...); r.e == nil {
			t.Fatal("invalid arguments accepted", args)
		}
	}
	r = runArgs(t, "history", "prune", "-y", "-j", "-O", "all", path)
	var results []struct {
		Removed int    `json:"removed"`
		Backup  string `json:"backup"`
	}
	if r.e != nil || json.Unmarshal([]byte(r.out), &results) != nil || len(results) != 1 || results[0].Removed != 2 {
		t.Fatalf("prune: %s %v", r.out, r.e)
	}
	after, err = os.ReadFile(path)
	if err != nil || string(after) != "ls\npwd\n" {
		t.Fatalf("pruned history: %q %v", after, err)
	}
	backup, err := os.ReadFile(results[0].Backup)
	if err != nil || string(backup) != body {
		t.Fatal("backup missing", err)
	}
	saved := runArgs(t, "history", "-j")
	if saved.e != nil || strings.Contains(saved.out, "history.duplicates") || strings.Contains(saved.out, "history.pattern") {
		t.Fatalf("findings not reconciled: %s %v", saved.out, saved.e)
	}
}

func TestHistoryScanAndSavedReport(t *testing.T) {
	cfgHome, _ := env(t)
	path := filepath.Join(t.TempDir(), ".zsh_history")
	secret := "test-private-command"
	body := ": 1:0;" + secret + "\n: 2:0;" + secret + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "shell_history:\n  files: [" + path + "]\n  patterns: [" + secret + "]\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runArgs(t, "history", "-j"); r.e == nil {
		t.Fatal("JSON without saved run must not scan")
	}
	r := runArgs(t, "history", "-r", "-j")
	if r.e != nil {
		t.Fatal(r.e)
	}
	for _, check := range []string{"history.pattern"} {
		if !strings.Contains(r.out, check) {
			t.Fatalf("missing %s: %s", check, r.out)
		}
	}
	if strings.Contains(r.out, "history.duplicates") {
		t.Fatalf("duplicates reported as issues: %s", r.out)
	}
	if strings.Contains(r.out+r.err, secret) {
		t.Fatal("history command leaked")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := runArgs(t, "history", "-j")
	if saved.e != nil || !strings.Contains(saved.out, "history.pattern") {
		t.Fatalf("saved report not reused: %s %v", saved.out, saved.e)
	}
	listing := runArgs(t, "history", "runs", "history", "-j")
	if listing.e != nil || !strings.Contains(listing.out, `"history"`) {
		t.Fatalf("run listing: %s %v", listing.out, listing.e)
	}
	rescanned := runArgs(t, "history", "-r", "-j")
	if rescanned.e != nil || strings.Contains(rescanned.out, "history.pattern") {
		t.Fatalf("rescan did not clear findings: %s %v", rescanned.out, rescanned.e)
	}
}

func TestHistoryHistDBStatsInFreshAndSavedReports(t *testing.T) {
	cfgHome, _ := env(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".zsh_history")
	body := ": 1:0;ls\n: 2:0;ls\n: 3:0;pwd\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "histdb.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"CREATE TABLE places (id INTEGER PRIMARY KEY, host TEXT)",
		"CREATE TABLE history (place_id INTEGER, session INTEGER)",
		"INSERT INTO history VALUES (1, 42), (1, 43), (2, 44)",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO places VALUES (1, ?), (2, ?)", host, host+"-other"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := "shell_history:\n  files: [" + path + "]\n  histdb: " + dbPath + "\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"42", ""} {
		t.Setenv("SESSION", session)
		fresh := runArgs(t, "history", "-r", "-j")
		var report struct {
			Run *run.Run `json:"run"`
		}
		if fresh.e != nil || json.Unmarshal([]byte(fresh.out), &report) != nil || report.Run == nil {
			t.Fatalf("fresh: %s %v", fresh.out, fresh.e)
		}
		stats := map[string]string{}
		for _, stat := range report.Run.Stats {
			if stat.Group != "history" {
				t.Errorf("stat outside history section: %+v", stat)
			}
			stats[stat.Name] = stat.Value
		}
		want := map[string]string{"files": "1", "entries": "3", "histdb total entries": "3", "histdb this host": "2", "histdb this session": "1"}
		if session == "" {
			want["histdb this session"] = "unavailable (SESSION is not set)"
		}
		for name, value := range want {
			if stats[name] != value {
				t.Errorf("%s = %q, want %q", name, stats[name], value)
			}
		}
		if len(report.Run.Findings) != 0 {
			t.Fatalf("repeated commands produced findings: %s", fresh.out)
		}
		for _, args := range [][]string{{"history", "--report"}, {"history", "--summary"}} {
			saved := runArgs(t, args...)
			if saved.e != nil {
				t.Fatal(saved.e)
			}
			for name := range want {
				if !strings.Contains(saved.out, name) {
					t.Errorf("%v missing %s: %s", args, name, saved.out)
				}
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != body {
		t.Fatal("history changed", err)
	}
}
