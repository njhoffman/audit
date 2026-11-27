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
		want := map[string]string{"files": "1", "entries": "3", "histdb total entries": "3", "histdb this host": "2", "histdb this session": "1",
			"format " + path: "zsh"}
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

func TestHistorySyncRefusesAndForces(t *testing.T) {
	cfgHome, _ := env(t)
	dir := t.TempDir()
	// A custom name: found by its content, not by "zsh" in the name.
	path := filepath.Join(dir, ".histfile")
	if err := os.WriteFile(path, []byte(": 1:0;one\n: 2:0;two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "histdb.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE commands (id INTEGER PRIMARY KEY, argv TEXT)",
		"CREATE TABLE places (id INTEGER PRIMARY KEY, host TEXT)",
		"CREATE TABLE history (id INTEGER PRIMARY KEY, session INTEGER, command_id INTEGER, place_id INTEGER, start_time INTEGER, duration INTEGER)",
		"INSERT INTO commands VALUES (1, 'one')",
		"INSERT INTO history (session, command_id, place_id, start_time, duration) VALUES (1, 1, 1, 10, 0)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	cfg := "shell_history:\n  files: [" + path + "]\n  histdb: " + dbPath + "\n"
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runArgs(t, "history", "sync", "-y")
	if r.e == nil || !strings.Contains(r.e.Error(), "--force") || !strings.Contains(r.out, "histdb has 1 entries; "+path+" has 2") {
		t.Fatalf("fewer histdb entries are refused: %v\n%s", r.e, r.out)
	}
	r = runArgs(t, "history", "sync", "-y", "-F")
	if r.e != nil || !strings.Contains(r.out, "the previous file is in ") {
		t.Fatalf("forced: %v\n%s", r.e, r.out)
	}
	if got, _ := os.ReadFile(path); string(got) != ": 10:0;one\n" {
		t.Errorf("file: %q", got)
	}
	if r := runArgs(t, "history", "sync", "-y", "-f", filepath.Join(dir, "missing")); r.e == nil {
		t.Error("a missing --file is an error")
	}
}

func TestHistoryBackupsCommands(t *testing.T) {
	cfgHome, _ := env(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".bash_history")
	if err := os.WriteFile(path, []byte("ls\nls\npwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeCfg := func(extra string) {
		cfg := "shell_history:\n  files: [" + path + "]\n" + extra
		if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("")
	if r := runArgs(t, "history", "backups"); r.e != nil || r.out != "No history backups.\n" {
		t.Fatalf("none yet: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "history", "prune", "-y"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runArgs(t, "history", "backups", "-j")
	var bs []struct {
		Path    string `json:"path"`
		Records int    `json:"records"`
	}
	if r.e != nil || json.Unmarshal([]byte(r.out), &bs) != nil || len(bs) != 1 || bs[0].Records != 3 {
		t.Fatalf("one backup of 3 records: %v %s", r.e, r.out)
	}
	backup := bs[0].Path

	r = runArgs(t, "history", "backups", "restore", backup, "-N")
	if r.e != nil || !strings.Contains(r.out, "2 records now, 3 in the backup; restoring brings back 1 and drops 0") {
		t.Fatalf("restore preview: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "history", "backups", "restore", backup); r.e == nil || !strings.Contains(r.e.Error(), "--yes") {
		t.Errorf("restore asks first: %v", r.e)
	}
	if r := runArgs(t, "history", "backups", "restore", backup, "-y"); r.e != nil || !strings.Contains(r.out, "Restored "+path) {
		t.Fatalf("restore: %v %q", r.e, r.out)
	}
	if b, _ := os.ReadFile(path); string(b) != "ls\nls\npwd\n" { // #nosec G304 -- test file
		t.Errorf("restored body %q", b)
	}

	if r := runArgs(t, "history", "backups", "clean"); r.e == nil || !strings.Contains(r.e.Error(), "--older-than, --keep") {
		t.Errorf("clean needs a limit: %v", r.e)
	}
	r = runArgs(t, "history", "backups", "clean", "-k", "1", "-N")
	if r.e != nil || strings.Count(r.out, ".audit-backup-") != 1 {
		t.Errorf("keep 1 of 2 previews one removal: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "history", "backups", "clean", "-k", "1", "-y"); r.e != nil || !strings.Contains(r.out, "Removed 1 backup(s).") {
		t.Errorf("clean: %v %q", r.e, r.out)
	}

	// With backup_keep set, prune removes the older backups itself.
	writeCfg("  backup_keep: 1\n")
	if r := runArgs(t, "history", "prune", "-y"); r.e != nil || !strings.Contains(r.out, "Removed 1 old backup(s)") {
		t.Errorf("retention after prune: %v %q", r.e, r.out)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "..bash_history.audit-backup-*")); len(m) != 1 {
		t.Errorf("one backup left: %v", m)
	}
}

func TestHistoryOutcomesRecorded(t *testing.T) {
	cfgHome, _ := env(t)
	path := filepath.Join(t.TempDir(), ".bash_history")
	if err := os.WriteFile(path, []byte("ls\nls\nls\npwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte("shell_history:\n  files: ["+path+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runArgs(t, "history", "prune", "-L"); r.e != nil || !strings.Contains(r.out, "No history prune, sync or restore recorded yet.") {
		t.Fatalf("nothing yet: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "history", "prune", "-y"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runArgs(t, "history", "prune", "-L")
	for _, w := range []string{"ACTION", "prune", path, "4 entries", "2 entries", "updated", ".audit-backup-"} {
		if r.e != nil || !strings.Contains(r.out, w) {
			t.Errorf("last prune missing %q: %v\n%s", w, r.e, r.out)
		}
	}
	if strings.Contains(r.out, "pwd") {
		t.Errorf("no command text is recorded:\n%s", r.out)
	}
	r = runArgs(t, "history", "prune", "-L", "-j")
	var u struct {
		Items []struct {
			Command, Name, ID, Kind, Status string
		} `json:"items"`
	}
	if r.e != nil || json.Unmarshal([]byte(r.out), &u) != nil || len(u.Items) != 1 || u.Items[0].Kind != "history" || u.Items[0].Command != "prune" {
		t.Fatalf("json: %v %s", r.e, r.out)
	}
	backup := u.Items[0].ID
	if r := runArgs(t, "history", "backups", "restore", backup, "-y"); r.e != nil {
		t.Fatal(r.e)
	}
	if r := runArgs(t, "history", "prune", "-L"); !strings.Contains(r.out, "restore") || !strings.Contains(r.out, "2 entries  4 entries") {
		t.Errorf("the restore is the last change:\n%s", r.out)
	}
	if r := runArgs(t, "packages", "update", "-L"); strings.Contains(r.out, "history") {
		t.Errorf("history changes stay out of packages update -L:\n%s", r.out)
	}
}
