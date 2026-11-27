package backups

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func checks(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Check+" "+f.Subject)
	}
	slices.Sort(out)
	return out
}

func TestScanDejaDupAndCommands(t *testing.T) {
	bin, home := t.TempDir(), "/home/u"
	if err := os.WriteFile(filepath.Join(bin, "deja-dup"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	f := &exec.Fake{}
	g := []string{"gsettings", "get", "org.gnome.DejaDup"}
	f.AddOutput("''\n", append(g, "last-backup")...)
	f.AddOutput("false\n", append(g, "periodic")...)
	f.AddOutput("'google'\n", append(g, "backend")...)
	f.AddOutput("['$HOME']\n", append(g, "include-list")...)
	f.AddOutput("['$TRASH', '$HOME/.cache']\n", append(g, "exclude-list")...)
	f.AddOutput("2026-09-20T03:00:00Z\n", "sh", "-c", "restic-last")
	f.Add([]string{"sh", "-c", "broken"}, exec.Result{Code: 2, Stderr: "repository not found"})
	f.AddOutput("yesterday\n", "sh", "-c", "garbled")
	env := &exec.Env{Vars: map[string]string{"PATH": bin}, Home: home, Runner: f}
	res, err := Scan(context.Background(), Options{Env: env, DejaDup: true, MaxAge: 7 * 24 * time.Hour, Now: now,
		Paths: []string{"~", "~/.cache/x", "/srv/data"},
		Sources: []Source{
			{Name: "restic", Command: "restic-last", Covers: []string{"/srv"}},
			{Name: "nas", Command: "broken", Covers: []string{"/srv/data"}},
			{Name: "odd", Command: "garbled"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"backups.error nas", "backups.error odd", "backups.never deja-dup", "backups.stale restic",
		"backups.uncovered /home/u/.cache/x", "backups.unscheduled deja-dup",
	}
	if got := checks(res.Findings); !slices.Equal(got, want) {
		t.Errorf("checks\n got %v\nwant %v", got, want)
	}
	dd := res.Data.Backups[0]
	if dd.Backend != "google" || !slices.Equal(dd.Covers, []string{home}) || len(dd.Excludes) != 2 || dd.Excludes[1] != "/home/u/.cache" {
		t.Errorf("deja-dup: %+v", dd)
	}
	if len(res.Stats) != 5 || res.Stats[1].Value != "never" || res.Stats[2].Value != "11d ago" {
		t.Errorf("stats %+v", res.Stats)
	}
}

func TestAnalyze(t *testing.T) {
	if got := checks(Analyze(nil, []string{"/home/u"}, time.Hour, now)); !slices.Equal(got, []string{"backups.none backups"}) {
		t.Errorf("nothing at all: %v", got)
	}
	ok := Backup{Name: "r", Last: now.Add(-time.Hour), Covers: []string{"/home/u"}}
	if got := Analyze([]Backup{ok}, []string{"/home/u/docs"}, 24*time.Hour, now); len(got) != 0 {
		t.Errorf("fresh and covering: %v", checks(got))
	}
	old := Backup{Name: "r", Last: now.Add(-30 * 24 * time.Hour)}
	if got := Analyze([]Backup{old}, nil, 7*24*time.Hour, now); len(got) != 1 || got[0].Severity != finding.Error {
		t.Errorf("four times past max_age is an error: %+v", got)
	}
	if got := Analyze([]Backup{old}, nil, 0, now); len(got) != 0 {
		t.Errorf("max_age 0 never goes stale: %+v", got)
	}
}

func TestParsers(t *testing.T) {
	if got := gvariantStrings("@as []"); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
	if got := gvariantStrings(`['$HOME', "/a b"]`); !slices.Equal(got, []string{"$HOME", "/a b"}) {
		t.Errorf("list: %v", got)
	}
	for in, want := range map[string]time.Time{
		"2026-09-20T03:00:00Z":     time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC),
		`"2026-09-20T03:00:00.5Z"`: time.Date(2026, 9, 20, 3, 0, 0, 5e8, time.UTC),
		"1790000000":               time.Unix(1790000000, 0),
	} {
		if got := parseTime(in); !got.Equal(want) {
			t.Errorf("parseTime(%q) = %v", in, got)
		}
	}
	if !parseTime("never").IsZero() {
		t.Error("garbage is zero")
	}
}
