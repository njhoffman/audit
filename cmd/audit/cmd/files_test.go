package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFilesScan(t *testing.T) {
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	// No tools on PATH: the cache probes would otherwise size this
	// machine's real caches.
	t.Setenv("PATH", t.TempDir())
	old := time.Now().Add(-400 * 24 * time.Hour)
	for p, size := range map[string]int{"Downloads/old.iso": 2 << 20, "proj/package.json": 10, "proj/node_modules/x.js": 2 << 20} {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"Downloads/old.iso", "proj/node_modules"} {
		if err := os.Chtimes(filepath.Join(home, p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, cfgHome, "files: {roots: ["+home+"], downloads: "+filepath.Join(home, "Downloads")+
		", build_min_mb: 1, downloads_min_mb: 1, large_mb: 1}\n")
	r := runArgs(t, "files", "-r", "-l")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"files.build", "files.downloads", "Largest directories", "Idle build and dependency directories",
		"~/proj/node_modules", "reclaimable"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q:\n%s", want, r.out)
		}
	}
	if r := runArgs(t, "files", "-j"); r.e != nil || !strings.Contains(r.out, `"reclaimable"`) {
		t.Errorf("json: %v", r.e)
	}
}

func TestFilesClean(t *testing.T) {
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	if err := os.Symlink("/bin/rm", filepath.Join(bin, "rm")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	old := time.Now().Add(-400 * 24 * time.Hour)
	nm := filepath.Join(home, "proj/node_modules")
	for p, size := range map[string]int{"proj/package.json": 10, "proj/node_modules/x.js": 2 << 20} {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(nm, old, old); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, cfgHome, "files: {roots: ["+home+"], build_min_mb: 1}\n")
	if r := runArgs(t, "files", "clean", "-N"); r.e == nil || !strings.Contains(r.e.Error(), "run `audit files -r` first") {
		t.Errorf("no scan yet: %v", r.e)
	}
	if r := runArgs(t, "files", "-r", "-s"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runArgs(t, "files", "clean", "-N")
	if r.e != nil || !strings.Contains(r.out, "rm -rf -- "+nm) {
		t.Fatalf("plan: %v\n%s", r.e, r.out)
	}
	if r := runArgs(t, "files", "clean", "-C", "nope"); r.e == nil {
		t.Error("unknown category")
	}
	r = runArgs(t, "files", "clean", "-y")
	if r.e != nil || !strings.Contains(r.out, "1 updated, 0 failed") || !strings.Contains(r.out, "freed or moved to the trash") {
		t.Fatalf("clean: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if _, err := os.Stat(nm); !os.IsNotExist(err) {
		t.Error("node_modules should be gone")
	}
	if _, err := os.Stat(filepath.Join(home, "proj/package.json")); err != nil {
		t.Error("the project stays")
	}
	if r := runArgs(t, "files", "clean", "-L"); r.e != nil || !strings.Contains(r.out, "1 updated") {
		t.Errorf("--last: %v\n%s", r.e, r.out)
	}
}
