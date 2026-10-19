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
