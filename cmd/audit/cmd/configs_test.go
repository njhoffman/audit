package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigsScanAndClean(t *testing.T) {
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, ".config")
	t.Setenv("XDG_CONFIG_HOME", cfg)
	bin := t.TempDir()
	trash := filepath.Join(home, "trashed")
	// A gio stand-in: "gio trash -- PATH" moves PATH into ~/trashed.
	gio := "#!/bin/sh\n/bin/mkdir -p '" + trash + "' && /bin/mv \"$3\" '" + trash + "/'\n"
	if err := os.WriteFile(filepath.Join(bin, "gio"), []byte(gio), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "kept"), nil, 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for p, body := range map[string]string{"kept/config.json": "{}", "goneapp/settings.yaml": "a: 1\n", "kept/broken.json": "{"} {
		full := filepath.Join(cfg, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, cfgHome, "configs: {roots: ["+cfg+"]}\n")
	r := runArgs(t, "configs", "-r", "-l")
	if r.e != nil || !strings.Contains(r.out, "config.syntax") || !strings.Contains(r.out, "config.orphaned") {
		t.Fatalf("scan: %v\n%s\n%s", r.e, r.out, r.err)
	}
	r = runArgs(t, "configs", "-O")
	if !strings.Contains(r.out, "~/.config/goneapp") || strings.Contains(r.out, "~/.config/kept ") {
		t.Errorf("--orphans:\n%s", r.out)
	}
	r = runArgs(t, "configs", "clean", "-N")
	if r.e != nil || !strings.Contains(r.out, "gio trash -- "+filepath.Join(cfg, "goneapp")) || strings.Contains(r.out, "kept") {
		t.Fatalf("plan: %v\n%s", r.e, r.out)
	}
	r = runArgs(t, "configs", "clean", "-y")
	if r.e != nil || !strings.Contains(r.out, "1 updated, 0 failed") {
		t.Fatalf("clean: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if _, err := os.Stat(filepath.Join(trash, "goneapp")); err != nil {
		t.Errorf("not in the trash: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg, "kept", "config.json")); err != nil {
		t.Error("owned configs stay")
	}
}
