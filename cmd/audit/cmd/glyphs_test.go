package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNerdFonts(t *testing.T) {
	cfgHome, _ := env(t)
	const icon = " system" // fa-desktop
	if r := runArgs(t, "--summary"); r.e != nil || strings.Contains(r.out, icon) {
		t.Errorf("Unicode markers by default: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "-G", "--summary"); r.e != nil || !strings.Contains(r.out, icon) {
		t.Errorf("-G turns the icons on: %v %q", r.e, r.out)
	}
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte("display: {nerd_fonts: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runArgs(t, "--summary"); r.e != nil || !strings.Contains(r.out, icon) {
		t.Errorf("display.nerd_fonts turns the icons on: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "--nerd-fonts=false", "--summary"); r.e != nil || strings.Contains(r.out, icon) {
		t.Errorf("--nerd-fonts=false turns them off: %v %q", r.e, r.out)
	}
}
