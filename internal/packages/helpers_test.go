package packages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

func testEnv(t *testing.T) (*exec.Env, *exec.Fake, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := &exec.Fake{}
	env := &exec.Env{
		Vars:   map[string]string{"HOME": home, "PATH": filepath.Join(home, "bin")},
		Home:   home,
		Runner: fake,
	}
	return env, fake, home
}

func makeExe(t *testing.T, path, content string) string {
	t.Helper()
	if content == "" {
		content = "#!/bin/sh\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func setPath(env *exec.Env, dirs ...string) {
	env.Vars["PATH"] = strings.Join(dirs, string(os.PathListSeparator))
}
