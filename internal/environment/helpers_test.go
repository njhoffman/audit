package environment

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
)

var ctx = context.Background()

func testEnv(t *testing.T) (*exec.Env, *exec.Fake, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	mkdir(t, home)
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
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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

func analyze(s *State) []finding.Finding {
	if s.Ctx == nil {
		s.Ctx = ctx
	}
	return Analyze(s)
}

func byCheck(fs []finding.Finding, check string) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func subjects(fs []finding.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Subject)
	}
	sort.Strings(out)
	return out
}

// fakeCapturer returns canned captures keyed by "shell/mode" and traces
// keyed by shell.
type fakeCapturer struct {
	captures map[string]Capture
	traces   map[string][]string
	calls    []string
}

func (f *fakeCapturer) Trace(_ context.Context, shell string) ([]string, bool) {
	f.calls = append(f.calls, shell+"/trace")
	files, ok := f.traces[shell]
	return files, ok
}

func (f *fakeCapturer) Capture(_ context.Context, shell, mode string) Capture {
	f.calls = append(f.calls, shell+"/"+mode)
	if c, ok := f.captures[shell+"/"+mode]; ok {
		c.Shell, c.Mode = shell, mode
		return c
	}
	return Capture{Shell: shell, Mode: mode, Code: exec.ExitNotFound, Err: shell + " is not installed"}
}
