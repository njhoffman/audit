package exec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeExe(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testEnv(t *testing.T, path ...string) *Env {
	home := t.TempDir()
	e := &Env{Vars: map[string]string{"PATH": strings.Join(path, ":")}, Home: home}
	e.Runner = NewOSRunner(e)
	return e
}

func TestWhichAllOrderAndDedupe(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	writeExe(t, filepath.Join(a, "tool"), "#!/bin/sh\n")
	writeExe(t, filepath.Join(b, "tool"), "#!/bin/sh\n")
	if err := os.WriteFile(filepath.Join(b, "plain"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	e := testEnv(t, b, a, b+"/", "")
	got := e.WhichAll("tool")
	want := []string{filepath.Join(b, "tool"), filepath.Join(a, "tool")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WhichAll = %v want %v", got, want)
	}
	if e.Which("plain") != "" {
		t.Error("non-executable file must not resolve")
	}
	if e.Which("absent") != "" {
		t.Error("absent command must not resolve")
	}
}

func TestOSRunnerCapturesAndUnsets(t *testing.T) {
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "show"), "#!/bin/sh\necho \"out:$FOO:$(pwd)\"\necho err >&2\nexit 3\n")
	e := testEnv(t, dir, "/usr/bin", "/bin")
	e.Vars["FOO"] = "bar"
	res := e.Run(context.Background(), "show", nil, Options{})
	if res.Code != 3 || res.Stdout != "out:bar:"+e.Home+"\n" || res.Stderr != "err\n" {
		t.Errorf("unexpected result %+v", res)
	}
	res = e.Run(context.Background(), "show", nil, Options{Unset: []string{"FOO"}})
	if !strings.HasPrefix(res.Stdout, "out::") {
		t.Errorf("FOO not unset: %q", res.Stdout)
	}
}

func TestOSRunnerNotFoundAndTimeout(t *testing.T) {
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "slow"), "#!/bin/sh\nexec sleep 5\n")
	e := testEnv(t, dir, "/usr/bin", "/bin")
	if res := e.Run(context.Background(), "nope-xyz", nil, Options{}); res.Code != ExitNotFound {
		t.Errorf("not found code = %d", res.Code)
	}
	start := time.Now()
	res := e.Run(context.Background(), "slow", nil, Options{Timeout: 100 * time.Millisecond})
	if res.Code != ExitTimeout {
		t.Errorf("timeout code = %d", res.Code)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("timeout not enforced")
	}
}

func TestOSRunnerStdinClosedByDefault(t *testing.T) {
	dir := t.TempDir()
	writeExe(t, filepath.Join(dir, "reader"), "#!/bin/sh\ncat\necho done\n")
	e := testEnv(t, dir, "/usr/bin", "/bin")
	res := e.Run(context.Background(), "reader", nil, Options{Timeout: 2 * time.Second})
	if res.Code != 0 || res.Stdout != "done\n" {
		t.Errorf("stdin not closed: %+v", res)
	}
	res = e.Run(context.Background(), "reader", nil, Options{Stdin: "hi\n"})
	if res.Stdout != "hi\ndone\n" {
		t.Errorf("stdin not passed: %q", res.Stdout)
	}
}

func TestExpandAndXDG(t *testing.T) {
	e := &Env{Vars: map[string]string{"FOO": "/f", "XDG_DATA_HOME": "/data"}, Home: "/h"}
	for in, want := range map[string]string{
		"~": "/h", "~/x": "/h/x", "$FOO/y": "/f/y", "${FOO}z": "/fz", "$HOME/a": "/h/a", "$NOPE/a": "/a",
	} {
		if got := e.Expand(in); got != want {
			t.Errorf("Expand(%q) = %q want %q", in, got, want)
		}
	}
	if e.XDG("XDG_DATA_HOME") != "/data" || e.XDG("XDG_CONFIG_HOME") != "/h/.config" {
		t.Error("XDG fallback wrong")
	}
}

func TestFakeLongestPrefix(t *testing.T) {
	f := &Fake{}
	f.AddOutput("generic", "uv")
	f.AddOutput("dir", "uv", "tool", "dir")
	ctx := context.Background()
	if r := f.Run(ctx, "uv", []string{"tool", "dir"}, Options{}); r.Stdout != "dir" {
		t.Errorf("got %q", r.Stdout)
	}
	if r := f.Run(ctx, "uv", []string{"tool", "list"}, Options{}); r.Stdout != "generic" {
		t.Errorf("got %q", r.Stdout)
	}
	if r := f.Run(ctx, "cargo", nil, Options{}); r.Code != ExitNotFound {
		t.Errorf("unmatched should be not found, got %d", r.Code)
	}
	if len(f.Calls) != 3 {
		t.Errorf("calls = %v", f.Calls)
	}
}
