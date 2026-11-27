package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

func zpoolEnv(t *testing.T, res exec.Result) *exec.Env {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zpool"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	f := &exec.Fake{}
	f.Add([]string{"zpool", "status", "-x"}, res)
	return &exec.Env{Vars: map[string]string{"PATH": dir}, Runner: f}
}

func TestZFSPools(t *testing.T) {
	ctx := context.Background()
	if fs := zfsPools(ctx, &exec.Env{Vars: map[string]string{"PATH": t.TempDir()}, Runner: &exec.Fake{}}); fs != nil {
		t.Errorf("no zpool, no findings: %v", fs)
	}
	for _, healthy := range []exec.Result{
		{Stdout: "all pools are healthy\n"},
		{Stdout: "no pools available\n"},
		{Code: 1, Stderr: "permission denied"},
	} {
		if fs := zfsPools(ctx, zpoolEnv(t, healthy)); fs != nil {
			t.Errorf("%+v: %v", healthy, fs)
		}
	}
	degraded := "  pool: tank\n state: DEGRADED\nstatus: One or more devices has been removed\naction: Online the device\n  scan: none\nconfig: ...\n"
	fs := zfsPools(ctx, zpoolEnv(t, exec.Result{Stdout: degraded}))
	if len(fs) != 1 || fs[0].Check != "zfs" || !strings.Contains(fs[0].Detail, "pool: tank / state: DEGRADED") || strings.Contains(fs[0].Detail, "scan:") {
		t.Errorf("degraded pool: %+v", fs)
	}
}

func TestFirstLines(t *testing.T) {
	if got := firstLines("\na\n  b\nc\n", 2); got != "a / b" {
		t.Errorf("%q", got)
	}
	if got := firstLines("one", 3); got != "one" {
		t.Errorf("%q", got)
	}
}
