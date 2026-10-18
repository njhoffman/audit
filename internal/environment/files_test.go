package environment

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDialectOf(t *testing.T) {
	for path, want := range map[string]Dialect{
		"/h/.zshrc":                   DialectZsh,
		"/h/.zprofile":                DialectZsh,
		"/h/.shell/zsh/options.zsh":   DialectZsh,
		"/h/.shell/zsh/functions/foo": DialectZsh,
		"/h/.bashrc":                  DialectBash,
		"/h/.bash_aliases":            DialectBash,
		"/h/.shell/bash/bashrc.sh":    DialectBash,
		"/h/x.bash":                   DialectBash,
		"/h/.profile":                 DialectSh,
		"/h/.shell/aliases/git.sh":    DialectSh,
		"/h/.shell/functions/mkcd":    DialectSh,
	} {
		if got := dialectOf(path); got != want {
			t.Errorf("dialectOf(%s) = %s, want %s", path, got, want)
		}
	}
}

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".shell")
	profile := writeFile(t, filepath.Join(home, ".profile"), "")
	writeFile(t, filepath.Join(root, "init.sh"), "")
	writeFile(t, filepath.Join(root, "zsh/zshrc.zsh"), "")
	writeFile(t, filepath.Join(root, "zsh/zshrc.zsh.zwc"), "")
	writeFile(t, filepath.Join(root, "functions/mkcd"), "")
	writeFile(t, filepath.Join(root, "functions/_index.sh"), "")
	writeFile(t, filepath.Join(root, "functions/_helper"), "")
	makeExe(t, filepath.Join(root, "bin/compile"), "#!/usr/bin/env zsh\n")
	makeExe(t, filepath.Join(root, "bin/tool"), "#!/usr/bin/python3\n")
	makeExe(t, filepath.Join(root, "aliases/install.sh"), "#!/bin/bash\n")
	writeFile(t, filepath.Join(root, "README.md"), "")
	writeFile(t, filepath.Join(root, "tests/env_test.sh"), "")
	writeFile(t, filepath.Join(root, ".git/hooks/pre-commit.sh"), "")
	writeFile(t, filepath.Join(root, "node_modules/x/y.sh"), "")
	if err := os.Symlink(filepath.Join(root, "init.sh"), filepath.Join(home, ".zshrc")); err != nil {
		t.Fatal(err)
	}

	got := discover([]string{profile, filepath.Join(home, ".zshrc"), filepath.Join(home, ".absent")}, []string{root})
	want := map[string]Script{
		profile:                                    {Path: profile, Dialect: DialectSh, Startup: true},
		filepath.Join(home, ".zshrc"):              {Path: filepath.Join(home, ".zshrc"), Dialect: DialectZsh, Startup: true},
		filepath.Join(root, "zsh/zshrc.zsh"):       {Path: filepath.Join(root, "zsh/zshrc.zsh"), Dialect: DialectZsh},
		filepath.Join(root, "functions/mkcd"):      {Path: filepath.Join(root, "functions/mkcd"), Dialect: DialectSh, Function: "mkcd"},
		filepath.Join(root, "functions/_index.sh"): {Path: filepath.Join(root, "functions/_index.sh"), Dialect: DialectSh},
		filepath.Join(root, "functions/_helper"):   {Path: filepath.Join(root, "functions/_helper"), Dialect: DialectSh, Function: "_helper"},
		filepath.Join(root, "bin/compile"):         {Path: filepath.Join(root, "bin/compile"), Dialect: DialectZsh, Executable: true},
		filepath.Join(root, "aliases/install.sh"):  {Path: filepath.Join(root, "aliases/install.sh"), Dialect: DialectBash, Executable: true},
	}
	if len(got) != len(want) {
		t.Fatalf("discover found %d scripts, want %d: %+v", len(got), len(want), got)
	}
	for i, s := range got {
		if w, ok := want[s.Path]; !ok || !reflect.DeepEqual(w, s) {
			t.Errorf("unexpected %+v", s)
		}
		if i > 0 && got[i-1].Path > s.Path {
			t.Error("scripts not sorted by path")
		}
	}
	// init.sh is the .zshrc symlink's target, so it is listed once, under
	// the startup-file name.
	for _, s := range got {
		if s.Path == filepath.Join(root, "init.sh") {
			t.Error("symlink target listed twice")
		}
	}
}

func TestLoadShells(t *testing.T) {
	both := map[string]bool{"zsh": true, "bash": true}
	for _, tc := range []struct {
		s      Script
		traced map[string]bool
		want   []string
	}{
		{Script{Dialect: DialectSh}, nil, []string{"bash", "zsh"}},
		{Script{Dialect: DialectSh}, both, nil},
		{Script{Dialect: DialectSh, LoadedBy: []string{"zsh"}}, both, []string{"zsh"}},
		{Script{Dialect: DialectSh}, map[string]bool{"zsh": true}, []string{"bash"}},
		{Script{Dialect: DialectZsh, LoadedBy: []string{"bash"}}, both, []string{"bash"}},
		{Script{Dialect: DialectZsh, Function: "f"}, both, []string{"zsh"}},
		{Script{Dialect: DialectBash, Executable: true}, both, []string{"bash"}},
	} {
		if got := tc.s.LoadShells(tc.traced); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("LoadShells(%+v, %v) = %#v, want %#v", tc.s, tc.traced, got, tc.want)
		}
	}
}

func TestShebangShell(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"#!/bin/bash\n":            "bash",
		"#!/usr/bin/env zsh\n":     "zsh",
		"#! /bin/sh -e\n":          "sh",
		"#!/bin/dash\n":            "sh",
		"#!/usr/bin/env python3\n": "",
		"echo hi\n":                "",
		"#!\n":                     "",
	} {
		p := writeFile(t, filepath.Join(dir, "s"), content)
		if got := shebangShell(p); got != want {
			t.Errorf("shebangShell(%q) = %q, want %q", content, got, want)
		}
	}
	if shebangShell(filepath.Join(dir, "missing")) != "" {
		t.Error("missing file")
	}
}
