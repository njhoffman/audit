package scripts

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

func TestShebangAndLang(t *testing.T) {
	for line, want := range map[string][2]string{
		"#!/bin/bash":                       {"/bin/bash", "bash"},
		"#!/usr/bin/env python3":            {"/usr/bin/env", "python3"},
		"#!/usr/bin/env -S uv run --script": {"/usr/bin/env", "uv"},
		"#! /bin/sh\r":                      {"/bin/sh", "sh"},
		"echo hi":                           {"", ""},
	} {
		i, p := Shebang(line)
		if [2]string{i, p} != want {
			t.Errorf("%q: %s %s", line, i, p)
		}
	}
	for c, want := range map[[2]string]string{{"python3.12", "x"}: "python", {"", "x.zsh"}: "zsh", {"bash", "x.py"}: "bash", {"", "x"}: ""} {
		if got := LangOf(c[0], c[1]); got != want {
			t.Errorf("LangOf%v = %q", c, got)
		}
	}
}

func TestHeader(t *testing.T) {
	desc, usage := Header("#!/usr/bin/env bash\n# shellcheck disable=SC2034\n#\n# Syncs the music library to the phone.\n"+
		"# Runs over adb.\n#\n# Usage: musicsync [-n] DIR\n#   -n  dry run\nset -e\n", "bash")
	if desc != "Syncs the music library to the phone. Runs over adb." || usage != "musicsync [-n] DIR\n-n  dry run" {
		t.Errorf("shell: %q / %q", desc, usage)
	}
	desc, _ = Header("#!/usr/bin/env python3\n\"\"\"Rename photos by EXIF date.\n\nMore text.\n\"\"\"\nimport os\n", "python")
	if desc != "Rename photos by EXIF date." {
		t.Errorf("docstring: %q", desc)
	}
	if desc, _ = Header("#!/bin/sh\necho hi\n", "shell"); desc != "" {
		t.Errorf("no header: %q", desc)
	}
	if desc, _ = Header("#!/usr/bin/env lua\n-- Toggles the bar.\nprint(1)\n", "lua"); desc != "Toggles the bar." {
		t.Errorf("lua: %q", desc)
	}
}

func TestCommands(t *testing.T) {
	script := strings.Join([]string{
		"#!/bin/bash",
		"helper() {",
		`  echo "using notacommand inside a string"`,
		"}",
		"other_fn()",
		"{",
		"  true",
		"}",
		`name="x"`,
		`case "$1" in`,
		"  -d|debug) termite --hold ;;",
		"  options) : ;;",
		"esac",
		"result=$(jq '.a' file | sort -u)",
		"local count=3",
		"sudo apt-get update && helper && other_fn",
		"cat <<END",
		"heredoc_word inside",
		"END",
		"$name --flag",
	}, "\n")
	got := Commands(script)
	want := []string{"apt-get", "cat", "jq", "sort", "termite"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestScan(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	write := func(name, body string, mode os.FileMode, mod time.Time) {
		p := filepath.Join(bin, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if !mod.IsZero() {
			if err := os.Chtimes(p, mod, mod); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	old := now.Add(-3 * 365 * 24 * time.Hour)
	write("good", "#!/bin/sh\n# Says hello.\nprintf hi\n", 0o755, time.Time{})
	write("noexec", "#!/bin/sh\nprintf x\n", 0o644, time.Time{})
	write("crlf", "#!/bin/sh\r\nprintf x\r\n", 0o755, time.Time{})
	write("gone", "#!/usr/bin/env nosuchinterp\n", 0o755, old)
	write("calls", "#!/bin/bash\nnosuchtool --x\nprintf ok\n", 0o755, old)
	write("broken.py", "#!/usr/bin/env python3\ndef f(:\n", 0o755, time.Time{})
	write("lib.zsh", "# a zsh function file\n", 0o644, time.Time{})
	write("binary", "\x7fELFxxxx", 0o755, time.Time{})
	write("README.md", "# docs\n", 0o644, time.Time{})
	if err := os.Symlink(filepath.Join(bin, "good"), filepath.Join(bin, "link")); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	for _, n := range []string{"sh", "bash", "printf", "python3", "env"} {
		if err := os.WriteFile(filepath.Join(tools, n), nil, 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	fake := &exec.Fake{}
	fake.Add([]string{"python3", "-I", "-c"}, exec.Result{Code: 1, Stderr: "  File \"broken.py\", line 2\nSyntaxError: invalid syntax"})
	env := &exec.Env{Vars: map[string]string{"PATH": tools + ":" + bin}, Home: home, Runner: fake}
	o := ScanOptions{Env: env, Options: Options{Roots: []string{bin}, MaxDepth: 2, MaxBytes: 1 << 20}, StaleAfter: 2 * 365 * 24 * time.Hour,
		Now: now, Descriptions: map[string]string{}}
	d, fs, stats, _, err := Scan(context.Background(), o, progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Script{}
	for _, s := range d.Scripts {
		names[s.Name] = s
	}
	if len(names) != 7 || names["good"].Description != "Says hello." || names["lib.zsh"].Lang != "zsh" {
		t.Errorf("scripts (no binary, README or symlink): %v", names)
	}
	got := map[string][]string{}
	for _, f := range fs {
		got[f.Check] = append(got[f.Check], filepath.Base(f.Subject))
	}
	for check, want := range map[string]string{
		"script.not_executable":   "noexec",
		"script.crlf":             "crlf",
		"script.interpreter":      "gone",
		"script.missing_commands": "calls",
		"script.syntax":           "broken.py",
		"script.dead":             "calls,gone",
	} {
		if strings.Join(got[check], ",") != want {
			t.Errorf("%s: %v, want %s", check, got[check], want)
		}
	}
	if stats[1].Value != "no: shellcheck is not installed" {
		t.Errorf("stats: %v", stats)
	}
	o.Descriptions = map[string]string{names["noexec"].SHA256: "Prints x."}
	d, _, _, _, _ = Scan(context.Background(), o, progress.Nop)
	for _, s := range d.Scripts {
		if s.Name == "noexec" && (s.Description != "Prints x." || s.DescSource != "ai") {
			t.Errorf("cached AI description: %+v", s)
		}
	}
}
