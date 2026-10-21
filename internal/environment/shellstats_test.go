package environment

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// The stats scripts must survive hostile user options, keep alias bodies to
// themselves and print nothing into the startup output.
func TestCaptureStatsRealShells(t *testing.T) {
	for _, tc := range []struct {
		shell, file, rc string
	}{
		{"zsh", ".zshrc", "setopt err_exit no_unset ksh_arrays\nfpath=(/nonexistent/fp $fpath)\n"},
		{"bash", ".bash_profile", "set -eu\n"},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			c, home := realCapturer(t, tc.shell)
			writeFile(t, filepath.Join(home, tc.file), tc.rc+`alias ll='ls -l'
alias gone=audit_no_such_command_xyz
alias tok='SECRET=hunter2 ls'
alias quoted="'audit_no_such_command_xyz' -x"
alias cat=ls
myfn() { :; }
`)
			for _, mode := range []string{ModeTTY, ModeNoTTY} {
				got := c.Capture(ctx, tc.shell, mode)
				if got.Code != 0 || got.Err != "" || len(got.Output) != 0 {
					t.Fatalf("%s: capture failed or printed: %+v", mode, got)
				}
				st := got.Stats
				if st == nil {
					t.Fatalf("%s: no stats", mode)
				}
				for _, k := range []string{"aliases", "functions", "params", "exports", "paths", "commands", "bins"} {
					if st.Counts[k] < 1 {
						t.Errorf("%s: count %s = %d", mode, k, st.Counts[k])
					}
				}
				if st.Counts["aliases"] < 5 { // system startup files may add their own
					t.Errorf("%s: aliases = %d", mode, st.Counts["aliases"])
				}
				if !reflect.DeepEqual(st.BrokenAliases, map[string]string{"gone": "audit_no_such_command_xyz"}) {
					t.Errorf("%s: broken aliases %v", mode, st.BrokenAliases)
				}
				if !slices.Contains(st.ShadowAliases, "cat") || slices.Contains(st.ShadowAliases, "ll") {
					t.Errorf("%s: shadow aliases %v", mode, st.ShadowAliases)
				}
				if tc.shell == "zsh" && (len(st.Fpath) == 0 || st.Fpath[0] != "/nonexistent/fp" || st.Counts["widgets"] < 1) {
					t.Errorf("%s: fpath %v widgets %d", mode, st.Fpath, st.Counts["widgets"])
				}
			}
		})
	}
}

func TestParseStats(t *testing.T) {
	st := parseStats([]byte("count aliases 12\ncount bad x\nfpath /a b\nalias_broken dc docker-compose\nalias_shadow vim\nalias_shadow cat\njunk\n"))
	want := &ShellStats{
		Counts: map[string]int{"aliases": 12}, Fpath: []string{"/a b"},
		BrokenAliases: map[string]string{"dc": "docker-compose"}, ShadowAliases: []string{"cat", "vim"},
	}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("got %+v", st)
	}
	if parseStats([]byte("")) != nil || parseStats([]byte("junk\n")) != nil {
		t.Error("nothing parsed means no stats")
	}
}

func TestCountBins(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	makeExe(t, filepath.Join(a, "tool"), "#!/bin/sh\n")
	makeExe(t, filepath.Join(a, "other"), "#!/bin/sh\n")
	makeExe(t, filepath.Join(b, "tool"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(b, "data.txt"), "x")
	mkdir(t, filepath.Join(b, "sub"))
	if n := countBins(strings.Join([]string{a, "", "relative", b, filepath.Join(dir, "missing")}, ":")); n != 2 {
		t.Errorf("countBins = %d, want 2", n)
	}
}

func statsCaptures() []Capture {
	tty := &ShellStats{
		Counts:        map[string]int{"aliases": 10, "functions": 5, "fpaths": 3},
		Fpath:         []string{"/nonexistent/one", "/nonexistent/one", "relative"},
		BrokenAliases: map[string]string{"dc": "docker-compose", "both": "x"},
		ShadowAliases: []string{"cat", "vim"},
	}
	notty := &ShellStats{
		Counts:        map[string]int{"aliases": 8, "functions": 5, "fpaths": 3},
		BrokenAliases: map[string]string{"both": "x", "only": "y"},
	}
	return []Capture{
		{Shell: "zsh", Mode: ModeTTY, Stats: tty},
		{Shell: "zsh", Mode: ModeNoTTY, Stats: notty},
		{Shell: "bash", Mode: ModeTTY},
		{Shell: "bash", Mode: ModeNoTTY, Stats: &ShellStats{Counts: map[string]int{"aliases": 2}}},
	}
}

func TestShellStatsRows(t *testing.T) {
	got := shellStats(statsCaptures(), "zsh")
	want := []run.Stat{
		{Group: "zsh", Name: "aliases", Value: "10", Note: "8 (notty)"},
		{Group: "zsh", Name: "functions", Value: "5"},
		{Group: "zsh", Name: "fpath entries", Value: "3"},
		{Group: "bash", Name: "aliases", Value: "2", Note: "notty only", Extra: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestShellStatsChecks(t *testing.T) {
	s := &State{Captures: statsCaptures()}
	msgs := func(fs []finding.Finding) []string {
		out := []string{}
		for _, f := range fs {
			out = append(out, f.Message)
		}
		return out
	}
	broken := aliasBroken(s)
	if got := msgs(broken); !reflect.DeepEqual(got, []string{
		"zsh alias both runs x, which is not a command",
		"zsh alias dc runs docker-compose, which is not a command under a terminal",
		"zsh alias only runs y, which is not a command without a terminal",
	}) {
		t.Errorf("alias_broken: %q", got)
	}
	if broken[0].Severity != finding.Warning || broken[0].Subject != "zsh both" {
		t.Errorf("alias_broken finding: %+v", broken[0])
	}
	shadows := aliasShadows(s)
	if len(shadows) != 1 || shadows[0].Severity != finding.Info || !reflect.DeepEqual(shadows[0].Details, []string{"cat", "vim"}) ||
		!strings.HasPrefix(shadows[0].Message, "2 zsh aliases named like a program on PATH run something else") {
		t.Errorf("alias_shadows: %+v", shadows)
	}
	if got := subjects(fpathMissing(s)); !reflect.DeepEqual(got, []string{"/nonexistent/one"}) {
		t.Errorf("fpath_missing: %v", got)
	}
	if got := msgs(fpathDuplicate(s)); !reflect.DeepEqual(got, []string{"/nonexistent/one appears 2 times in zsh fpath (positions 0, 1)"}) {
		t.Errorf("fpath_duplicate: %q", got)
	}
	if got := msgs(nottyDefinitions(s)); !reflect.DeepEqual(got, []string{"zsh login startup without a terminal defines only 8 of 10 aliases"}) {
		t.Errorf("notty_definitions: %q", got)
	}

	rc := writeFile(t, filepath.Join(t.TempDir(), "aliases.zsh"), "# aliases\nalias dc='docker-compose'\n")
	s = &State{Captures: statsCaptures(), Traced: map[string]bool{"zsh": true},
		Scripts: []Script{{Path: rc, Dialect: DialectZsh, LoadedBy: []string{"zsh"}}}}
	for _, f := range aliasBroken(s) {
		want := []string(nil)
		if f.Subject == "zsh dc" {
			want = []string{rc + ": line 2: " + f.Message}
		}
		if !reflect.DeepEqual(f.Details, want) || f.Group == nil || !f.Group.Rollup {
			t.Errorf("%s: details %q group %+v", f.Subject, f.Details, f.Group)
		}
	}

	if fs := analyze(&State{Env: s.Env, Captures: []Capture{{Shell: "zsh", Mode: ModeTTY}}}); len(byCheck(fs, "shell.alias_broken")) != 0 {
		t.Error("no stats, no findings")
	}
}

func TestStatsExtraForOtherShells(t *testing.T) {
	d := Data{Captures: []Capture{
		{Shell: "zsh", Mode: ModeTTY, Path: "/bin/zsh", Code: 1, Output: []string{"x"}, Stats: &ShellStats{Counts: map[string]int{"aliases": 1}}},
		{Shell: "bash", Mode: ModeTTY, Path: "/bin/bash", Stats: &ShellStats{Counts: map[string]int{"aliases": 2}}},
	}}
	extra := func(sh string) map[string]bool {
		out := map[string]bool{}
		for _, st := range stats(d, &exec.Env{Vars: map[string]string{"SHELL": sh}}, nil) {
			if st.Group == "startup" || st.Group == "zsh" || st.Group == "bash" {
				out[st.Group+"/"+st.Name] = st.Extra
			}
			if st.Name == "zsh tty" && st.Note != "exit 1, 1 unexpected line(s)" {
				t.Errorf("zsh tty note %q", st.Note)
			}
		}
		return out
	}
	if got := extra("/usr/bin/zsh"); !reflect.DeepEqual(got, map[string]bool{
		"startup/zsh tty": false, "startup/bash tty": true, "zsh/aliases": false, "bash/aliases": true}) {
		t.Errorf("SHELL zsh: %v", got)
	}
	if got := extra(""); got["startup/bash tty"] || got["bash/aliases"] {
		t.Errorf("no SHELL hides nothing: %v", got)
	}
}
