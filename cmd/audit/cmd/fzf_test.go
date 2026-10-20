package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFzfHelperLinesAndState(t *testing.T) {
	env(t)
	for i, title := range []string{"first task", "second task"} {
		timeNow = func() time.Time { return testNow.Add(time.Duration(i) * time.Second) } // manual keys come from the clock
		if r := runArgs(t, "todo", "add", title); r.e != nil {
			t.Fatal(r.e)
		}
	}
	if r := runArgs(t, "todo", "set", "1", "done"); r.e != nil {
		t.Fatal(r.e)
	}

	t.Setenv("FZF_PROMPT", "tasks> ")
	r := runArgs(t, "fzf-helper", "lines", "tasks")
	if r.e != nil || strings.Contains(r.out, "first task") || !strings.HasPrefix(r.out, "2 ") {
		t.Errorf("open tasks: %v %q", r.e, r.out)
	}
	t.Setenv("FZF_PROMPT", "tasks +closed> ")
	if r := runArgs(t, "fzf-helper", "lines", "tasks"); !strings.Contains(r.out, "first task") {
		t.Errorf("closed tasks: %q", r.out)
	}
	t.Setenv("FZF_PROMPT", "tasks manual +closed> ")
	t.Setenv("AUDIT_FZF_FILTER", "s:open")
	if r := runArgs(t, "fzf-helper", "lines", "tasks"); strings.Contains(r.out, "first task") || !strings.Contains(r.out, "second task") {
		t.Errorf("status filter: %q", r.out)
	}

	t.Setenv("FZF_PROMPT", "tasks> ")
	if r := runArgs(t, "fzf-helper", "toggle-closed"); !strings.HasPrefix(r.out, "change-prompt(tasks +closed> )+reload(") {
		t.Errorf("toggle: %q", r.out)
	}
	if r := runArgs(t, "fzf-helper", "cycle-command"); !strings.HasPrefix(r.out, "change-prompt(tasks manual> )") {
		t.Errorf("cycle: %q", r.out)
	}
	t.Setenv("FZF_PROMPT", "tasks manual> ")
	if r := runArgs(t, "fzf-helper", "cycle-command"); !strings.HasPrefix(r.out, "change-prompt(tasks> )") {
		t.Errorf("cycle back to all: %q", r.out)
	}

	if r := runArgs(t, "fzf-helper", "lines", "dashboard"); !strings.Contains(r.out, "system ") || !strings.Contains(r.out, "never") {
		t.Errorf("dashboard: %q", r.out)
	}
	t.Setenv("FZF_PREVIEW_COLUMNS", "60")
	if r := runArgs(t, "fzf-helper", "preview", "task", "2"); r.e != nil || !strings.Contains(r.out, "#2 second task") {
		t.Errorf("preview task: %v %q", r.e, r.out)
	}
	if r := runArgs(t, "fzf-helper", "preview", "report", "system"); !strings.Contains(r.out, "system has never run; alt-r rescans it") {
		t.Errorf("preview never-run report: %q", r.out)
	}
	if r := runArgs(t, "fzf-helper", "lines", "bogus"); r.e == nil {
		t.Error("bad arguments must error")
	}
}

func TestFzfFlagNeedsTerminal(t *testing.T) {
	env(t)
	if r := runArgs(t, "todo", "--fzf"); r.e == nil || !strings.Contains(r.e.Error(), "needs a terminal") {
		t.Errorf("todo --fzf without a terminal: %v", r.e)
	}
	if r := runArgs(t, "--fzf"); r.e != nil || !strings.Contains(r.out, "system") {
		t.Errorf("bare audit --fzf without a terminal prints the summary: %v %q", r.e, r.out)
	}
}

func TestUseFzf(t *testing.T) {
	cfgHome, _ := env(t)
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte("tui: {interface: fzf}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runArgs(t, "todo", "-i")
	if r.e == nil || !strings.Contains(r.e.Error(), "needs a terminal") {
		t.Errorf("tui.interface fzf makes -i use fzf: %v", r.e)
	}
	r = runArgs(t, "todo", "-i", "--fzf=false")
	if r.e == nil || strings.Contains(r.e.Error(), "--fzf") {
		t.Errorf("--fzf=false picks the TUI: %v", r.e)
	}
}
