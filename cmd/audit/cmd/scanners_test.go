package cmd

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
)

// TestScanEntriesMatchCommands keeps scanEntries, core.Commands,
// core.ScopeFlags and the cobra tree in step: every command has an entry
// in the same order, its cobra command carries its name and scope flag, and
// its scanner reports the same command.
func TestScanEntriesMatchCommands(t *testing.T) {
	names := make([]string, len(scanEntries))
	for i, e := range scanEntries {
		names[i] = e.name
	}
	if !slices.Equal(names, core.Commands) {
		t.Fatalf("scanEntries %v, core.Commands %v", names, core.Commands)
	}
	for flag := range core.ScopeFlags {
		if !slices.Contains(core.Commands, flag) {
			t.Errorf("core.ScopeFlags names %q, which is not a command", flag)
		}
	}

	env(t)
	var out bytes.Buffer
	a := newApp(&out, io.Discard)
	a.runner = &exec.Fake{}
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	root := newRootCmd(a)
	for _, e := range scanEntries {
		c, _, err := root.Find([]string{e.name})
		if err != nil || c.Name() != e.name {
			t.Errorf("%s: not a subcommand of audit (%v)", e.name, err)
			continue
		}
		if flag, ok := core.ScopeFlags[e.name]; ok && c.Flags().Lookup(strings.TrimPrefix(flag, "--")) == nil {
			t.Errorf("%s: its scope flag %s is not defined", e.name, flag)
		}
		s, err := a.defaultScanner(e.name)
		if err != nil {
			t.Errorf("%s: %v", e.name, err)
			continue
		}
		if s.Command() != e.name {
			t.Errorf("%s: the scanner reports %q", e.name, s.Command())
		}
		if s.Scope() != "" {
			t.Errorf("%s: the default scanner is scoped to %q", e.name, s.Scope())
		}
	}
	if _, err := a.defaultScanner("nope"); err == nil {
		t.Error("an unknown command is an error")
	}
}
