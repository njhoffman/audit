package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
)

// scanEntry wires one scanning command: its cobra command and the scanner
// the dashboard, fzf and AI fixes build for it with the configured scope.
type scanEntry struct {
	name    string
	newCmd  func(*app) *cobra.Command
	scanner func(*app, context.Context) (core.Scanner, error)
}

// scanEntries lists every scanning command, in core.Commands order
// (TestScanEntriesMatchCommands keeps the two in step). A new scanning
// command is added here, to core.Commands and, with a scope flag, to
// core.ScopeFlags.
var scanEntries = []scanEntry{
	{"system", newSystemCmd, func(a *app, _ context.Context) (core.Scanner, error) { return a.systemScanner(nil) }},
	{"environment", newEnvironmentCmd, func(a *app, _ context.Context) (core.Scanner, error) { return core.NewEnvironment(a.cfg, a.env) }},
	{"packages", newPackagesCmd, func(a *app, _ context.Context) (core.Scanner, error) { return a.packagesScanner(nil) }},
	{"repos", newReposCmd, func(a *app, ctx context.Context) (core.Scanner, error) { return a.reposScanner(ctx), nil }},
	{"files", newFilesCmd, func(a *app, _ context.Context) (core.Scanner, error) { return core.NewFiles(a.cfg, a.env), nil }},
	{"backups", newBackupsCmd, func(a *app, _ context.Context) (core.Scanner, error) { return core.NewBackups(a.cfg, a.env), nil }},
	{"containers", newContainersCmd, func(a *app, _ context.Context) (core.Scanner, error) { return core.NewContainers(a.cfg, a.env), nil }},
	{"configs", newConfigsCmd, func(a *app, ctx context.Context) (core.Scanner, error) { return a.configsScanner(ctx), nil }},
	{"scripts", newScriptsCmd, func(a *app, _ context.Context) (core.Scanner, error) { return a.scriptsScanner(), nil }},
	{"history", newHistoryCmd, func(a *app, _ context.Context) (core.Scanner, error) { return core.NewHistory(a.cfg, a.env), nil }},
	{"ai", newAICmd, func(a *app, _ context.Context) (core.Scanner, error) { return a.aiScanner(false), nil }},
}

// scanCommands builds the cobra command of every scanning command.
func scanCommands(a *app) []*cobra.Command {
	out := make([]*cobra.Command, len(scanEntries))
	for i, e := range scanEntries {
		out[i] = e.newCmd(a)
	}
	return out
}

// defaultScanner builds command's scanner with its configured scope.
func (a *app) defaultScanner(ctx context.Context, command string) (core.Scanner, error) {
	for _, e := range scanEntries {
		if e.name == command {
			return e.scanner(a, ctx)
		}
	}
	return nil, fmt.Errorf("unknown command %q", command)
}
