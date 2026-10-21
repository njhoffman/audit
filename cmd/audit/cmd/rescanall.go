package cmd

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// rescanFlags are bare audit's --rescan options.
type rescanFlags struct {
	rescan bool
	all    bool
	only   []string
}

// rescanTargets are the commands of f.only (every command when empty), in
// core.Commands order, that are stale or never ran; with f.all, all of
// them. Staleness is that of the unscoped run, which is what gets scanned.
func (a *app) rescanTargets(ctx context.Context, f rescanFlags) ([]string, error) {
	only := splitList(f.only)
	for _, c := range only {
		if !slices.Contains(core.Commands, c) {
			return nil, fmt.Errorf("--only: unknown command %q (want %s)", c, strings.Join(core.Commands, ", "))
		}
	}
	var out []string
	for _, c := range core.Commands {
		if len(only) > 0 && !slices.Contains(only, c) {
			continue
		}
		if !f.all {
			r, err := a.engine.Saved(ctx, c, "")
			if err != nil {
				return nil, err
			}
			th := a.cfg.Stale.For(c)
			if r != nil && run.FreshnessOf(r.Age(timeNow()), th.Warn, th.Old) == run.Fresh {
				continue
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// scanDisplay shows the progress of several scans: a board on a terminal,
// a line as each one starts and ends otherwise, nothing with --quiet.
type scanDisplay struct {
	board *progress.Board
	lines bool
	a     *app
	mu    sync.Mutex
}

func (a *app) newScanDisplay(cmds []string) *scanDisplay {
	d := &scanDisplay{a: a}
	if a.flags.quiet {
		return d
	}
	fd := int(os.Stderr.Fd()) // #nosec G115 -- fd fits in int
	if a.errOut != os.Stderr || !term.IsTerminal(fd) {
		d.lines = true
		return d
	}
	d.board = progress.NewBoard(a.errOut, func() int {
		if w, _, err := term.GetSize(fd); err == nil {
			return w
		}
		return 80
	}, cmds)
	d.board.Start()
	a.log.SetOutput(d.board.Writer())
	return d
}

func (d *scanDisplay) reporter(command string) progress.Reporter {
	if d.board != nil {
		return d.board.Task(command)
	}
	if d.lines {
		d.say("%s: scanning\n", command)
	}
	return progress.Nop
}

func (d *scanDisplay) finish(command, result string, failed bool) {
	switch {
	case d.board != nil:
		d.board.Finish(command, result, failed)
	case d.lines:
		d.say("%s: %s\n", command, result)
	}
}

func (d *scanDisplay) say(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	say(d.a.errOut, format, args...)
}

func (d *scanDisplay) stop() {
	if d.board != nil {
		d.board.Stop()
		d.a.log.SetOutput(d.a.errOut)
	}
}

// rescanAll scans the targets of f: packages first, since configs reads
// its saved inventory, then the rest scan.concurrency at a time. A failed
// scan does not stop the others; the error lists every one that failed.
func (a *app) rescanAll(ctx context.Context, f rescanFlags) error {
	cmds, err := a.rescanTargets(ctx, f)
	if err != nil {
		return err
	}
	if len(cmds) == 0 {
		if !a.flags.quiet {
			sayln(a.errOut, "Every command is fresh; -a rescans them anyway.")
		}
		return nil
	}
	d := a.newScanDisplay(cmds)
	var (
		mu     sync.Mutex
		failed []string
	)
	scan := func(c string) {
		start := time.Now()
		changes, err := a.scanOne(ctx, c, d.reporter(c))
		took := time.Since(start).Round(100 * time.Millisecond)
		if err != nil {
			d.finish(c, err.Error(), true)
			mu.Lock()
			failed = append(failed, c+": "+err.Error())
			mu.Unlock()
			return
		}
		d.finish(c, fmt.Sprintf("%s, %d task(s) updated", took, changes), false)
	}
	rest := cmds
	if slices.Contains(cmds, packages.Command) {
		scan(packages.Command)
		rest = slices.DeleteFunc(slices.Clone(cmds), func(c string) bool { return c == packages.Command })
	}
	sem := make(chan struct{}, a.cfg.Scan.Concurrency)
	var wg sync.WaitGroup
	for _, c := range rest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				d.finish(c, "canceled", true)
				return
			}
			defer func() { <-sem }()
			scan(c)
		}()
	}
	wg.Wait()
	d.stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(failed) > 0 {
		slices.Sort(failed)
		return fmt.Errorf("%d of %d scans failed:\n  %s", len(failed), len(cmds), strings.Join(failed, "\n  "))
	}
	return nil
}

// scanOne scans command with its default scope and saves the run.
func (a *app) scanOne(ctx context.Context, command string, rep progress.Reporter) (int, error) {
	s, err := a.scanner(command)
	if err != nil {
		return 0, err
	}
	res, err := a.engine.Execute(ctx, s, rep)
	if err != nil {
		return 0, err
	}
	return res.TaskChanges, nil
}
