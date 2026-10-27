package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	osexec "os/exec"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/todo"
	"github.com/njhoffman/audit/internal/tui"
)

// tuiBackend adapts the app to the dashboard. forceColor renders in color
// although stdout is not a terminal (fzf previews and pagers).
type tuiBackend struct {
	a          *app
	forceColor bool
}

func runDashboard(ctx context.Context, a *app) error {
	return tui.Run(ctx, tuiBackend{a: a}, a.tuiOptions()...)
}

func runTodoEditor(ctx context.Context, a *app, f todo.Filter) error {
	if !a.interactive() {
		return fmt.Errorf("--interactive needs a terminal")
	}
	return tui.Run(ctx, tuiBackend{a: a}, append(a.tuiOptions(), tui.StartInTodos(f))...)
}

func (a *app) tuiOptions() []tui.Option {
	return []tui.Option{tui.WithClock(timeNow), tui.WithKeys(a.cfg.TUI.Keys), tui.WithHome(a.env.Home),
		tui.WithGlyphs(render.GlyphsFor(a.cfg.Display.NerdFonts))}
}

func (b tuiBackend) Statuses(ctx context.Context) ([]render.CommandStatus, error) {
	return b.a.statuses(ctx)
}

func (b tuiBackend) Report(ctx context.Context, command string, width int, expanded bool) (string, bool, error) {
	r, err := b.a.engine.Saved(ctx, command, "")
	if err != nil || r == nil {
		return "", false, err
	}
	var buf bytes.Buffer
	p := b.printer(&buf, width)
	p.Collapsed, p.AllDetails = !expanded, expanded
	p.Report(r, render.ReportOptions{Thresholds: b.a.cfg.Stale.For(command), Saved: true,
		RescanHint: core.RescanHint(command, r.Scope)})
	return buf.String(), true, nil
}

func (b tuiBackend) Rescan(ctx context.Context, command string) (int, error) {
	s, err := b.a.defaultScanner(command)
	if err != nil {
		return 0, err
	}
	res, err := b.a.engine.Execute(ctx, s, progress.Nop)
	if err != nil {
		return 0, err
	}
	return res.TaskChanges, nil
}

func (b tuiBackend) Todos(ctx context.Context) ([]todo.Todo, error) {
	return b.a.store.Todos(ctx, "")
}

func (b tuiBackend) SetStatus(ctx context.Context, id int64, s todo.Status) (todo.Todo, error) {
	return b.a.store.SetTodoStatus(ctx, id, s, nil, timeNow())
}

func (b tuiBackend) SetNote(ctx context.Context, id int64, note string) (todo.Todo, error) {
	return b.a.store.SetTodoNote(ctx, id, note, timeNow())
}

func (b tuiBackend) Explain(ctx context.Context, id int64, width int, refresh bool) (string, error) {
	t, resp, err := b.a.explainTask(ctx, id, refresh, "", false)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	p := b.printer(&buf, width)
	p.AI(fmt.Sprintf("#%d %s", t.ID, t.Title), resp.Model, resp.Cached, resp.CreatedAt, resp.CostUSD, resp.Text)
	return buf.String(), nil
}

func (b tuiBackend) FixSession(ctx context.Context, id int64) (*osexec.Cmd, error) {
	return b.a.fixSession(ctx, id)
}

// defaultScanner builds command's scanner with its configured scope.
func (a *app) defaultScanner(command string) (core.Scanner, error) {
	switch command {
	case "system":
		return core.NewSystem(a.cfg, a.env, nil)
	case "environment":
		return core.NewEnvironment(a.cfg, a.env)
	case "packages":
		return a.packagesScanner(nil)
	case "repos":
		return a.reposScanner(), nil
	case "files":
		return core.NewFiles(a.cfg, a.env), nil
	case "configs":
		return a.configsScanner(context.Background()), nil
	case "scripts":
		return a.scriptsScanner(), nil
	case "history":
		return core.NewHistory(a.cfg, a.env), nil
	case "ai":
		return a.aiScanner(false), nil
	}
	return nil, fmt.Errorf("unknown command %q", command)
}

// printer renders into buf at width in the backend's color profile.
func (b tuiBackend) printer(buf *bytes.Buffer, width int) *render.Printer {
	p := render.NewProfile(buf, b.profile(), width)
	p.Now = timeNow
	p.Verbose = b.a.flags.verbose
	if b.a.cfg != nil {
		p.Details = b.a.cfg.Display.Details
		p.Glyphs = render.GlyphsFor(b.a.cfg.Display.NerdFonts)
	}
	if b.a.env != nil {
		p.Home = b.a.env.Home
	}
	return p
}

func (b tuiBackend) profile() termenv.Profile {
	switch {
	case b.a.flags.noColor || b.a.cfg.NoColor || os.Getenv("NO_COLOR") != "":
		return termenv.Ascii
	case b.forceColor:
		return termenv.ANSI256
	case b.a.noColorTUI():
		return termenv.Ascii
	}
	return lipgloss.ColorProfile()
}

// noColorTUI is noColor without the redirected-stdout rule, which never
// applies inside the full-screen UI.
func (a *app) noColorTUI() bool {
	return a.flags.noColor || a.cfg.NoColor || lipgloss.ColorProfile() == termenv.Ascii
}
