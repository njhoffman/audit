package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"

	clog "github.com/charmbracelet/log"
	"golang.org/x/term"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/htmlreport"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/log"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// globalFlags are the persistent flags on the root command.
type globalFlags struct {
	config  string
	noColor bool
	width   int
	verbose bool
	debug   bool
	quiet   bool
}

// app is the state every subcommand shares. It is built lazily so that
// --help and --version never touch the config or the database.
type app struct {
	flags   globalFlags
	out     io.Writer
	errOut  io.Writer
	cfg     *config.Config
	cfgPath string
	store   *store.Store
	engine  *core.Engine
	log     *clog.Logger
	env     *exec.Env
	// opener opens a file in the desktop's default application.
	opener func(path string) error
	// interactive reports whether stdin and stdout are terminals.
	interactive func() bool
}

func newApp(out, errOut io.Writer) *app {
	return &app{out: out, errOut: errOut, opener: xdgOpen, interactive: func() bool {
		return isTerminal(out) && term.IsTerminal(int(os.Stdin.Fd())) // #nosec G115 -- fd fits in int
	}}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) // #nosec G115 -- fd fits in int
}

// load reads the config and opens the store.
func (a *app) load() error {
	if a.engine != nil {
		return nil
	}
	a.log = log.New(log.Options{Level: log.LevelFromFlags(a.flags.verbose, a.flags.debug, a.flags.quiet), Out: a.errOut})
	if err := a.ensureConfig(); err != nil {
		return err
	}
	cfg, path, err := config.Load(a.flags.config)
	if err != nil {
		return err
	}
	a.cfg, a.cfgPath = cfg, path
	if path != "" {
		a.log.Debug("config", "path", path)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	a.store = st
	host, _ := os.Hostname()
	a.env = exec.FromOS()
	a.engine = &core.Engine{Store: st, Config: cfg, Host: host}
	return nil
}

// ensureConfig creates the default config file on first run. An explicit
// --config is never created: a missing one is an error from config.Load.
func (a *app) ensureConfig() error {
	if a.flags.config != "" {
		return nil
	}
	path, created, err := config.EnsureDefault()
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	if created && !a.flags.quiet {
		say(a.errOut, "audit: created %s with the default settings\n", path)
	}
	return nil
}

func (a *app) close() {
	if a.store != nil {
		_ = a.store.Close()
	}
}

func (a *app) noColor() bool {
	if a.flags.noColor || os.Getenv("NO_COLOR") != "" || !isTerminal(a.out) {
		return true
	}
	return a.cfg != nil && a.cfg.NoColor
}

// printer writes to stdout, wrapping to the terminal width (unlimited when
// output is redirected, unless --width is given).
func (a *app) printer() *render.Printer {
	width := a.flags.width
	if width == 0 {
		if f, ok := a.out.(*os.File); ok && term.IsTerminal(int(f.Fd())) { // #nosec G115 -- fd fits in int
			if w, _, err := term.GetSize(int(f.Fd())); err == nil { // #nosec G115 -- fd fits in int
				width = w
			}
		}
	}
	p := render.New(a.out, a.noColor(), width)
	p.Verbose = a.flags.verbose
	p.Now = timeNow
	if a.cfg != nil {
		p.Details = a.cfg.Display.Details
	}
	return p
}

func (a *app) progress(enabled bool) progress.Reporter {
	return progress.New(enabled && !a.flags.quiet)
}

// aiClient builds the claude CLI client; level overrides the configured
// analysis level when set.
func (a *app) aiClient(level string) *llm.Client {
	if level != "" {
		a.cfg.AI.AnalysisLevel = level
	}
	return &llm.Client{Runner: exec.NewOSRunner(a.env), Command: a.cfg.AI.Command, Model: a.cfg.AI.Model,
		Timeout: a.cfg.AI.Timeout, Cache: a.store}
}

func (a *app) writeJSON(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeReport saves the HTML report of r and refreshes the index page. It
// returns the report's path.
func (a *app) writeReport(ctx context.Context, r *run.Run) (string, error) {
	todos, err := a.store.Todos(ctx, r.Command)
	if err != nil {
		return "", err
	}
	path := filepath.Join(a.cfg.ReportDir(), htmlreport.FileName(r.Command))
	err = htmlreport.Save(path, func(w io.Writer) error {
		return htmlreport.Write(w, r, htmlreport.Options{Thresholds: a.cfg.Stale.For(r.Command), Todos: todos,
			RescanHint: core.RescanHint(r.Command, r.Scope)})
	})
	if err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	if _, err := a.writeIndex(ctx); err != nil {
		return "", err
	}
	return path, nil
}

// writeIndex writes the overview page linking every command's report.
func (a *app) writeIndex(ctx context.Context) (string, error) {
	statuses, err := a.statuses(ctx)
	if err != nil {
		return "", err
	}
	rows := make([]htmlreport.IndexRow, len(statuses))
	for i, s := range statuses {
		rows[i] = htmlreport.IndexRow{Command: s.Command, Latest: s.Latest, Thresholds: s.Thresholds, Open: s.Open}
		if _, err := os.Stat(filepath.Join(a.cfg.ReportDir(), htmlreport.FileName(s.Command))); err == nil {
			rows[i].Link = htmlreport.FileName(s.Command)
		}
	}
	path := filepath.Join(a.cfg.ReportDir(), "index.html")
	err = htmlreport.Save(path, func(w io.Writer) error { return htmlreport.WriteIndex(w, rows, timeNow()) })
	if err != nil {
		return "", fmt.Errorf("write index: %w", err)
	}
	return path, nil
}

// statuses collects the dashboard rows: last run and open tasks per command.
func (a *app) statuses(ctx context.Context) ([]render.CommandStatus, error) {
	latest, err := a.store.LatestPerCommand(ctx)
	if err != nil {
		return nil, err
	}
	all, err := a.store.Todos(ctx, "")
	if err != nil {
		return nil, err
	}
	byCmd := map[string][]todo.Todo{}
	for _, t := range all {
		byCmd[t.Command] = append(byCmd[t.Command], t)
	}
	out := make([]render.CommandStatus, len(core.Commands))
	for i, c := range core.Commands {
		out[i] = render.CommandStatus{Command: c, Thresholds: a.cfg.Stale.For(c), Open: render.OpenCounts(byCmd[c])}
		if ri, ok := latest[c]; ok {
			out[i].Latest = &ri
		}
	}
	return out, nil
}

func xdgOpen(path string) error {
	c := osexec.Command("xdg-open", path) // #nosec G204 -- path is a report file audit wrote
	c.Stdout, c.Stderr = nil, nil
	if err := c.Start(); err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	return c.Process.Release()
}

// say and sayln write user-facing messages; a failed write to the terminal
// has nowhere better to be reported.
func say(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func sayln(w io.Writer, args ...any) { _, _ = fmt.Fprintln(w, args...) }
