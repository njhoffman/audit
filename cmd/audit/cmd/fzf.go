package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/fzf"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/todo"
	"github.com/njhoffman/audit/internal/tui"
)

// useFzf reports whether c opens the fzf interface: its --fzf flag when
// given, else tui.interface.
func (a *app) useFzf(c *cobra.Command) bool {
	if f := c.Flags().Lookup("fzf"); f != nil && f.Changed {
		return f.Value.String() == "true"
	}
	return a.cfg.TUI.Interface == config.InterfaceFzf
}

// fzfInterface runs this audit binary, with the same config file, from the
// fzf bindings.
func (a *app) fzfInterface() fzf.Interface {
	exe := packages.SelfCommand
	if exe == "" {
		exe = "audit"
	}
	self := []string{exe}
	if a.flags.config != "" {
		cfg := a.flags.config
		if abs, err := filepath.Abs(cfg); err == nil {
			cfg = abs
		}
		self = append(self, "-c", cfg)
	}
	if a.flags.noColor {
		self = append(self, "-n")
	}
	return fzf.Interface{Self: self, Keys: a.cfg.TUI.FzfKeys}
}

func runFzfDashboard(ctx context.Context, a *app) error {
	rows, err := a.statuses(ctx)
	if err != nil {
		return err
	}
	return fzf.Run(ctx, a.fzfInterface().DashboardArgs(), fzf.DashboardLines(rows, timeNow()), nil)
}

func runFzfTasks(ctx context.Context, a *app, flt todo.Filter) error {
	ts, err := a.store.Todos(ctx, "")
	if err != nil {
		return err
	}
	state := fzf.State{Command: flt.Command, Closed: flt.ShowClosed}
	f := fzf.Filter{Priorities: flt.Priorities, Statuses: flt.Statuses}
	return fzf.Run(ctx, a.fzfInterface().TasksArgs(state, flt.Search), fzf.TaskLines(ts, state, f, a.env.Home),
		[]string{fzf.FilterEnv + "=" + f.Encode()})
}

// newFzfHelperCmd is what the fzf bindings call; it is hidden because its
// arguments are an internal protocol between audit and its own fzf lists.
func newFzfHelperCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:    fzf.Helper + " OP [ARG...]",
		Short:  "Callbacks of the fzf interface",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			op, rest := args[0], args[1:]
			switch op {
			case "lines", "preview", "toggle-closed", "cycle-command":
				return a.fzfQuiet(ctx, op, rest)
			}
			// The rest run in fzf's execute, on the terminal: an error has to
			// stay on screen until it is read.
			if err := a.fzfInteractive(ctx, op, rest); err != nil {
				sayln(a.errOut, "audit: "+err.Error())
				say(a.errOut, "press enter to go back ")
				_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			}
			return nil
		},
	}
}

func (a *app) fzfQuiet(ctx context.Context, op string, args []string) error {
	in := a.fzfInterface()
	state := fzf.ParsePrompt(os.Getenv("FZF_PROMPT"))
	switch {
	case op == "lines" && len(args) == 1 && args[0] == "dashboard":
		rows, err := a.statuses(ctx)
		if err != nil {
			return err
		}
		return writeLines(a.out, fzf.DashboardLines(rows, timeNow()))
	case op == "lines" && len(args) == 1 && args[0] == "tasks":
		ts, err := a.store.Todos(ctx, "")
		if err != nil {
			return err
		}
		return writeLines(a.out, fzf.TaskLines(ts, state, fzf.DecodeFilter(os.Getenv(fzf.FilterEnv)), a.env.Home))
	case op == "preview" && len(args) == 2:
		width, _ := strconv.Atoi(os.Getenv("FZF_PREVIEW_COLUMNS"))
		text, err := a.fzfRender(ctx, args[0], args[1], width)
		if err != nil {
			return err
		}
		say(a.out, "%s", text)
		return nil
	case op == "toggle-closed":
		state.Closed = !state.Closed
		sayln(a.out, in.Switch(state))
		return nil
	case op == "cycle-command":
		ts, err := a.store.Todos(ctx, "")
		if err != nil {
			return err
		}
		state.Command = fzf.Next(fzf.Commands(ts), state.Command)
		sayln(a.out, in.Switch(state))
		return nil
	}
	return fmt.Errorf("%s: bad arguments %q", fzf.Helper, append([]string{op}, args...))
}

func (a *app) fzfInteractive(ctx context.Context, op string, args []string) error {
	switch {
	case op == "page" && len(args) == 2:
		if args[0] == "explain" {
			sayln(a.errOut, "asking the AI...")
		}
		width := 0
		if term.IsTerminal(int(os.Stdout.Fd())) { // #nosec G115 -- fd fits in int
			width, _, _ = term.GetSize(int(os.Stdout.Fd())) // #nosec G115 -- fd fits in int
		}
		text, err := a.fzfRender(ctx, args[0], args[1], width)
		if err != nil {
			return err
		}
		return page(text)
	case op == "rescan" && len(args) == 1:
		s, err := a.defaultScanner(args[0])
		if err != nil {
			return err
		}
		res, err := a.engine.Execute(ctx, s, a.progress(true))
		if err != nil {
			return err
		}
		sayln(a.errOut, fmt.Sprintf("%s scanned; %d task(s) updated", args[0], res.TaskChanges))
		return nil
	case op == "note" && len(args) == 1:
		t, err := a.fzfTask(ctx, args[0])
		if err != nil {
			return err
		}
		say(a.errOut, "\x1b[H\x1b[2J") // fzf leaves its screen behind
		sayln(a.errOut, fmt.Sprintf("#%d %s", t.ID, t.Title))
		if t.Note != "" {
			sayln(a.errOut, "current note: "+t.Note)
		}
		say(a.errOut, "note #%d (empty keeps it, - clears it): ", t.ID)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		switch line = strings.TrimSpace(line); line {
		case "":
			return nil
		case "-":
			line = ""
		}
		_, err = a.store.SetTodoNote(ctx, t.ID, line, timeNow())
		return err
	case op == "edit" && len(args) == 1:
		t, err := a.fzfTask(ctx, args[0])
		if err != nil {
			return err
		}
		c, cleanup, err := tui.EditorCommand(t)
		if err != nil {
			return err
		}
		defer cleanup()
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run()
	}
	return fmt.Errorf("%s: bad arguments %q", fzf.Helper, append([]string{op}, args...))
}

func (a *app) fzfTask(ctx context.Context, arg string) (todo.Todo, error) {
	id, err := parseID(arg)
	if err != nil {
		return todo.Todo{}, err
	}
	return a.store.GetTodo(ctx, id)
}

// fzfRender renders a command's saved report, a task or an AI explanation
// of a task, in color.
func (a *app) fzfRender(ctx context.Context, kind, arg string, width int) (string, error) {
	b := tuiBackend{a: a, forceColor: true}
	switch kind {
	case "report":
		text, ok, err := b.Report(ctx, arg, width, true)
		if err != nil || ok {
			return text, err
		}
		return fmt.Sprintf("%s has never run; %s rescans it.\n", arg, strings.Join(a.cfg.TUI.FzfKeys["rescan"], "/")), nil
	case "task":
		t, err := a.fzfTask(ctx, arg)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		p := b.printer(&buf, width)
		p.Todo(t)
		return buf.String(), nil
	case "explain":
		id, err := parseID(arg)
		if err != nil {
			return "", err
		}
		return b.Explain(ctx, id, width, false)
	}
	return "", fmt.Errorf("nothing to render as %q", kind)
}

// page shows text in $PAGER, or prints it when stdout is not a terminal.
// The default less turns off quit-if-one-screen and no-init from $LESS,
// which would flash a short report and drop back to fzf.
func page(text string) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) { // #nosec G115 -- fd fits in int
		_, err := io.WriteString(os.Stdout, text)
		return err
	}
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less -R -+F -+X"
	}
	c := osexec.Command("sh", "-c", pager) // #nosec G204 G702 -- the user's own $PAGER
	c.Stdin, c.Stdout, c.Stderr = strings.NewReader(text), os.Stdout, os.Stderr
	return c.Run()
}

func writeLines(w io.Writer, lines []string) error {
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}
