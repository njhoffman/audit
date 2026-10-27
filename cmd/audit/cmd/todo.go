package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

func parseID(s string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimPrefix(s, "#"), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid task id %q", s)
	}
	return id, nil
}

func newTodoCmd(a *app) *cobra.Command {
	var (
		command     string
		priorities  []string
		statuses    []string
		all         bool
		search      string
		asJSON      bool
		interactive bool
		useFzf      bool
		html, open  bool
		serve       bool
		port        int
	)
	c := &cobra.Command{
		Use:     "todo",
		Aliases: []string{"todos", "tasks"},
		Short:   "List and update the tasks scans create",
		Long: `Every issue and suggestion a scan finds becomes a task: errors and
criticals are high priority, warnings medium, notices low, and suggestions
suggestion. Info findings of one check are rolled into a single low-priority
task. Rescans keep tasks in sync: new findings add tasks, findings that are
gone resolve theirs, and a task you mark won't-do stays that way.

Without a subcommand, open and in-progress tasks are listed.

--html writes tasks.html next to the reports: every task, searchable and
filterable in the browser. --serve serves the same page on 127.0.0.1 with
buttons that change status and notes; the URL it prints carries a per-run
token that every request needs.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			flt := todo.Filter{Command: command, ShowClosed: all, Search: search}
			for _, p := range splitList(priorities) {
				pr, err := todo.ParsePriority(p)
				if err != nil {
					return err
				}
				flt.Priorities = append(flt.Priorities, pr)
			}
			for _, s := range splitList(statuses) {
				st, err := todo.ParseStatus(s)
				if err != nil {
					return err
				}
				flt.Statuses = append(flt.Statuses, st)
			}
			if interactive || c.Flags().Changed("fzf") && useFzf {
				if a.useFzf(c) {
					if !a.interactive() {
						return fmt.Errorf("--fzf needs a terminal")
					}
					return runFzfTasks(c.Context(), a, flt)
				}
				return runTodoEditor(c.Context(), a, flt)
			}
			if serve {
				return a.serveTasks(c.Context(), port, open, nil)
			}
			if html || open {
				path, err := a.writeTasksPage(c.Context())
				if err != nil {
					return err
				}
				if _, err := a.writeIndex(c.Context()); err != nil {
					return err
				}
				if open {
					if err := a.opener(path); err != nil {
						return err
					}
				}
				sayln(a.errOut, "tasks: "+path)
				return nil
			}
			ts, err := a.store.Todos(c.Context(), "")
			if err != nil {
				return err
			}
			ts = flt.Apply(ts)
			todo.Sort(ts)
			if asJSON {
				if ts == nil {
					ts = []todo.Todo{}
				}
				return a.writeJSON(ts)
			}
			a.printer().Todos(ts)
			return nil
		},
	}
	fl := c.Flags()
	fl.StringVarP(&command, "cmd", "C", "", "only tasks of this command")
	fl.StringSliceVarP(&priorities, "priority", "p", nil, "only these priorities: high, medium, low, suggestion")
	fl.StringSliceVarP(&statuses, "status", "S", nil, "only these statuses: open, in-progress, done, wont-do, resolved")
	fl.BoolVarP(&all, "all", "a", false, "include closed tasks (done, won't do, resolved)")
	fl.StringVarP(&search, "find", "f", "", "only tasks whose title, key or note contains this text")
	fl.BoolVarP(&asJSON, "json", "j", false, "print tasks as JSON")
	fl.BoolVarP(&interactive, "interactive", "i", false, "browse and change tasks in a terminal UI")
	fl.BoolVarP(&useFzf, "fzf", "F", false, "browse and change tasks in fzf (implies -i; default tui.interface)")
	fl.BoolVarP(&html, "html", "H", false, "write the searchable tasks page (tasks.html in the report directory)")
	fl.BoolVarP(&open, "open", "o", false, "like --html, then open it; with --serve, open the live page")
	fl.BoolVarP(&serve, "serve", "s", false, "serve the tasks page on 127.0.0.1, saving status and note changes")
	fl.IntVarP(&port, "port", "P", 0, "port for --serve (default: any free port)")
	c.MarkFlagsMutuallyExclusive("interactive", "serve")
	c.MarkFlagsMutuallyExclusive("fzf", "serve")
	c.MarkFlagsMutuallyExclusive("fzf", "html")
	c.MarkFlagsMutuallyExclusive("fzf", "json")
	c.MarkFlagsMutuallyExclusive("interactive", "html")
	c.MarkFlagsMutuallyExclusive("json", "serve")
	c.MarkFlagsMutuallyExclusive("json", "html")

	c.AddCommand(newTodoShowCmd(a), newTodoSetCmd(a), newTodoNoteCmd(a), newTodoAddCmd(a), newTodoRmCmd(a), newTodoExplainCmd(a), newTodoFixCmd(a))
	return c
}

func newTodoShowCmd(a *app) *cobra.Command {
	var asJSON, lines bool
	c := &cobra.Command{
		Use:   "show ID",
		Short: "Show every field of a task",
		Long: `Show every field of a task, including all of its detail lines.

--lines prints only the detail lines, one per line. Tasks that collect lint
or syntax errors (shellcheck, parse failures) list them as FILE:LINE: message,
which editors read as a quickfix list:

  vim -q <(audit todo show 12 -l)`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			t, err := a.store.GetTodo(c.Context(), id)
			if err != nil {
				return err
			}
			switch {
			case asJSON:
				return a.writeJSON(t)
			case lines:
				for _, d := range t.Details {
					sayln(a.out, d)
				}
				return nil
			}
			a.printer().Todo(t)
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the task as JSON")
	c.Flags().BoolVarP(&lines, "lines", "l", false, "print only the detail lines (FILE:LINE: message for lint tasks)")
	c.MarkFlagsMutuallyExclusive("json", "lines")
	return c
}

func newTodoSetCmd(a *app) *cobra.Command {
	var note string
	c := &cobra.Command{
		Use:   "set ID STATUS",
		Short: "Change a task's status (open, in-progress, done, wont-do, resolved)",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			st, err := todo.ParseStatus(args[1])
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			var notePtr *string
			if c.Flags().Changed("note") {
				notePtr = &note
			}
			t, err := a.store.SetTodoStatus(c.Context(), id, st, notePtr, timeNow())
			if err != nil {
				return err
			}
			say(a.out, "#%d %s: %s\n", t.ID, t.Status.Label(), t.Title)
			return nil
		},
	}
	c.Flags().StringVarP(&note, "note", "N", "", "also set the task's note")
	return c
}

func newTodoNoteCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "note ID TEXT...",
		Short: "Set a task's note (an empty TEXT clears it)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			t, err := a.store.SetTodoNote(c.Context(), id, strings.Join(args[1:], " "), timeNow())
			if err != nil {
				return err
			}
			say(a.out, "#%d note updated\n", t.ID)
			return nil
		},
	}
}

func newTodoAddCmd(a *app) *cobra.Command {
	var (
		priority string
		command  string
		hint     string
		note     string
	)
	c := &cobra.Command{
		Use:   "add TITLE...",
		Short: "Add a task by hand",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			pr, err := todo.ParsePriority(priority)
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			now := timeNow()
			if command == "" {
				command = "manual"
			}
			t := todo.Todo{Key: store.NextManualKey(command, now), Command: command, Title: strings.Join(args, " "),
				Hint: hint, Note: note, Priority: pr, Status: todo.Open, Source: todo.Manual,
				CreatedAt: now, UpdatedAt: now, LastSeenAt: now}
			ts := []todo.Todo{t}
			if err := a.store.SaveTodos(c.Context(), ts); err != nil {
				return err
			}
			say(a.out, "#%d added\n", ts[0].ID)
			return nil
		},
	}
	fl := c.Flags()
	fl.StringVarP(&priority, "priority", "p", "medium", "high, medium, low or suggestion")
	fl.StringVarP(&command, "cmd", "C", "", "file the task under this command (default manual)")
	fl.StringVarP(&hint, "hint", "H", "", "how to do it")
	fl.StringVarP(&note, "note", "N", "", "a note")
	return c
}

func newTodoRmCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "rm ID",
		Short: "Delete a task added by hand (scan tasks are closed with set ID wont-do)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := parseID(args[0])
			if err != nil {
				return err
			}
			if err := a.load(); err != nil {
				return err
			}
			if err := a.store.DeleteTodo(c.Context(), id); err != nil {
				return err
			}
			say(a.out, "#%d deleted\n", id)
			return nil
		},
	}
}
