// Package fzf is the fzf interface to the dashboard and the task editor:
// fzf lists the commands or the tasks, and its key bindings call back into
// audit (a hidden helper command, plus todo set) to preview, page, rescan
// and change tasks, then reload the list.
package fzf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/keys"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// Helper is the hidden audit command the bindings call.
const Helper = "fzf-helper"

// FilterEnv carries the task list's fixed filters (priorities, statuses) to
// the helper, encoded by Filter.Encode.
const FilterEnv = "AUDIT_FZF_FILTER"

// Interface builds fzf command lines.
type Interface struct {
	// Self is the audit command the bindings run: the executable and the
	// global flags to repeat, such as -c FILE.
	Self []string
	Keys keys.Map
}

// quote single-quotes s for sh.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// self is the shell command running audit with args; args starting with {
// are fzf placeholders, which fzf quotes itself.
func (in Interface) self(args ...string) string {
	parts := make([]string, 0, len(in.Self)+len(args))
	for _, a := range in.Self {
		parts = append(parts, quote(a))
	}
	for _, a := range args {
		if strings.HasPrefix(a, "{") {
			parts = append(parts, a)
		} else {
			parts = append(parts, quote(a))
		}
	}
	return strings.Join(parts, " ")
}

func (in Interface) helper(args ...string) string {
	return in.self(append([]string{Helper}, args...)...)
}

// delimiters are tried in order for an action's argument; fzf ends the
// argument at the first closing one.
var delimiters = [][2]string{{"(", ")"}, {"[", "]"}, {"{", "}"}, {"<", ">"}, {"~", "~"}, {"!", "!"}, {"@", "@"}, {"#", "#"}, {"%", "%"}}

// act is "name(arg)" with delimiters that do not occur in arg.
func act(name, arg string) string {
	for _, d := range delimiters {
		if !strings.Contains(arg, d[1]) {
			return name + d[0] + arg + d[1]
		}
	}
	return name + ":" + arg // only valid as the last action of a chain
}

// bind is a --bind for action's keys, or "" when it is unbound.
func (in Interface) bind(action string, actions ...string) []string {
	ks := in.Keys[action]
	if len(ks) == 0 {
		return nil
	}
	return []string{"--bind", strings.Join(ks, ",") + ":" + strings.Join(actions, "+")}
}

// headerWidth is where the help wraps; the list gets 40% of the window.
const headerWidth = 56

// header is the help: the first key of each action, wrapped.
func (in Interface) header(hints [][2]string) string {
	var lines []string
	line := ""
	for _, h := range hints {
		ks := in.Keys[h[0]]
		if len(ks) == 0 {
			continue
		}
		part := ks[0] + " " + h[1]
		if line != "" && len(line)+2+len(part) > headerWidth {
			lines, line = append(lines, line), ""
		}
		if line != "" {
			line += "  "
		}
		line += part
	}
	if line != "" && len(line)+len("  esc quit") > headerWidth {
		lines, line = append(lines, line), ""
	}
	if line != "" {
		line += "  "
	}
	return strings.Join(append(lines, line+"esc quit"), "\n")
}

// common are the options of both lists. Lines are padded with spaces, and
// fzf's default field splitting makes the first column {1}. nohidden
// overrides a hidden preview window from FZF_DEFAULT_OPTS.
func common(prompt, header string) []string {
	return []string{
		"--ansi", "--no-sort", "--with-shell", "sh -c",
		"--prompt", prompt, "--header", header, "--preview-window", "right,60%,wrap,nohidden",
	}
}

// DashboardArgs lists the commands with their saved report as the preview.
func (in Interface) DashboardArgs() []string {
	reload := act("reload", in.helper("lines", "dashboard"))
	args := common("audit> ", in.header([][2]string{
		{keys.Open, "report"}, {keys.Rescan, "rescan"}, {keys.ShowTasks, "tasks"},
	}))
	args = append(args, "--preview", in.helper("preview", "report", "{1}"))
	args = append(args, in.bind(keys.Open, act("execute", in.helper("page", "report", "{1}")))...)
	args = append(args, in.bind(keys.Rescan, act("execute", in.helper("rescan", "{1}")), reload, "refresh-preview")...)
	args = append(args, in.bind(keys.ShowTasks, act("execute", in.self("todo", "--fzf")), reload, "refresh-preview")...)
	return args
}

// TasksArgs lists the tasks of state with the task as the preview. The
// prompt carries the state, so the helper can reload the same list.
func (in Interface) TasksArgs(state State, query string) []string {
	reload := act("reload", in.helper("lines", "tasks"))
	args := common(state.Prompt(), in.header([][2]string{
		{keys.Open, "details"}, {keys.Editor, "editor"}, {keys.StatusOpen, "open"}, {keys.StatusDoing, "in progress"},
		{keys.StatusDone, "done"}, {keys.StatusWontDo, "won't do"}, {keys.Note, "note"}, {keys.ExplainTask, "explain"},
		{keys.CycleCommand, "command"}, {keys.ToggleClosed, "closed"},
	}))
	if query != "" {
		args = append(args, "--query", query)
	}
	args = append(args, "--preview", in.helper("preview", "task", "{1}"))
	args = append(args, in.bind(keys.Open, act("execute", in.helper("page", "task", "{1}")))...)
	args = append(args, in.bind(keys.Editor, act("execute", in.helper("edit", "{1}")))...)
	args = append(args, in.bind(keys.ExplainTask, act("execute", in.helper("page", "explain", "{1}")))...)
	for _, s := range []struct {
		action string
		status todo.Status
	}{{keys.StatusOpen, todo.Open}, {keys.StatusDoing, todo.InProgress}, {keys.StatusDone, todo.Done}, {keys.StatusWontDo, todo.WontDo}} {
		args = append(args, in.bind(s.action, act("execute-silent", in.self("todo", "set", "{1}", string(s.status))), reload, "refresh-preview")...)
	}
	args = append(args, in.bind(keys.Note, act("execute", in.helper("note", "{1}")), reload, "refresh-preview")...)
	args = append(args, in.bind(keys.ToggleClosed, act("transform", in.helper("toggle-closed")))...)
	args = append(args, in.bind(keys.CycleCommand, act("transform", in.helper("cycle-command")))...)
	return args
}

// Switch is the transform output that moves the task list to state.
func (in Interface) Switch(state State) string {
	return act("change-prompt", state.Prompt()) + "+" + act("reload", in.helper("lines", "tasks")) + "+first"
}

// State is the task list's toggles, carried in fzf's prompt.
type State struct {
	Command string // "" for every command
	Closed  bool
}

// Prompt is "tasks> ", "tasks system> ", "tasks +closed> " or both.
func (s State) Prompt() string {
	p := "tasks"
	if s.Command != "" {
		p += " " + s.Command
	}
	if s.Closed {
		p += " +closed"
	}
	return p + "> "
}

// ParsePrompt reads the state back from fzf's $FZF_PROMPT.
func ParsePrompt(p string) State {
	var s State
	for i, f := range strings.Fields(strings.TrimSuffix(strings.TrimSpace(p), ">")) {
		switch {
		case i == 0:
		case f == "+closed":
			s.Closed = true
		default:
			s.Command = f
		}
	}
	return s
}

// Filter are the task list's fixed filters, from audit todo's flags.
type Filter struct {
	Priorities []todo.Priority
	Statuses   []todo.Status
}

// Encode is the value of FilterEnv.
func (f Filter) Encode() string {
	var parts []string
	for _, p := range f.Priorities {
		parts = append(parts, "p:"+string(p))
	}
	for _, s := range f.Statuses {
		parts = append(parts, "s:"+string(s))
	}
	return strings.Join(parts, ",")
}

// DecodeFilter reads FilterEnv.
func DecodeFilter(v string) Filter {
	var f Filter
	for _, part := range strings.Split(v, ",") {
		switch k, val, _ := strings.Cut(part, ":"); k {
		case "p":
			f.Priorities = append(f.Priorities, todo.Priority(val))
		case "s":
			f.Statuses = append(f.Statuses, todo.Status(val))
		}
	}
	return f
}

// TaskLines are the tasks of state and f, sorted, one line each: the ID
// (the field the bindings use), then priority, status, command and title,
// with home shown as ~.
func TaskLines(ts []todo.Todo, state State, f Filter, home string) []string {
	ts = todo.Filter{Command: state.Command, ShowClosed: state.Closed, Priorities: f.Priorities, Statuses: f.Statuses}.Apply(ts)
	todo.Sort(ts)
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, fmt.Sprintf("%-5d %-10s %-11s %-11s %s", t.ID, t.Priority, t.Status.Label(), t.Command, render.Tilde(t.Title, home)))
	}
	return out
}

// Commands are the commands that have tasks, in task order, for cycling the
// command filter.
func Commands(ts []todo.Todo) []string {
	var out []string
	for _, t := range ts {
		if !slices.Contains(out, t.Command) {
			out = append(out, t.Command)
		}
	}
	return out
}

// Next is the command after cur in cmds, then "" (every command).
func Next(cmds []string, cur string) string {
	if cur == "" {
		if len(cmds) > 0 {
			return cmds[0]
		}
		return ""
	}
	if i := slices.Index(cmds, cur); i >= 0 && i+1 < len(cmds) {
		return cmds[i+1]
	}
	return ""
}

// DashboardLines are the commands, one line each: the name (the field the
// bindings use), last run, age, finding counts and open tasks.
func DashboardLines(rows []render.CommandStatus, now time.Time) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		last, age, findings := "never", "-", "-"
		if r.Latest != nil {
			last = r.Latest.FinishedAt.Local().Format("2006-01-02 15:04")
			age = run.HumanAge(now.Sub(r.Latest.FinishedAt))
			findings = render.CountsText(r.Latest.Counts)
		}
		out = append(out, fmt.Sprintf("%-12s %-16s %-8s %-28s %s", r.Command, last, age, findings, render.TasksText(r.Open)))
	}
	return out
}

// Run starts fzf on lines with args. Leaving fzf (esc) or an empty list is
// not an error; whatever fzf prints on accept is discarded.
func Run(ctx context.Context, args, lines, env []string) error {
	path, err := osexec.LookPath("fzf")
	if err != nil {
		return errors.New("the fzf interface needs fzf (0.51 or later) on PATH")
	}
	c := osexec.CommandContext(ctx, path, args...) // #nosec G204 -- fzf with arguments we build
	c.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	c.Stdout, c.Stderr = io.Discard, os.Stderr
	c.Env = append(os.Environ(), env...)
	err = c.Run()
	var exit *osexec.ExitError
	if errors.As(err, &exit) {
		switch exit.ExitCode() {
		case 1, 130: // no match, aborted
			return nil
		}
		return fmt.Errorf("fzf exited with status %d", exit.ExitCode())
	}
	return err
}
