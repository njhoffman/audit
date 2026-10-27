// Package keys names the actions of the interactive dashboard, the screens
// each one works on and the keys bound to them by default. The config
// package checks user bindings against it and the tui package builds its key
// bindings from it.
package keys

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// Screen is one view of the dashboard.
type Screen string

// Screens.
const (
	Dashboard Screen = "dashboard"
	Report    Screen = "report"
	Tasks     Screen = "tasks"
	Task      Screen = "task"
	Explain   Screen = "explain"
)

var (
	allScreens = []Screen{Dashboard, Report, Tasks, Task, Explain}
	// scrolling are the screens with a viewport or a table.
	scrolling = []Screen{Report, Tasks, Task, Explain}
)

// Reserved is always quit and cannot be bound to an action.
const Reserved = "ctrl+c"

// Action names.
const (
	Quit         = "quit"
	Back         = "back"
	ShowTasks    = "tasks"
	Up           = "up"
	Down         = "down"
	PageUp       = "page_up"
	PageDown     = "page_down"
	HalfPageUp   = "half_page_up"
	HalfPageDown = "half_page_down"
	Top          = "top"
	Bottom       = "bottom"
	Open         = "open"
	Rescan       = "rescan"
	Details      = "toggle_details"
	Reask        = "reask"
	ExplainTask  = "explain"
	Editor       = "editor"
	FixTask      = "fix"
	StatusOpen   = "status_open"
	StatusDoing  = "status_in_progress"
	StatusDone   = "status_done"
	StatusWontDo = "status_wont_do"
	Note         = "note"
	Search       = "search"
	ToggleClosed = "toggle_closed"
	CycleCommand = "cycle_command"
)

// Action is something a key does.
type Action struct {
	Name    string
	Help    string
	Screens []Screen
	Default []string
}

// Actions is every action, in the order the config template lists them.
var Actions = []Action{
	{Quit, "quit", allScreens, []string{"q"}},
	{Back, "back", allScreens, []string{"esc", "backspace", "h", "left"}},
	{ShowTasks, "tasks", []Screen{Dashboard, Report, Task, Explain}, []string{"t"}},
	{Up, "up", allScreens, []string{"k", "up"}},
	{Down, "down", allScreens, []string{"j", "down"}},
	{PageUp, "page up", scrolling, []string{"pgup", "b"}},
	{PageDown, "page down", scrolling, []string{"pgdown", "f", " "}},
	{HalfPageUp, "half page up", scrolling, []string{"ctrl+u", "u"}},
	{HalfPageDown, "half page down", scrolling, []string{"ctrl+d"}},
	{Top, "top", scrolling, []string{"home", "g"}},
	{Bottom, "bottom", scrolling, []string{"end", "G"}},
	{Open, "open", []Screen{Dashboard, Tasks}, []string{"enter", "l", "right"}},
	{Rescan, "rescan", []Screen{Dashboard, Report}, []string{"r"}},
	{Details, "details", []Screen{Report}, []string{"x"}},
	{Reask, "ask again", []Screen{Explain}, []string{"r"}},
	{ExplainTask, "explain", []Screen{Tasks, Task}, []string{"e"}},
	{Editor, "editor", []Screen{Tasks, Task}, []string{"v"}},
	{FixTask, "fix with AI", []Screen{Tasks, Task}, []string{"F"}},
	{StatusOpen, "open", []Screen{Tasks}, []string{"o"}},
	{StatusDoing, "in progress", []Screen{Tasks}, []string{"i"}},
	{StatusDone, "done", []Screen{Tasks}, []string{"d"}},
	{StatusWontDo, "won't do", []Screen{Tasks}, []string{"w"}},
	{Note, "note", []Screen{Tasks}, []string{"n"}},
	{Search, "find", []Screen{Tasks}, []string{"/"}},
	{ToggleClosed, "closed", []Screen{Tasks}, []string{"a"}},
	{CycleCommand, "command", []Screen{Tasks}, []string{"c"}},
}

// Map holds the keys of each action by name.
type Map map[string][]string

// Defaults returns a fresh copy of the default bindings.
func Defaults() Map {
	m := make(Map, len(Actions))
	for _, a := range Actions {
		m[a.Name] = slices.Clone(a.Default)
	}
	return m
}

// Lookup returns the action called name.
func Lookup(name string) (Action, bool) {
	for _, a := range Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}

// Validate reports unknown actions, blank or reserved keys, and a key bound
// to two actions on the same screen. An action with no keys is unbound.
func Validate(m Map) error {
	var errs []error
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := Lookup(n); !ok {
			errs = append(errs, fmt.Errorf("unknown action %q", n))
			continue
		}
		for _, k := range m[n] {
			switch k {
			case "":
				errs = append(errs, fmt.Errorf("%s: empty key", n))
			case Reserved:
				errs = append(errs, fmt.Errorf("%s: %s always quits and cannot be bound", n, Reserved))
			}
		}
	}
	errs = append(errs, conflicts(m, allScreens, Actions)...)
	return errors.Join(errs...)
}

// conflicts reports keys bound to two actions on one of screens.
func conflicts(m Map, screens []Screen, actions []Action) []error {
	var errs []error
	for _, s := range screens {
		owner := map[string]string{}
		for _, a := range actions {
			if !slices.Contains(a.Screens, s) {
				continue
			}
			for _, k := range m[a.Name] {
				if prev, ok := owner[k]; ok && prev != a.Name {
					errs = append(errs, fmt.Errorf("%q is bound to both %s and %s on the %s screen", k, prev, a.Name, s))
					continue
				}
				owner[k] = a.Name
			}
		}
	}
	return errs
}

// Label is how a key is shown in help.
func Label(k string) string {
	switch k {
	case " ":
		return "space"
	case "pgdown":
		return "pgdn"
	}
	return k
}

// First is the label of the first key of action in m, or "" when unbound.
func (m Map) First(action string) string {
	if ks := m[action]; len(ks) > 0 {
		return Label(ks[0])
	}
	return ""
}

// FzfScreens are the screens of the fzf interface: the command list and the
// task list. An action works there on the screens it shares with the
// dashboard.
var FzfScreens = []Screen{Dashboard, Tasks}

// fzfDefaults are the keys of the actions the fzf interface has. Typing goes
// to fzf's query, so they use alt- rather than plain letters; scrolling,
// searching and leaving are fzf's own keys.
var fzfDefaults = Map{
	Open:         {"enter"},
	Rescan:       {"alt-r"},
	ShowTasks:    {"alt-t"},
	ExplainTask:  {"alt-e"},
	Editor:       {"alt-v"},
	FixTask:      {"alt-f"},
	StatusOpen:   {"alt-o"},
	StatusDoing:  {"alt-i"},
	StatusDone:   {"alt-d"},
	StatusWontDo: {"alt-w"},
	Note:         {"alt-n"},
	ToggleClosed: {"alt-a"},
	CycleCommand: {"alt-c"},
}

// fzfReserved leave fzf.
var fzfReserved = []string{"esc", "ctrl-c", "ctrl-g", "ctrl-q"}

// FzfDefaults returns a fresh copy of the default fzf bindings.
func FzfDefaults() Map {
	m := make(Map, len(fzfDefaults))
	for k, v := range fzfDefaults {
		m[k] = slices.Clone(v)
	}
	return m
}

// FzfActions are the actions of the fzf interface, in Actions order.
func FzfActions() []Action {
	var out []Action
	for _, a := range Actions {
		if _, ok := fzfDefaults[a.Name]; ok {
			a.Screens = slices.DeleteFunc(slices.Clone(a.Screens), func(s Screen) bool { return !slices.Contains(FzfScreens, s) })
			out = append(out, a)
		}
	}
	return out
}

// ValidateFzf is Validate for fzf bindings (fzf key names such as alt-d or
// ctrl-x): it also rejects actions fzf lacks, the keys that leave fzf, and
// single printable characters, which would no longer reach the query.
func ValidateFzf(m Map) error {
	var errs []error
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := Lookup(n); !ok {
			errs = append(errs, fmt.Errorf("unknown action %q", n))
			continue
		}
		if _, ok := fzfDefaults[n]; !ok {
			errs = append(errs, fmt.Errorf("%s is not available in fzf", n))
			continue
		}
		for _, k := range m[n] {
			switch {
			case k == "":
				errs = append(errs, fmt.Errorf("%s: empty key", n))
			case slices.Contains(fzfReserved, k):
				errs = append(errs, fmt.Errorf("%s: %s leaves fzf and cannot be bound", n, k))
			case len([]rune(k)) == 1:
				errs = append(errs, fmt.Errorf("%s: %q would stop typing it into the query; use alt-%s or ctrl-%s", n, k, k, k))
			}
		}
	}
	errs = append(errs, conflicts(m, FzfScreens, FzfActions())...)
	return errors.Join(errs...)
}
