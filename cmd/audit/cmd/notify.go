package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/todo"
)

// openTaskIDs are the IDs of the tasks open (or in progress) now.
func (a *app) openTaskIDs(ctx context.Context) map[int64]bool {
	ts, err := a.store.Todos(ctx, "")
	if err != nil {
		a.log.Warn("read tasks before the rescan", "err", err)
		return nil
	}
	out := map[int64]bool{}
	for _, t := range ts {
		if !t.Status.Closed() {
			out[t.ID] = true
		}
	}
	return out
}

// newUrgentTasks are the open tasks at or above least that were not open
// before: created or reopened by the rescan.
func newUrgentTasks(before map[int64]bool, after []todo.Todo, least todo.Priority) []todo.Todo {
	var out []todo.Todo
	for _, t := range after {
		if !t.Status.Closed() && !before[t.ID] && t.Priority.Rank() >= least.Rank() {
			out = append(out, t)
		}
	}
	todo.Sort(out)
	return out
}

// hasSessionBus reports whether a desktop notification can be delivered:
// a session bus address, or the user bus socket systemd user services see.
func hasSessionBus(env *exec.Env) bool {
	if env.Get("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	if rt := env.Get("XDG_RUNTIME_DIR"); rt != "" {
		if _, err := os.Stat(filepath.Join(rt, "bus")); err == nil {
			return true
		}
	}
	return false
}

// notifyNewTasks sends one notification about the urgent tasks the rescan
// opened, when notify.enabled is set and the run has no terminal. Failures
// are logged; the scans are saved either way.
func (a *app) notifyNewTasks(ctx context.Context, before map[int64]bool) {
	if !a.cfg.Notify.Enabled || before == nil || a.interactive() {
		return
	}
	after, err := a.store.Todos(ctx, "")
	if err != nil {
		a.log.Warn("read tasks after the rescan", "err", err)
		return
	}
	least, err := todo.ParsePriority(a.cfg.Notify.MinPriority)
	if err != nil {
		return
	}
	ts := newUrgentTasks(before, after, least)
	if len(ts) == 0 {
		return
	}
	if !hasSessionBus(a.env) {
		a.log.Info("no session bus; skipping the notification", "tasks", len(ts))
		return
	}
	title := fmt.Sprintf("audit: %d new %s task(s)", len(ts), least)
	if least != todo.High {
		title = fmt.Sprintf("audit: %d new task(s) at %s or above", len(ts), least)
	}
	var lines []string
	for _, t := range ts[:min(len(ts), 5)] {
		lines = append(lines, fmt.Sprintf("#%d %s: %s", t.ID, t.Command, t.Title))
	}
	if len(ts) > 5 {
		lines = append(lines, fmt.Sprintf("and %d more", len(ts)-5))
	}
	lines = append(lines, "audit todo lists them.")
	r := a.env.Run(ctx, "notify-send", []string{"--app-name=audit", title, strings.Join(lines, "\n")}, exec.Options{Timeout: 10 * time.Second})
	if !r.OK() {
		a.log.Warn("notify-send failed", "err", strings.TrimSpace(r.Stderr))
	}
}
