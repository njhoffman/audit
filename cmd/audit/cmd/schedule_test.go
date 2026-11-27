package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

func TestSchedule(t *testing.T) {
	cfgHome, _ := env(t)
	old := packages.SelfCommand
	packages.SelfCommand = "/usr/local/bin/audit"
	t.Cleanup(func() { packages.SelfCommand = old })
	f := &exec.Fake{}
	f.AddOutput("", "systemctl", "--user", "daemon-reload")
	f.AddOutput("", "systemctl", "--user", "enable", "--now", "audit.timer")
	f.AddOutput("", "systemctl", "--user", "disable", "--now", "audit.timer")
	f.AddOutput("enabled\n", "systemctl", "--user", "is-enabled", "audit.timer")
	f.AddOutput("active\n", "systemctl", "--user", "is-active", "audit.timer")
	f.AddOutput("NextElapseUSecRealtime=Fri 2026-11-27 00:07:12 CST\nLastTriggerUSec=n/a\n", "systemctl", "--user", "show", "audit.timer")
	f.AddOutput("Result=success\nExecMainStatus=0\n", "systemctl", "--user", "show", "audit.service")
	setup := func(a *app) { a.runner = f }
	dir := filepath.Join(cfgHome, "systemd", "user")

	if r := runArgsWith(t, setup, "schedule"); r.e != nil || !strings.Contains(r.out, "Not installed") {
		t.Fatalf("status before: %v %q", r.e, r.out)
	}
	r := runArgsWith(t, setup, "schedule", "install", "-N")
	if r.e != nil || !strings.Contains(r.out, "ExecStart=/usr/local/bin/audit -r -q -O system,environment,repos,files,configs,scripts,history,ai") {
		t.Fatalf("dry run: %v\n%s", r.e, r.out)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("a dry run writes nothing")
	}
	writeConfig(t, cfgHome, "schedule: {calendar: hourly, commands: [repos], ai: true}\n")
	r = runArgsWith(t, setup, "schedule", "install")
	if r.e != nil || !strings.Contains(r.out, "Installed audit.timer (hourly): audit -r -q -O repos -A") || !strings.Contains(r.out, "cost money") {
		t.Fatalf("install: %v %q", r.e, r.out)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "audit.timer")); !strings.Contains(string(b), "OnCalendar=hourly") { // #nosec G304 -- test file
		t.Errorf("timer file:\n%s", b)
	}
	r = runArgsWith(t, setup, "schedule")
	for _, w := range []string{"enabled", "active", "Fri 2026-11-27", "never", "-O repos -A"} {
		if r.e != nil || !strings.Contains(r.out, w) {
			t.Errorf("status missing %q: %v\n%s", w, r.e, r.out)
		}
	}
	if strings.Contains(r.out, "last result") {
		t.Errorf("no result before the first run:\n%s", r.out)
	}
	r = runArgsWith(t, setup, "schedule", "remove")
	if r.e != nil || !strings.Contains(r.out, "Removed audit.timer and audit.service.") {
		t.Fatalf("remove: %v %q", r.e, r.out)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "audit.*")); len(m) != 0 {
		t.Errorf("unit files left: %v", m)
	}
	if r := runArgsWith(t, setup, "schedule", "remove"); r.e != nil || !strings.Contains(r.out, "Not installed.") {
		t.Errorf("remove twice: %v %q", r.e, r.out)
	}
	writeConfig(t, cfgHome, "schedule: {commands: [nope]}\n")
	if r := runArgsWith(t, setup, "schedule", "install"); r.e == nil || !strings.Contains(r.e.Error(), `unknown command "nope"`) {
		t.Errorf("bad command: %v", r.e)
	}
	bus := &exec.Fake{}
	bus.Add([]string{"systemctl", "--user"}, exec.Result{Code: 1, Stderr: "Failed to connect to bus"})
	writeConfig(t, cfgHome, "")
	if r := runArgsWith(t, func(a *app) { a.runner = bus }, "schedule", "install"); r.e == nil || !strings.Contains(r.e.Error(), "Failed to connect to bus") {
		t.Errorf("systemctl failure: %v", r.e)
	}
}
