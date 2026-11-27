// Package schedule writes the systemd user timer that runs audit -r
// unattended.
package schedule

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Unit names.
const (
	Service = "audit.service"
	Timer   = "audit.timer"
)

// Options describe the scheduled run.
type Options struct {
	// Exe is the audit binary the service runs.
	Exe string
	// Calendar is the timer's OnCalendar spec (daily, hourly, Mon 09:00).
	Calendar string
	// Commands are rescanned when stale (audit -r -O ...); empty means all.
	Commands []string
	// AI adds an AI review of each rescanned command (-A).
	AI bool
}

// Args are the audit arguments of the scheduled run.
func (o Options) Args() []string {
	args := []string{"-r", "-q"}
	if len(o.Commands) > 0 {
		args = append(args, "-O", strings.Join(o.Commands, ","))
	}
	if o.AI {
		args = append(args, "-A")
	}
	return args
}

// quote makes one ExecStart word: systemd splits on spaces and reads
// backslashes and quotes, so a word holding them is double-quoted with
// those escaped.
func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%")
	return `"` + r.Replace(s) + `"`
}

// Units are the service and timer files.
func Units(o Options) (service, timer string) {
	words := []string{quote(o.Exe)}
	for _, a := range o.Args() {
		words = append(words, quote(a))
	}
	service = fmt.Sprintf(`# Written by audit schedule install; audit schedule remove deletes it.
[Unit]
Description=audit: rescan stale commands
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s
Nice=10
IOSchedulingClass=idle
`, strings.Join(words, " "))
	timer = fmt.Sprintf(`# Written by audit schedule install; audit schedule remove deletes it.
[Unit]
Description=Run audit %s

[Timer]
OnCalendar=%s
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
`, o.Calendar, o.Calendar)
	return service, timer
}

// Dir is the systemd user unit directory under configHome
// ($XDG_CONFIG_HOME, else ~/.config).
func Dir(configHome string) string { return filepath.Join(configHome, "systemd", "user") }
