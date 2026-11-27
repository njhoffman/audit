package schedule

import (
	"strings"
	"testing"
)

func TestUnits(t *testing.T) {
	svc, tmr := Units(Options{Exe: "/home/u/go/bin/audit", Calendar: "daily", Commands: []string{"system", "repos"}})
	if !strings.Contains(svc, "ExecStart=/home/u/go/bin/audit -r -q -O system,repos\n") || !strings.Contains(svc, "Type=oneshot") {
		t.Errorf("service:\n%s", svc)
	}
	if !strings.Contains(tmr, "OnCalendar=daily\n") || !strings.Contains(tmr, "Persistent=true") || !strings.Contains(tmr, "WantedBy=timers.target") {
		t.Errorf("timer:\n%s", tmr)
	}
	svc, _ = Units(Options{Exe: "/opt/my tools/audit", Calendar: "Mon 09:00", AI: true})
	if !strings.Contains(svc, `ExecStart="/opt/my tools/audit" -r -q -A`+"\n") {
		t.Errorf("a path with a space is quoted, no -O for all commands:\n%s", svc)
	}
	if got := quote(`a"b$c%d`); got != `"a\"b$$c%%d"` {
		t.Errorf("quote: %s", got)
	}
}
