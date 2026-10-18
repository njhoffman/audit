package procs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestDeriveFindings_Zombies(t *testing.T) {
	all := []Process{}
	zombies := []Process{
		{PID: 1234, Name: "stale-child"},
		{PID: 5678, Name: "stale-child-2"},
	}
	out := deriveFindings(all, zombies, DefaultOptions())
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Severity != scan.SeverityWarning {
		t.Errorf("zombie severity: got %q", out[0].Severity)
	}
	if out[0].Check != "zombies" || out[0].Subject != "zombie processes" || !strings.Contains(out[0].Detail, "2 zombie") {
		t.Errorf("zombie finding: %+v", out[0])
	}
}

func TestDeriveFindings_HighCPU(t *testing.T) {
	all := []Process{
		{PID: 1, Name: "calm", CPUPct: 5.0},
		{PID: 2, Name: "hot", CPUPct: 90.0, User: "root", Cmd: "/bin/yes"},
	}
	out := deriveFindings(all, nil, DefaultOptions())
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Check != "high_cpu" || out[0].Subject != "hot" || !strings.Contains(out[0].Detail, "pid 2") {
		t.Errorf("high cpu: %+v", out[0])
	}
}

func TestDeriveFindings_HighMem(t *testing.T) {
	all := []Process{
		{PID: 1, Name: "fat", MemPct: 30.0, RSSMB: 1024, User: "u", Cmd: "x"},
	}
	out := deriveFindings(all, nil, DefaultOptions())
	if len(out) != 1 || out[0].Check != "high_memory" || out[0].Subject != "fat" || !strings.Contains(out[0].Detail, "1024 MiB") {
		t.Fatalf("expected one high memory finding, got %v", out)
	}
}

func TestDeriveFindings_HighThreads(t *testing.T) {
	all := []Process{
		{PID: 1, Name: "thready", NumThreads: 2000, User: "u", Cmd: "x"},
	}
	out := deriveFindings(all, nil, DefaultOptions())
	if len(out) != 1 || out[0].Check != "high_threads" || !strings.Contains(out[0].Detail, "2000 threads") {
		t.Fatalf("expected one high thread finding, got %v", out)
	}
}

func TestTopBy(t *testing.T) {
	in := []Process{{CPUPct: 1}, {CPUPct: 5}, {CPUPct: 3}, {CPUPct: 9}}
	top := topBy(in, func(a, b Process) bool { return a.CPUPct > b.CPUPct }, 2)
	if len(top) != 2 || top[0].CPUPct != 9 || top[1].CPUPct != 5 {
		t.Errorf("topBy: got %+v", top)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short: %q", got)
	}
	if got := truncate("hello world", 5); got != "hello..." {
		t.Errorf("truncate long: %q", got)
	}
}
