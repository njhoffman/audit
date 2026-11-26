package procs

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
)

func fakeProcesses(t *testing.T, ps []Process, err error) {
	t.Helper()
	old := listProcesses
	t.Cleanup(func() { listProcesses = old })
	listProcesses = func(context.Context) ([]Process, error) { return ps, err }
}

func TestScanSummarizes(t *testing.T) {
	fakeProcesses(t, []Process{
		{PID: 1, Name: "init", Status: []string{process.Sleep}, CPUPct: 0.1, MemPct: 0.5},
		{PID: 2, Name: "hog", Status: []string{process.Running}, CPUPct: 95, MemPct: 30, NumThreads: 4},
		{PID: 3, Name: "dead", Status: []string{process.Zombie}},
		{PID: 4, Name: "busy", Status: []string{process.Running}, CPUPct: 40, MemPct: 2},
	}, nil)
	r, err := Scan(context.Background(), Options{TopN: 2, HighCPUPct: 80, HighMemPct: 25, HighThreadCount: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "procs" || r.Summary["total"] != 4 {
		t.Errorf("summary: %+v", r.Summary)
	}
	if bs := r.Summary["by_status"].(map[string]int); bs[process.Running] != 2 || bs[process.Zombie] != 1 {
		t.Errorf("by status: %v", bs)
	}
	top := r.Summary["top_cpu"].([]Process)
	if len(top) != 2 || top[0].Name != "hog" || top[1].Name != "busy" {
		t.Errorf("top CPU keeps TopN, highest first: %+v", top)
	}
	if z := r.Summary["zombies"].([]Process); len(z) != 1 || z[0].PID != 3 {
		t.Errorf("zombies: %+v", z)
	}
	checks := map[string]int{}
	for _, f := range r.Findings {
		checks[f.Check]++
	}
	if checks["zombies"] != 1 || checks["high_cpu"] != 1 || checks["high_memory"] != 1 || checks["high_threads"] != 0 {
		t.Errorf("findings: %v", checks)
	}
}

func TestScanDefaultsAndErrors(t *testing.T) {
	fakeProcesses(t, nil, errors.New("no /proc"))
	if _, err := Scan(context.Background(), Options{}); err == nil {
		t.Error("a failed listing fails the scan")
	}
	fakeProcesses(t, []Process{{PID: 9, Name: "x", CPUPct: 85}}, nil)
	r, err := Scan(context.Background(), Options{}) // zero options take the defaults
	if err != nil || len(r.Findings) != 1 || r.Findings[0].Check != "high_cpu" {
		t.Errorf("defaults apply (high CPU at 80%%): %+v %v", r.Findings, err)
	}
}

// The real listing, over this test's own process.
func TestListProcessesSnapshotsSelf(t *testing.T) {
	ps, err := listProcesses(context.Background())
	if err != nil {
		t.Skip("no process listing here:", err)
	}
	self := int32(os.Getpid()) // #nosec G115 -- a pid fits in int32
	for _, p := range ps {
		if p.PID == self {
			if p.Name == "" || p.NumThreads < 1 || p.Started.IsZero() || p.PPID != int32(os.Getppid()) { // #nosec G115 -- a pid fits in int32
				t.Errorf("self snapshot: %+v", p)
			}
			return
		}
	}
	t.Errorf("own pid %d not listed among %d", self, len(ps))
}

func TestListProcessesCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := listProcesses(ctx); err == nil {
		t.Error("a canceled listing stops")
	}
}
