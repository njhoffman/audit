// Package procs scans running processes and produces a digest plus derived findings.
package procs

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/njhoffman/audit/internal/scan"
)

// Process is a flattened, marshalable view of a single process.
type Process struct {
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid"`
	Name       string    `json:"name"`
	User       string    `json:"user"`
	Cmd        string    `json:"cmd"`
	Status     []string  `json:"status"`
	CPUPct     float64   `json:"cpu_pct"`
	MemPct     float32   `json:"mem_pct"`
	RSSMB      uint64    `json:"rss_mb"`
	NumThreads int32     `json:"num_threads"`
	Started    time.Time `json:"started"`
}

// Options tunes the scan.
type Options struct {
	TopN            int     // how many top CPU/Mem processes to report
	HighCPUPct      float64 // flag procs using >= this percent CPU
	HighMemPct      float32 // flag procs using >= this percent memory
	HighThreadCount int32   // flag procs with >= this many threads
}

func DefaultOptions() Options {
	return Options{
		TopN:            10,
		HighCPUPct:      80.0,
		HighMemPct:      25.0,
		HighThreadCount: 1000,
	}
}

// Scan walks /proc and returns a scan.Result with a digest and findings.
func Scan(ctx context.Context, opts Options) (*scan.Result, error) {
	if opts.TopN <= 0 {
		opts = DefaultOptions()
	}
	started := time.Now()

	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}

	collected := make([]Process, 0, len(procs))
	byStatus := map[string]int{}
	zombies := []Process{}

	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		flat := snapshot(ctx, p)
		collected = append(collected, flat)
		for _, s := range flat.Status {
			byStatus[s]++
			if s == process.Zombie {
				zombies = append(zombies, flat)
			}
		}
	}

	topCPU := topBy(collected, func(a, b Process) bool { return a.CPUPct > b.CPUPct }, opts.TopN)
	topMem := topBy(collected, func(a, b Process) bool { return a.MemPct > b.MemPct }, opts.TopN)

	findings := deriveFindings(collected, zombies, opts)

	hi, _ := host.InfoWithContext(ctx)

	res := &scan.Result{
		Kind:       "procs",
		StartedAt:  started,
		FinishedAt: time.Now(),
		Summary: map[string]any{
			"host":      hi,
			"total":     len(collected),
			"by_status": byStatus,
			"top_cpu":   topCPU,
			"top_mem":   topMem,
			"zombies":   zombies,
		},
		Findings: findings,
	}
	return res, nil
}

func snapshot(ctx context.Context, p *process.Process) Process {
	flat := Process{PID: p.Pid}
	if v, err := p.PpidWithContext(ctx); err == nil {
		flat.PPID = v
	}
	if v, err := p.NameWithContext(ctx); err == nil {
		flat.Name = v
	}
	if v, err := p.UsernameWithContext(ctx); err == nil {
		flat.User = v
	}
	if v, err := p.CmdlineWithContext(ctx); err == nil {
		flat.Cmd = v
	}
	if v, err := p.StatusWithContext(ctx); err == nil {
		flat.Status = v
	}
	if v, err := p.CPUPercentWithContext(ctx); err == nil {
		flat.CPUPct = v
	}
	if v, err := p.MemoryPercentWithContext(ctx); err == nil {
		flat.MemPct = v
	}
	if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
		flat.RSSMB = mi.RSS / (1024 * 1024)
	}
	if v, err := p.NumThreadsWithContext(ctx); err == nil {
		flat.NumThreads = v
	}
	if ms, err := p.CreateTimeWithContext(ctx); err == nil {
		flat.Started = time.UnixMilli(ms)
	}
	return flat
}

func topBy(in []Process, less func(a, b Process) bool, n int) []Process {
	cp := make([]Process, len(in))
	copy(cp, in)
	sort.Slice(cp, func(i, j int) bool { return less(cp[i], cp[j]) })
	if n > len(cp) {
		n = len(cp)
	}
	return cp[:n]
}

func deriveFindings(all, zombies []Process, opts Options) []scan.Finding {
	out := []scan.Finding{}
	if len(zombies) > 0 {
		names := make([]string, 0, len(zombies))
		for _, z := range zombies {
			names = append(names, fmt.Sprintf("%s(%d)", z.Name, z.PID))
		}
		out = append(out, scan.Finding{
			Check:    "zombies",
			Severity: scan.SeverityWarning,
			Subject:  "zombie processes",
			Detail:   fmt.Sprintf("%d zombie process(es); a parent is not reaping its children. Offenders: %s", len(zombies), joinShort(names, 10)),
		})
	}
	for _, p := range all {
		if p.CPUPct >= opts.HighCPUPct {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Check:    "high_cpu",
				Subject:  p.Name,
				Detail:   fmt.Sprintf("%.1f%% CPU (pid %d, user %s): %s", p.CPUPct, p.PID, p.User, truncate(p.Cmd, 200)),
			})
		}
		if p.MemPct >= opts.HighMemPct {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Check:    "high_memory",
				Subject:  p.Name,
				Detail:   fmt.Sprintf("%.1f%% memory, %d MiB RSS (pid %d, user %s): %s", p.MemPct, p.RSSMB, p.PID, p.User, truncate(p.Cmd, 200)),
			})
		}
		if opts.HighThreadCount > 0 && p.NumThreads >= opts.HighThreadCount {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Check:    "high_threads",
				Subject:  p.Name,
				Detail:   fmt.Sprintf("%d threads (pid %d, user %s): %s", p.NumThreads, p.PID, p.User, truncate(p.Cmd, 200)),
			})
		}
	}
	return out
}

func joinShort(names []string, max int) string {
	if len(names) <= max {
		return fmt.Sprintf("%v", names)
	}
	return fmt.Sprintf("%v ...(+%d more)", names[:max], len(names)-max)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
