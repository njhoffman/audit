// Package resources checks pressure on the machine: memory, I/O and CPU
// stall time (PSI), available memory and swap, recent OOM kills, load
// against the core count, temperatures near their critical trip point,
// thermal throttling and battery wear.
package resources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/scan"
)

// Options configures the scan.
type Options struct {
	Env *exec.Env
	// Root prefixes /proc and /sys (tests).
	Root string
	// CPUs is the core count load is compared with; 0 asks the runtime.
	CPUs int
}

func (o Options) read(p string) string {
	b, err := os.ReadFile(filepath.Join(o.Root, p)) // #nosec G304 -- fixed /proc and /sys paths
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ParsePSI reads a /proc/pressure file into kind ("some", "full") -> field
// ("avg10", "avg60", "avg300") -> value.
func ParsePSI(text string) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		m := map[string]float64{}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				m[k] = x
			}
		}
		out[f[0]] = m
	}
	return out
}

// ParseMeminfo reads /proc/meminfo into kB values.
func ParseMeminfo(text string) map[string]float64 {
	out := map[string]float64{}
	for line := range strings.SplitSeq(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if f := strings.Fields(v); len(f) > 0 {
			if x, err := strconv.ParseFloat(f[0], 64); err == nil {
				out[k] = x
			}
		}
	}
	return out
}

var oomRe = regexp.MustCompile(`Killed process \d+ \(([^)]+)\)`)

// Scan implements the system part.
func Scan(ctx context.Context, o Options) (*scan.Result, error) {
	started := time.Now()
	var fs []scan.Finding
	summary := map[string]any{}
	add := func(check string, sev scan.Severity, subject, detail string) {
		fs = append(fs, scan.Finding{Check: check, Severity: sev, Subject: subject, Detail: detail})
	}

	pressure := map[string]float64{}
	for _, kind := range []string{"memory", "io", "cpu"} {
		psi := ParsePSI(o.read("/proc/pressure/" + kind))
		some, full := psi["some"]["avg300"], psi["full"]["avg300"]
		pressure[kind+"_some_avg300"] = some
		switch {
		case kind == "memory" && full >= 2:
			add("memory_pressure", scan.SeverityError, "memory",
				fmt.Sprintf("every task stalled on memory %.1f%% of the last 5 minutes; the machine is thrashing", full))
		case kind == "memory" && some >= 10:
			add("memory_pressure", scan.SeverityWarning, "memory",
				fmt.Sprintf("tasks stalled waiting for memory %.1f%% of the last 5 minutes", some))
		case kind == "io" && some >= 20:
			add("io_pressure", scan.SeverityNotice, "io", fmt.Sprintf("tasks stalled on I/O %.1f%% of the last 5 minutes", some))
		case kind == "cpu" && some >= 40:
			add("cpu_pressure", scan.SeverityNotice, "cpu", fmt.Sprintf("runnable tasks waited for a CPU %.1f%% of the last 5 minutes", some))
		}
	}
	summary["pressure"] = pressure

	mi := ParseMeminfo(o.read("/proc/meminfo"))
	if total := mi["MemTotal"]; total > 0 {
		avail := mi["MemAvailable"] * 100 / total
		summary["memory_available_pct"] = int(avail)
		if avail < 5 {
			add("low_memory", scan.SeverityWarning, "memory", fmt.Sprintf("only %.0f%% of memory is available (%.0f MB)", avail, mi["MemAvailable"]/1024))
		}
	}
	if st := mi["SwapTotal"]; st > 0 {
		used := (st - mi["SwapFree"]) * 100 / st
		summary["swap_used_pct"] = int(used)
		if used >= 80 {
			add("swap", scan.SeverityNotice, "swap", fmt.Sprintf("swap is %.0f%% used", used))
		}
	}

	if o.Env != nil {
		r := o.Env.Run(ctx, "journalctl", []string{"-k", "-q", "--no-pager", "--since", "7 days ago", "-o", "cat",
			"--grep", "Out of memory: Killed process|oom-kill"}, exec.Options{Timeout: 30 * time.Second})
		victims := map[string]int{}
		for _, m := range oomRe.FindAllStringSubmatch(r.Stdout, -1) {
			victims[m[1]]++
		}
		if len(victims) > 0 {
			names := make([]string, 0, len(victims))
			n := 0
			for v, c := range victims {
				names = append(names, fmt.Sprintf("%s x%d", v, c))
				n += c
			}
			sort.Strings(names)
			add("oom_kills", scan.SeverityWarning, "kernel",
				fmt.Sprintf("the kernel killed %d process(es) for lack of memory in the last 7 days: %s", n, strings.Join(names, ", ")))
		}
		summary["oom_kills_7d"] = len(victims)
	}

	cpus := o.CPUs
	if cpus == 0 {
		cpus = runtime.NumCPU()
	}
	if f := strings.Fields(o.read("/proc/loadavg")); len(f) >= 3 {
		if l15, err := strconv.ParseFloat(f[2], 64); err == nil {
			summary["load15"] = l15
			if l15 > 1.5*float64(cpus) {
				add("load", scan.SeverityNotice, "load", fmt.Sprintf("the 15-minute load is %.1f on %d cores", l15, cpus))
			}
		}
	}

	fs = append(fs, thermal(o)...)
	if n := throttles(o); n > 0 {
		summary["cpu_throttle_events"] = n
		add("throttled", scan.SeverityInfo, "cpu", fmt.Sprintf("the CPU was thermally throttled %d time(s) since boot", n))
	}
	bf, batteries := battery(o)
	fs = append(fs, bf...)
	if len(batteries) > 0 {
		summary["batteries"] = batteries
	}
	return &scan.Result{Kind: "resources", StartedAt: started, FinishedAt: time.Now(), Summary: summary, Findings: fs}, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// thermal reports zones within 5 C of their critical trip point.
func thermal(o Options) []scan.Finding {
	zones, _ := filepath.Glob(filepath.Join(o.Root, "/sys/class/thermal/thermal_zone*"))
	var out []scan.Finding
	for _, z := range zones {
		rel := strings.TrimPrefix(z, o.Root)
		temp := atoi(o.read(rel + "/temp"))
		trips, _ := filepath.Glob(filepath.Join(z, "trip_point_*_type"))
		for _, tp := range trips {
			if o.read(strings.TrimPrefix(tp, o.Root)) != "critical" {
				continue
			}
			crit := atoi(o.read(strings.TrimSuffix(strings.TrimPrefix(tp, o.Root), "_type") + "_temp"))
			if crit > 0 && temp >= crit-5000 {
				name := o.read(rel + "/type")
				out = append(out, scan.Finding{Check: "temperature", Severity: scan.SeverityWarning, Subject: name,
					Detail: fmt.Sprintf("%s is at %.0f C, close to its critical %.0f C", name, float64(temp)/1000, float64(crit)/1000)})
			}
		}
	}
	return out
}

func throttles(o Options) int {
	files, _ := filepath.Glob(filepath.Join(o.Root, "/sys/devices/system/cpu/cpu*/thermal_throttle/package_throttle_count"))
	n := 0
	for _, f := range files {
		n += atoi(o.read(strings.TrimPrefix(f, o.Root)))
	}
	return n
}

// Battery is one system battery's wear.
type Battery struct {
	Name      string `json:"name"`
	HealthPct int    `json:"health_pct"`
	Cycles    int    `json:"cycles,omitempty"`
}

func battery(o Options) ([]scan.Finding, []Battery) {
	dirs, _ := filepath.Glob(filepath.Join(o.Root, "/sys/class/power_supply/*"))
	var out []scan.Finding
	var bats []Battery
	for _, d := range dirs {
		rel := strings.TrimPrefix(d, o.Root)
		// Peripheral batteries (mice, keyboards) report scope Device.
		if o.read(rel+"/type") != "Battery" || o.read(rel+"/scope") == "Device" {
			continue
		}
		full, design := atoi(o.read(rel+"/energy_full")), atoi(o.read(rel+"/energy_full_design"))
		if design == 0 {
			full, design = atoi(o.read(rel+"/charge_full")), atoi(o.read(rel+"/charge_full_design"))
		}
		if design == 0 {
			continue
		}
		b := Battery{Name: filepath.Base(d), HealthPct: full * 100 / design, Cycles: atoi(o.read(rel + "/cycle_count"))}
		bats = append(bats, b)
		detail := fmt.Sprintf("%s holds %d%% of its design capacity", b.Name, b.HealthPct)
		if b.Cycles > 0 {
			detail += fmt.Sprintf(" after %d cycles", b.Cycles)
		}
		switch {
		case b.HealthPct < 60:
			out = append(out, scan.Finding{Check: "battery", Severity: scan.SeverityWarning, Subject: b.Name, Detail: detail + "; consider replacing it"})
		case b.HealthPct < 80:
			out = append(out, scan.Finding{Check: "battery", Severity: scan.SeverityNotice, Subject: b.Name, Detail: detail})
		}
	}
	return out, bats
}
