package resources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

func write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/proc/pressure/memory", "some avg10=1.00 avg60=1.00 avg300=12.50 total=1\nfull avg10=0 avg60=0 avg300=0.50 total=1\n")
	write(t, root, "/proc/pressure/io", "some avg10=0 avg60=0 avg300=25.00 total=1\n")
	write(t, root, "/proc/pressure/cpu", "some avg10=0 avg60=0 avg300=1.00 total=1\n")
	write(t, root, "/proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 40 kB\nSwapTotal: 100 kB\nSwapFree: 10 kB\n")
	write(t, root, "/proc/loadavg", "1.0 2.0 7.5 1/100 1\n")
	write(t, root, "/sys/class/thermal/thermal_zone0/type", "x86_pkg_temp")
	write(t, root, "/sys/class/thermal/thermal_zone0/temp", "96000")
	write(t, root, "/sys/class/thermal/thermal_zone0/trip_point_0_type", "critical")
	write(t, root, "/sys/class/thermal/thermal_zone0/trip_point_0_temp", "100000")
	write(t, root, "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count", "7")
	write(t, root, "/sys/class/power_supply/BAT0/type", "Battery")
	write(t, root, "/sys/class/power_supply/BAT0/energy_full", "42")
	write(t, root, "/sys/class/power_supply/BAT0/energy_full_design", "100")
	write(t, root, "/sys/class/power_supply/BAT0/cycle_count", "900")
	write(t, root, "/sys/class/power_supply/mouse/type", "Battery")
	write(t, root, "/sys/class/power_supply/mouse/scope", "Device")
	write(t, root, "/sys/class/power_supply/mouse/charge_full", "1")
	write(t, root, "/sys/class/power_supply/mouse/charge_full_design", "10")
	fake := &exec.Fake{}
	fake.AddOutput("Out of memory: Killed process 12 (chrome) total-vm:1kB\nOut of memory: Killed process 13 (chrome)\n"+
		"Out of memory: Killed process 14 (java)\n", "journalctl")
	res, err := Scan(context.Background(), Options{Root: root, CPUs: 4, Env: &exec.Env{Vars: map[string]string{}, Runner: fake}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.Check] = string(f.Severity) + ": " + f.Detail
	}
	for check, want := range map[string]string{
		"memory_pressure": "warning: tasks stalled waiting for memory 12.5% of the last 5 minutes",
		"io_pressure":     "notice: tasks stalled on I/O 25.0% of the last 5 minutes",
		"low_memory":      "warning: only 4% of memory is available (0 MB)",
		"swap":            "notice: swap is 90% used",
		"oom_kills":       "warning: the kernel killed 3 process(es) for lack of memory in the last 7 days: chrome x2, java x1",
		"load":            "notice: the 15-minute load is 7.5 on 4 cores",
		"temperature":     "warning: x86_pkg_temp is at 96 C, close to its critical 100 C",
		"throttled":       "info: the CPU was thermally throttled 7 time(s) since boot",
		"battery":         "warning: BAT0 holds 42% of its design capacity after 900 cycles; consider replacing it",
	} {
		if got[check] != want {
			t.Errorf("%s:\n got %q\nwant %q", check, got[check], want)
		}
	}
	if len(got) != 9 {
		t.Errorf("the mouse battery and cpu pressure stay quiet: %v", got)
	}
}
