// Package updates checks the operating system's update state: a reboot
// requested by a package, a newer kernel installed than the one running,
// pending security updates in apt's cached lists, failed automatic upgrade
// runs, and old kernels kept around.
package updates

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	// Root prefixes /run, /var and /boot (tests).
	Root string
	// KeepKernels is how many installed kernels are normal.
	KeepKernels int
}

// DefaultOptions are the documented defaults.
func DefaultOptions() Options { return Options{KeepKernels: 3} }

func (o Options) path(p string) string { return filepath.Join(o.Root, p) }

var numRe = regexp.MustCompile(`\d+`)

// CompareKernels orders kernel release strings ("6.17.0-41-generic") by
// their numbers: -1, 0 or 1.
func CompareKernels(a, b string) int {
	na, nb := numRe.FindAllString(a, -1), numRe.FindAllString(b, -1)
	for i := range min(len(na), len(nb)) {
		x, _ := strconv.Atoi(na[i])
		y, _ := strconv.Atoi(nb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(na) < len(nb):
		return -1
	case len(na) > len(nb):
		return 1
	}
	return 0
}

// Kernels lists the kernel releases in /boot, newest first.
func Kernels(root string) []string {
	files, _ := filepath.Glob(filepath.Join(root, "/boot/vmlinuz-*"))
	var out []string
	for _, f := range files {
		if v := strings.TrimPrefix(filepath.Base(f), "vmlinuz-"); v != "" && !strings.HasSuffix(v, ".old") {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return CompareKernels(out[i], out[j]) > 0 })
	return out
}

// SecurityUpdates picks the packages of `apt list --upgradable` that come
// from a -security suite.
func SecurityUpdates(out string) []string {
	var names []string
	for line := range strings.SplitSeq(out, "\n") {
		name, rest, ok := strings.Cut(line, "/")
		if !ok || !strings.Contains(line, "[upgradable from:") {
			continue
		}
		suites, _, _ := strings.Cut(rest, " ")
		if strings.Contains(suites, "-security") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Scan implements the system part.
func Scan(ctx context.Context, o Options) (*scan.Result, error) {
	started := time.Now()
	if o.KeepKernels <= 0 {
		o.KeepKernels = DefaultOptions().KeepKernels
	}
	var fs []scan.Finding
	summary := map[string]any{}
	add := func(check string, sev scan.Severity, subject, detail string) {
		fs = append(fs, scan.Finding{Check: check, Severity: sev, Subject: subject, Detail: detail})
	}

	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := os.Stat(o.path(p)); err != nil {
			continue
		}
		detail := "a package update asks for a reboot"
		if b, err := os.ReadFile(o.path(p + ".pkgs")); err == nil { // #nosec G304 -- fixed path
			if pkgs := strings.Fields(string(b)); len(pkgs) > 0 {
				sort.Strings(pkgs)
				detail += " (" + strings.Join(dedupe(pkgs), ", ") + ")"
			}
		}
		add("reboot_required", scan.SeverityNotice, "reboot", detail)
		summary["reboot_required"] = true
		break
	}

	kernels := Kernels(o.Root)
	summary["kernels_installed"] = len(kernels)
	if o.Env != nil {
		if r := o.Env.Run(ctx, "uname", []string{"-r"}, exec.Options{Timeout: 5 * time.Second}); r.OK() {
			running := strings.TrimSpace(r.Stdout)
			summary["kernel_running"] = running
			if len(kernels) > 0 && CompareKernels(kernels[0], running) > 0 {
				add("kernel", scan.SeverityNotice, "kernel",
					fmt.Sprintf("kernel %s is installed but %s is running; reboot to use it", kernels[0], running))
			}
		}
	}
	if len(kernels) > o.KeepKernels {
		add("old_kernels", scan.SeverityInfo, "kernels",
			fmt.Sprintf("%d kernels are installed (%s); sudo apt autoremove --purge removes the old ones", len(kernels), strings.Join(kernels, ", ")))
	}

	if o.Env == nil {
		return &scan.Result{Kind: "updates", StartedAt: started, FinishedAt: time.Now(), Summary: summary, Findings: fs}, nil
	}
	if o.Env.Which("apt") != "" {
		if r := o.Env.Run(ctx, "apt", []string{"list", "--upgradable"}, exec.Options{Timeout: time.Minute}); r.OK() {
			sec := SecurityUpdates(r.Stdout)
			summary["security_updates"] = len(sec)
			if len(sec) > 0 {
				add("security_updates", scan.SeverityWarning, "apt",
					fmt.Sprintf("%d security update(s) pending: %s; audit packages update -M apt", len(sec), strings.Join(sec, ", ")))
			}
		}
	}
	units := []string{"unattended-upgrades.service", "apt-daily-upgrade.service", "apt-daily.service"}
	r := o.Env.Run(ctx, "systemctl", append([]string{"is-failed"}, units...), exec.Options{Timeout: 15 * time.Second})
	for i, state := range strings.Fields(r.Stdout) {
		if state == "failed" && i < len(units) {
			add("upgrade_failed", scan.SeverityWarning, units[i],
				fmt.Sprintf("%s failed on its last run; see journalctl -u %s", units[i], units[i]))
		}
	}
	if line := lastError(o.path("/var/log/unattended-upgrades/unattended-upgrades.log"), started); line != "" {
		add("upgrade_errors", scan.SeverityWarning, "unattended-upgrades", "unattended-upgrades logged an error in the last week: "+line)
	}
	return &scan.Result{Kind: "updates", StartedAt: started, FinishedAt: time.Now(), Summary: summary, Findings: fs}, nil
}

// lastError is the last ERROR line of an unattended-upgrades log written in
// the week before now.
func lastError(path string, now time.Time) string {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed log path
	if err != nil {
		return ""
	}
	last := ""
	for line := range strings.SplitSeq(string(b), "\n") {
		if !strings.Contains(line, " ERROR ") {
			continue
		}
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", firstN(line, 19), time.Local); err == nil && now.Sub(t) > 7*24*time.Hour {
			continue
		}
		last = strings.TrimSpace(line)
	}
	return last
}

func firstN(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func dedupe(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}
