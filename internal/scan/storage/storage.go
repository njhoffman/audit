// Package storage checks filesystems: how full they are by space and
// inodes, unexpected read-only mounts, and (opt-in, through sudo -n) disk
// SMART health, plus zfs pool and btrfs device errors.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/scan"
)

// Options configures the scan.
type Options struct {
	Env *exec.Env
	// Root prefixes /proc paths (tests).
	Root string
	// WarnPct and ErrorPct are the fullness thresholds, for space and inodes.
	WarnPct, ErrorPct float64
	// SMART asks smartctl (and btrfs device stats) through sudo -n, which
	// needs cached credentials or a NOPASSWD rule.
	SMART bool
}

// DefaultOptions are the documented defaults.
func DefaultOptions() Options { return Options{WarnPct: 90, ErrorPct: 97} }

// Mount is one checked filesystem.
type Mount struct {
	Device   string  `json:"device"`
	Point    string  `json:"point"`
	Type     string  `json:"type"`
	ReadOnly bool    `json:"read_only,omitempty"`
	SizeGB   float64 `json:"size_gb"`
	UsedPct  float64 `json:"used_pct"`
	InodePct float64 `json:"inode_pct,omitempty"`
}

// realFS are the filesystem types that hold data worth checking.
var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true, "bcachefs": true}

// Usage is what statfs reports, in bytes and inodes.
type Usage struct{ Total, Free, Avail, Files, FilesFree uint64 }

// Statfs reads a mount's usage; tests replace it.
var Statfs = func(path string) (Usage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Bsize) // #nosec G115 -- block size is positive
	return Usage{Total: st.Blocks * bs, Free: st.Bfree * bs, Avail: st.Bavail * bs, Files: st.Files, FilesFree: st.Ffree}, nil
}

// ParseMounts reads /proc/self/mounts, keeping data filesystems once per
// device (bind mounts repeat them) and skipping snap squashfs and the like.
func ParseMounts(text string) []Mount {
	var out []Mount
	seen := map[string]bool{}
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !realFS[f[2]] {
			continue
		}
		point := strings.ReplaceAll(f[1], `\040`, " ")
		if seen[f[0]] || strings.HasPrefix(point, "/snap/") {
			continue
		}
		seen[f[0]] = true
		ro := false
		for _, o := range strings.Split(f[3], ",") {
			ro = ro || o == "ro"
		}
		out = append(out, Mount{Device: f[0], Point: point, Type: f[2], ReadOnly: ro})
	}
	return out
}

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

// Scan implements the system part.
func Scan(ctx context.Context, o Options) (*scan.Result, error) {
	started := time.Now()
	text, err := os.ReadFile(filepath.Join(o.Root, "/proc/self/mounts"))
	if err != nil {
		return nil, fmt.Errorf("read mounts: %w", err)
	}
	mounts := ParseMounts(string(text))
	var fs []scan.Finding
	var errs []string
	for i := range mounts {
		m := &mounts[i]
		u, err := Statfs(m.Point)
		if err != nil {
			errs = append(errs, fmt.Sprintf("statfs %s: %v", m.Point, err))
			continue
		}
		m.SizeGB = float64(u.Total) / (1 << 30)
		// Like df: used over what is usable, so reserved blocks count as full.
		m.UsedPct = pct(u.Total-u.Free, u.Total-u.Free+u.Avail)
		if u.Files > 0 {
			m.InodePct = pct(u.Files-u.FilesFree, u.Files)
		}
		if f := full("full", m.Point, m.UsedPct, o, fmt.Sprintf("%s is %.0f%% full (%.1f GB free of %.1f GB)",
			m.Point, m.UsedPct, float64(u.Avail)/(1<<30), m.SizeGB)); f != nil {
			fs = append(fs, *f)
		}
		if f := full("inodes", m.Point, m.InodePct, o, fmt.Sprintf("%s has used %.0f%% of its inodes", m.Point, m.InodePct)); f != nil {
			fs = append(fs, *f)
		}
		if m.ReadOnly && m.Type != "vfat" && m.Type != "fuseblk" {
			fs = append(fs, scan.Finding{Check: "read_only", Severity: scan.SeverityWarning, Subject: m.Point,
				Detail: fmt.Sprintf("%s (%s on %s) is mounted read-only; the kernel remounts a filesystem read-only after errors", m.Point, m.Type, m.Device)})
		}
	}
	if o.Env != nil {
		fs = append(fs, zfsPools(ctx, o.Env)...)
		if o.SMART {
			sf, serrs := smart(ctx, o.Env)
			fs, errs = append(fs, sf...), append(errs, serrs...)
			for _, m := range mounts {
				if m.Type == "btrfs" {
					if r := o.Env.Run(ctx, "sudo", []string{"-n", "btrfs", "device", "stats", "--check", m.Point},
						exec.Options{Timeout: 30 * time.Second}); r.Code != 0 && r.Code != exec.ExitNotFound {
						fs = append(fs, scan.Finding{Check: "btrfs_errors", Severity: scan.SeverityError, Subject: m.Point,
							Detail: m.Point + " has btrfs device errors: " + firstLines(r.Stdout+r.Stderr, 3)})
					}
				}
			}
		}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Point < mounts[j].Point })
	summary := map[string]any{"filesystems": len(mounts), "mounts": mounts}
	if len(errs) > 0 {
		summary["errors"] = errs
	}
	return &scan.Result{Kind: "storage", StartedAt: started, FinishedAt: time.Now(), Summary: summary, Findings: fs}, nil
}

func full(check, point string, p float64, o Options, detail string) *scan.Finding {
	switch {
	case p >= o.ErrorPct:
		return &scan.Finding{Check: check, Severity: scan.SeverityError, Subject: point, Detail: detail}
	case p >= o.WarnPct:
		return &scan.Finding{Check: check, Severity: scan.SeverityWarning, Subject: point, Detail: detail}
	}
	return nil
}

func zfsPools(ctx context.Context, env *exec.Env) []scan.Finding {
	if env.Which("zpool") == "" {
		return nil
	}
	r := env.Run(ctx, "zpool", []string{"status", "-x"}, exec.Options{Timeout: 30 * time.Second})
	out := strings.TrimSpace(r.Stdout)
	if !r.OK() || out == "" || strings.Contains(out, "all pools are healthy") || strings.Contains(out, "no pools available") {
		return nil
	}
	return []scan.Finding{{Check: "zfs", Severity: scan.SeverityError, Subject: "zpool",
		Detail: "zpool status -x: " + firstLines(out, 4)}}
}

type smartReport struct {
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Model string `json:"model_name"`
}

// smart asks smartctl -H about each disk lsblk lists.
func smart(ctx context.Context, env *exec.Env) ([]scan.Finding, []string) {
	r := env.Run(ctx, "lsblk", []string{"-dnJ", "-o", "NAME,TYPE"}, exec.Options{Timeout: 15 * time.Second})
	if !r.OK() {
		return nil, []string{"lsblk failed: " + firstLines(r.Stderr, 1)}
	}
	var lb struct {
		Devices []struct{ Name, Type string } `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &lb); err != nil {
		return nil, []string{"lsblk: " + err.Error()}
	}
	var fs []scan.Finding
	var errs []string
	for _, d := range lb.Devices {
		if d.Type != "disk" || strings.HasPrefix(d.Name, "zram") || strings.HasPrefix(d.Name, "loop") {
			continue
		}
		dev := "/dev/" + d.Name
		res := env.Run(ctx, "sudo", []string{"-n", "smartctl", "-H", "-j", dev}, exec.Options{Timeout: 30 * time.Second})
		var rep smartReport
		if err := json.Unmarshal([]byte(res.Stdout), &rep); err != nil || rep.SmartStatus == nil {
			msg := firstLines(res.Stderr, 1)
			if msg == "" {
				msg = "no SMART status (unsupported, or sudo needs a password)"
			}
			errs = append(errs, fmt.Sprintf("smartctl %s: %s", dev, msg))
			continue
		}
		if !rep.SmartStatus.Passed {
			fs = append(fs, scan.Finding{Check: "smart", Severity: scan.SeverityCritical, Subject: dev,
				Detail: fmt.Sprintf("%s (%s) fails its SMART health check; back it up and replace it", dev, rep.Model)})
		}
	}
	return fs, errs
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " / ")
}
