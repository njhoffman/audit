package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/scan"
)

func TestParseMounts(t *testing.T) {
	ms := ParseMounts(`/dev/nvme0n1p2 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
/dev/nvme0n1p2 /var/snap ext4 rw 0 0
/dev/loop1 /snap/core/1 squashfs ro 0 0
/dev/sda1 /media/my\040disk vfat ro 0 0
/dev/sdb1 /data xfs ro,noatime 0 0
`)
	if len(ms) != 3 || ms[0].Point != "/" || ms[1].Point != "/media/my disk" || !ms[2].ReadOnly || ms[0].ReadOnly {
		t.Errorf("mounts: %+v", ms)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc/self"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/self/mounts"), []byte("/dev/a / ext4 rw 0 0\n/dev/b /home ext4 rw 0 0\n"+
		"/dev/c /data xfs ro 0 0\n/dev/d /ok ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := Statfs
	t.Cleanup(func() { Statfs = old })
	Statfs = func(p string) (Usage, error) {
		switch p {
		case "/":
			return Usage{Total: 100, Free: 2, Avail: 1, Files: 100, FilesFree: 50}, nil
		case "/home":
			return Usage{Total: 100, Free: 8, Avail: 8, Files: 100, FilesFree: 5}, nil
		}
		return Usage{Total: 100, Free: 50, Avail: 50, Files: 100, FilesFree: 90}, nil
	}
	fake := &exec.Fake{}
	fake.AddOutput(`{"blockdevices":[{"name":"sda","type":"disk"},{"name":"zram0","type":"disk"},{"name":"sr0","type":"rom"}]}`, "lsblk")
	fake.AddOutput(`{"model_name":"Old Disk","smart_status":{"passed":false}}`, "sudo", "-n", "smartctl")
	o := DefaultOptions()
	o.Root, o.SMART, o.Env = root, true, &exec.Env{Vars: map[string]string{"PATH": ""}, Runner: fake}
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]scan.Severity{}
	for _, f := range res.Findings {
		got[f.Check+" "+f.Subject] = f.Severity
	}
	want := map[string]scan.Severity{"full /": scan.SeverityError, "full /home": scan.SeverityWarning,
		"inodes /home": scan.SeverityWarning, "read_only /data": scan.SeverityWarning, "smart /dev/sda": scan.SeverityCritical}
	if len(got) != len(want) {
		t.Errorf("findings: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q (all %v)", k, got[k], got)
		}
	}
	for _, c := range fake.Calls {
		if len(c) > 3 && c[3] == "/dev/zram0" {
			t.Error("zram is not a disk to check")
		}
	}
}
