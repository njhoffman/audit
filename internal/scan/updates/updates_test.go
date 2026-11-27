package updates

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/scan"
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

func TestKernels(t *testing.T) {
	if CompareKernels("6.17.0-41-generic", "6.12.10-76061203-generic") <= 0 || CompareKernels("6.17.0-9", "6.17.0-41") >= 0 ||
		CompareKernels("6.1", "6.1") != 0 {
		t.Error("CompareKernels")
	}
	root := t.TempDir()
	for _, k := range []string{"6.12.10-76061203-generic", "6.17.0-41-generic", "6.17.0-40-generic", "6.17.0-41-generic.old"} {
		write(t, root, "/boot/vmlinuz-"+k, "")
	}
	if got := Kernels(root); !reflect.DeepEqual(got, []string{"6.17.0-41-generic", "6.17.0-40-generic", "6.12.10-76061203-generic"}) {
		t.Errorf("kernels: %v", got)
	}
	if got := SecurityUpdates("Listing...\nopenssl/noble-updates,noble-security 3.0.2 amd64 [upgradable from: 3.0.1]\n" +
		"vim/noble-updates 9.1 amd64 [upgradable from: 9.0]\n"); !reflect.DeepEqual(got, []string{"openssl"}) {
		t.Errorf("security: %v", got)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	for _, k := range []string{"6.8.0-1", "6.9.0-1", "6.10.0-1", "6.11.0-2"} {
		write(t, root, "/boot/vmlinuz-"+k+"-generic", "")
	}
	write(t, root, "/run/reboot-required", "")
	write(t, root, "/run/reboot-required.pkgs", "linux-base\nlibc6\nlibc6\n")
	recent := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05")
	write(t, root, "/var/log/unattended-upgrades/unattended-upgrades.log", "2020-01-01 00:00:00,000 ERROR ancient\n"+
		recent+",123 ERROR Installing the upgrades failed!\n")
	fake := &exec.Fake{}
	fake.AddOutput("6.10.0-1-generic\n", "uname")
	fake.AddOutput("Listing...\nopenssl/noble-security 3 amd64 [upgradable from: 2]\n", "apt", "list")
	fake.AddOutput("active\nfailed\ninactive\n", "systemctl")
	fake.AddOutput(`{"Devices":[{"Name":"Dock","Version":"1.0","Releases":[{"Version":"1.2","Urgency":"high"}]}]}`, "fwupdmgr", "get-updates")
	bin := t.TempDir()
	for _, b := range []string{"apt", "fwupdmgr"} {
		write(t, bin, b, "")
		if err := os.Chmod(filepath.Join(bin, b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Scan(context.Background(), Options{Root: root, Env: &exec.Env{Vars: map[string]string{"PATH": bin}, Runner: fake}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.Check] = f.Detail
	}
	for check, want := range map[string]string{
		"reboot_required":  "a package update asks for a reboot (libc6, linux-base)",
		"kernel":           "kernel 6.11.0-2-generic is installed but 6.10.0-1-generic is running; reboot to use it",
		"old_kernels":      "4 kernels are installed",
		"security_updates": "1 security update(s) pending: openssl",
		"upgrade_failed":   "apt-daily-upgrade.service failed on its last run",
		"upgrade_errors":   "Installing the upgrades failed!",
		"firmware":         "1 firmware update(s): Dock 1.0 -> 1.2; fwupdmgr update applies them",
	} {
		if !strings.Contains(got[check], want) {
			t.Errorf("%s: %q, want it to contain %q", check, got[check], want)
		}
	}
	for _, f := range res.Findings {
		if f.Check == "firmware" && f.Severity != scan.SeverityWarning {
			t.Errorf("a high-urgency firmware release is a warning: %v", f.Severity)
		}
	}
	if strings.Contains(got["upgrade_errors"], "ancient") {
		t.Error("errors older than a week are left out")
	}
}

func TestFirmwareUpdates(t *testing.T) {
	out := `{"Devices":[{"Name":"UEFI dbx","Version":"20250902","Releases":[{"Version":"20260707"},{"Version":"20260402"}]},
{"Name":"Dock","Version":"1.0","Releases":[{"Version":"1.2","Urgency":"high"}]},{"Name":"Disk","Version":"3"}]}`
	ups, err := FirmwareUpdates(out)
	if err != nil || len(ups) != 2 || ups[0].To != "20260707" || ups[1].Urgency != "high" {
		t.Fatalf("%+v %v", ups, err)
	}
	if _, err := FirmwareUpdates("No updatable devices"); err == nil {
		t.Error("non-JSON is an error")
	}
}
