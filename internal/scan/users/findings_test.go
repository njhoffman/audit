package users

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

// fakeStat is a minimal os.FileInfo for permission-mode tests.
type fakeStat struct {
	name string
	mode fs.FileMode
}

func (f fakeStat) Name() string       { return f.name }
func (f fakeStat) Size() int64        { return 0 }
func (f fakeStat) Mode() fs.FileMode  { return f.mode }
func (f fakeStat) ModTime() time.Time { return time.Time{} }
func (f fakeStat) IsDir() bool        { return false }
func (f fakeStat) Sys() any           { return nil }

func TestFindUID0Extras(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "root", UID: 0},
		{Name: "backdoor", UID: 0, Home: "/root", Shell: "/bin/bash"},
	}
	out := findUID0Extras(pwd)
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("want 1 critical finding, got %+v", out)
	}
	if !strings.Contains(out[0].Subject, "backdoor") {
		t.Errorf("subject: %q", out[0].Subject)
	}
}

func TestFindUIDCollisions(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "alice", UID: 1000},
		{Name: "alice2", UID: 1000},
		{Name: "bob", UID: 1001},
		{Name: "root2", UID: 0},
	}
	out := findUIDCollisions(pwd)
	if len(out) != 1 {
		t.Fatalf("want 1 collision finding (UID 1000), got %d: %+v", len(out), out)
	}
	if !strings.Contains(out[0].Subject, "1000") {
		t.Errorf("subject: %q", out[0].Subject)
	}
}

func TestFindUIDCollisions_Root(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "root", UID: 0},
		{Name: "backdoor", UID: 0},
	}
	out := findUIDCollisions(pwd)
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("UID 0 collision should be critical, got %+v", out)
	}
}

func TestFindGIDCollisions(t *testing.T) {
	grp := []GroupEntry{
		{Name: "g1", GID: 100},
		{Name: "g2", GID: 100},
		{Name: "g3", GID: 200},
	}
	out := findGIDCollisions(grp)
	if len(out) != 1 || !strings.Contains(out[0].Subject, "GID 100") {
		t.Errorf("got %+v", out)
	}
}

func TestFindSystemAccountsWithLoginShell(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "root", UID: 0, Shell: "/bin/bash"},           // skip (UID 0)
		{Name: "daemon", UID: 1, Shell: "/usr/sbin/nologin"}, // ok
		{Name: "weird", UID: 100, Shell: "/bin/bash"},        // flag
		{Name: "alice", UID: 1000, Shell: "/bin/bash"},       // skip (regular)
	}
	out := findSystemAccountsWithLoginShell(pwd)
	if len(out) != 1 || !strings.Contains(out[0].Subject, "weird") {
		t.Errorf("got %+v", out)
	}
}

func TestFindPrivilegedGroupMembership_SkipsRootInRoot(t *testing.T) {
	// "root" is the only user in group "root" by convention. Reporting
	// that is noise; the rule should suppress it.
	pwd := []PasswdEntry{{Name: "root", UID: 0, GID: 0}}
	grp := []GroupEntry{{Name: "root", GID: 0, Members: nil}}
	out := findPrivilegedGroupMembership(pwd, grp)
	if len(out) != 0 {
		t.Errorf("self-referential root-in-root should be suppressed, got %+v", out)
	}
}

func TestFindPrivilegedGroupMembership_RootWithExtras(t *testing.T) {
	// If anyone other than root is also in group root, the finding fires.
	pwd := []PasswdEntry{
		{Name: "root", UID: 0, GID: 0},
		{Name: "alice", UID: 1000, GID: 1000},
	}
	grp := []GroupEntry{{Name: "root", GID: 0, Members: []string{"alice"}}}
	out := findPrivilegedGroupMembership(pwd, grp)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding when alice is in root, got %+v", out)
	}
}

func TestFindPrivilegedGroupMembership_ExplicitAndPrimary(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "alice", UID: 1000, GID: 1000},
		{Name: "bob", UID: 1001, GID: 27}, // primary GID matches sudo
	}
	grp := []GroupEntry{
		{Name: "sudo", GID: 27, Members: []string{"alice"}},
		{Name: "users", GID: 1000, Members: nil},
	}
	out := findPrivilegedGroupMembership(pwd, grp)
	if len(out) != 1 {
		t.Fatalf("got %d findings: %+v", len(out), out)
	}
	f := out[0]
	if f.Subject != "sudo" || !strings.Contains(f.Detail, "alice") || !strings.Contains(f.Detail, "bob") {
		t.Errorf("want subject sudo with alice and bob in detail: %+v", f)
	}
}

func TestFindShadowAnomalies_EmptyHash(t *testing.T) {
	out := findShadowAnomalies(nil, []ShadowEntry{
		{Name: "ghost", HashField: ""},
	})
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("empty hash should be critical, got %+v", out)
	}
}

func TestFindShadowAnomalies_LockedWithLoginShell(t *testing.T) {
	pwd := []PasswdEntry{{Name: "alice", Shell: "/bin/bash"}}
	shd := []ShadowEntry{{Name: "alice", HashField: "!"}}
	out := findShadowAnomalies(pwd, shd)
	if len(out) != 1 || out[0].Check != "locked_with_shell" || out[0].Subject != "alice" {
		t.Errorf("got %+v", out)
	}
}

func TestFindShadowAnomalies_LockedNoShell_Ignored(t *testing.T) {
	pwd := []PasswdEntry{{Name: "daemon", Shell: "/usr/sbin/nologin"}}
	shd := []ShadowEntry{{Name: "daemon", HashField: "!"}}
	out := findShadowAnomalies(pwd, shd)
	if len(out) != 0 {
		t.Errorf("locked + nologin should be quiet, got %+v", out)
	}
}

func TestFindFilePermAnomalies(t *testing.T) {
	stats := map[string]os.FileInfo{
		PathPasswd: fakeStat{name: "passwd", mode: 0o644}, // ok
		PathGroup:  fakeStat{name: "group", mode: 0o666},  // loose (world-writable)
		PathShadow: fakeStat{name: "shadow", mode: 0o644}, // critical (world-readable)
	}
	out := findFilePermAnomalies(stats)
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(out), out)
	}
	var sawShadowCritical bool
	for _, f := range out {
		if strings.Contains(f.Subject, "shadow") && f.Severity == scan.SeverityCritical {
			sawShadowCritical = true
		}
	}
	if !sawShadowCritical {
		t.Errorf("shadow anomaly should be critical, got %+v", out)
	}
}
