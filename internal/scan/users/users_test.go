package users

import (
	"context"
	"os"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestDeriveFindings(t *testing.T) {
	pwd := []PasswdEntry{
		{Name: "root", UID: 0, GID: 0, Shell: "/bin/bash"},
		{Name: "toor", UID: 0, GID: 0, Shell: "/bin/sh"},
		{Name: "daemon", UID: 1, GID: 1, Shell: "/bin/bash"},
		{Name: "me", UID: 1000, GID: 1000, Shell: "/bin/zsh"},
	}
	grp := []GroupEntry{{Name: "root", GID: 0}, {Name: "sudo", GID: 27, Members: []string{"me"}}}
	checks := func(fs []scan.Finding) map[string]bool {
		out := map[string]bool{}
		for _, f := range fs {
			out[f.Check] = true
		}
		return out
	}

	// Shadow unreadable: its checks are skipped and one info says so.
	fs := DeriveFindings(pwd, grp, nil, nil, false)
	got := checks(fs)
	for _, c := range []string{"uid0_extra", "uid_shared", "system_login_shell", "privileged_group", "shadow_unreadable"} {
		if !got[c] {
			t.Errorf("missing %s in %v", c, got)
		}
	}
	for i := 1; i < len(fs); i++ {
		if severityRank(fs[i].Severity) > severityRank(fs[i-1].Severity) {
			t.Fatalf("not sorted worst first at %d: %v then %v", i, fs[i-1].Severity, fs[i].Severity)
		}
	}

	// Readable shadow runs its checks instead of the info.
	shd := []ShadowEntry{{Name: "me", HashField: ""}, {Name: "toor", HashField: "!"}}
	got = checks(DeriveFindings(pwd, grp, shd, nil, true))
	if got["shadow_unreadable"] || !got["empty_password"] || !got["locked_with_shell"] {
		t.Errorf("readable shadow: %v", got)
	}
}

func TestSeverityRank(t *testing.T) {
	order := []scan.Severity{scan.SeverityCritical, scan.SeverityError, scan.SeverityWarning, scan.SeverityNotice, scan.SeverityInfo, "other"}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i]) >= severityRank(order[i-1]) {
			t.Errorf("%s should rank below %s", order[i], order[i-1])
		}
	}
}

// TestScanThisMachine reads the real /etc/passwd and /etc/group, which
// every Linux system has and every user may read.
func TestScanThisMachine(t *testing.T) {
	if _, err := os.Stat(PathPasswd); err != nil {
		t.Skip("no /etc/passwd")
	}
	res, err := Scan(context.Background(), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "users" || res.Summary["users_total"].(int) == 0 || res.Summary["groups_total"].(int) == 0 {
		t.Errorf("summary %v", res.Summary)
	}
	readable := res.Summary["shadow_readable"].(bool)
	if reason := res.Summary["shadow_skip_reason"].(string); readable == (reason != "") {
		t.Errorf("shadow readable %v with skip reason %q", readable, reason)
	}
	if byRange := res.Summary["users_by_range"].(map[string]int); byRange["root"] != 1 {
		t.Errorf("one root account: %v", byRange)
	}
	if st := statFiles(); st[PathPasswd] == nil || st[PathGroup] == nil {
		t.Errorf("stat %v", st)
	}
}
