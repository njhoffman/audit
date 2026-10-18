package logs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		// PID, IPv4, port number normalized; "ssh2" stays because the 2
		// has no word boundary to its left (intentional: keeps program
		// names like ssh2/v6/python3 intact).
		"sshd[12345]: Failed password for root from 10.0.0.5 port 22 ssh2": "sshd[<pid>]: Failed password for root from <ip> port <n> ssh2",
		"systemd[1]: starting nginx.service":                               "systemd[<pid>]: starting nginx.service",
		"connection from 2001:db8::1 to 2001:db8::2":                       "connection from <ip> to <ip>",
		"job 550e8400-e29b-41d4-a716-446655440000 finished":                "job <uuid> finished",
		"call at 0xffff800012345678":                                       "call at <hex>",
		"open /etc/passwd failed":                                          "open <path> failed",
	}
	for in, want := range cases {
		got := Normalize(in)
		if got != want {
			t.Errorf("Normalize(%q)\n got=%q\nwant=%q", in, got, want)
		}
	}
}

func TestTopBuckets_SortsByCountThenAlpha(t *testing.T) {
	// Three groups that all normalize to the same key per group. Pattern
	// normalization collapses IPs, PIDs, and port numbers but not free-form
	// names — that's why these messages share variable IPs.
	entries := []Entry{
		{Message: "Failed password from 1.2.3.4"},
		{Message: "Failed password from 5.6.7.8"},
		{Message: "Failed password from 9.10.11.12"},
		{Message: "Killed pid 12345 (chrome)"},
		{Message: "Killed pid 67890 (chrome)"},
		{Message: "unique line never repeated"},
	}
	got := TopBuckets(entries, 5)
	if len(got) != 3 {
		t.Fatalf("want 3 buckets, got %d: %+v", len(got), got)
	}
	if got[0].Count != 3 {
		t.Errorf("top bucket count: got %d want 3 (%+v)", got[0].Count, got[0])
	}
	if got[1].Count != 2 || got[2].Count != 1 {
		t.Errorf("counts: %+v", got)
	}
}

func TestTopBuckets_LimitsN(t *testing.T) {
	entries := []Entry{}
	for i := 0; i < 10; i++ {
		entries = append(entries, Entry{Message: "msg"})
	}
	for i := 0; i < 5; i++ {
		entries = append(entries, Entry{Message: "other"})
	}
	got := TopBuckets(entries, 1)
	if len(got) != 1 || got[0].Count != 10 {
		t.Errorf("expected one bucket with count 10, got %+v", got)
	}
}

func TestApplyRules_KernelPanic(t *testing.T) {
	out := ApplyRules(SourceDmesg, []Entry{{Message: "Kernel panic - not syncing: VFS"}})
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("kernel panic finding: %+v", out)
	}
}

func TestApplyRules_OOM(t *testing.T) {
	out := ApplyRules(SourceJournal, []Entry{{Message: "Out of memory: Killed process 1234 (chrome)"}})
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("OOM finding: %+v", out)
	}
	if out[0].Check != "oom-kill" || out[0].Subject != "journal" || !strings.Contains(out[0].Detail, "OOM killer") {
		t.Errorf("OOM finding: %+v", out[0])
	}
}

func TestApplyRules_AggregatesMultipleHits(t *testing.T) {
	entries := []Entry{
		{Message: "Failed password for alice from 1.2.3.4"},
		{Message: "Failed password for bob from 1.2.3.4"},
		{Message: "Failed password for carol from 1.2.3.4"},
	}
	out := ApplyRules(SourceAuth, entries)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding (auth-failure), got %d", len(out))
	}
	if out[0].Subject != "auth" || !strings.Contains(out[0].Detail, "(3 hit(s))") {
		t.Errorf("expected stable subject and hit count in detail: %+v", out[0])
	}
}

func TestApplyRules_HardwareErrorIgnoresEDACBanner(t *testing.T) {
	// Regression: previous pattern `EDAC` matched "EDAC MC: Ver: 3.0.0"
	// at boot, which is the init banner, not a real error.
	out := ApplyRules(SourceDmesg, []Entry{{Message: "EDAC MC: Ver: 3.0.0"}})
	for _, f := range out {
		if strings.Contains(f.Subject, "hardware error") {
			t.Errorf("EDAC init banner should not fire hardware-error rule: %+v", f)
		}
	}
}

func TestApplyRules_HardwareErrorMatchesRealEvent(t *testing.T) {
	out := ApplyRules(SourceDmesg, []Entry{
		{Message: "EDAC MC0: 1 CE memory read error on CPU_SrcID#0_MC#0_Chan#0_DIMM#0"},
	})
	if len(out) != 1 || out[0].Severity != scan.SeverityError {
		t.Errorf("real EDAC CE should fire: %+v", out)
	}
}

func TestApplyRules_NoMatch(t *testing.T) {
	out := ApplyRules(SourceJournal, []Entry{{Message: "boring routine startup line"}})
	if len(out) != 0 {
		t.Errorf("expected no findings, got %+v", out)
	}
}
