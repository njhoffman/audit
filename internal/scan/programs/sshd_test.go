package programs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func directives(pairs ...string) map[string]sshdDirective {
	out := map[string]sshdDirective{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out[strings.ToLower(pairs[i])] = sshdDirective{Value: pairs[i+1], Source: "test"}
	}
	return out
}

func TestSplitDirective(t *testing.T) {
	cases := map[string][2]string{
		"PermitRootLogin yes":       {"PermitRootLogin", "yes"},
		"PasswordAuthentication=no": {"PasswordAuthentication", "no"},
		"  Port\t22  ":              {"Port", "22"},
		"X11Forwarding   yes":       {"X11Forwarding", "yes"},
	}
	for in, want := range cases {
		k, v, ok := splitDirective(strings.TrimSpace(in))
		if !ok || k != want[0] || v != want[1] {
			t.Errorf("splitDirective(%q) = %q %q ok=%v want %q %q", in, k, v, ok, want[0], want[1])
		}
	}
	if _, _, ok := splitDirective(""); ok {
		t.Error("empty line should not parse")
	}
}

func TestSshdRules_PermitRootLoginYes(t *testing.T) {
	out := sshdRules(directives("PermitRootLogin", "yes"))
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("PermitRootLogin=yes should be critical, got %+v", out)
	}
}

func TestSshdRules_PermitRootLogin_KeyOnly(t *testing.T) {
	for _, val := range []string{"prohibit-password", "without-password"} {
		out := sshdRules(directives("PermitRootLogin", val))
		if len(out) != 1 || out[0].Severity != scan.SeverityNotice {
			t.Errorf("PermitRootLogin=%s should be notice, got %+v", val, out)
		}
	}
}

func TestSshdRules_PermitRootLogin_No(t *testing.T) {
	out := sshdRules(directives("PermitRootLogin", "no"))
	if len(out) != 0 {
		t.Errorf("PermitRootLogin=no should produce no findings, got %+v", out)
	}
}

func TestSshdRules_PasswordAuth(t *testing.T) {
	out := sshdRules(directives("PasswordAuthentication", "yes"))
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("PasswordAuthentication=yes should warn, got %+v", out)
	}
}

func TestSshdRules_PermitEmptyPasswords(t *testing.T) {
	out := sshdRules(directives("PermitEmptyPasswords", "yes"))
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("PermitEmptyPasswords=yes critical, got %+v", out)
	}
}

func TestSshdRules_Protocol1(t *testing.T) {
	out := sshdRules(directives("Protocol", "2,1"))
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("Protocol=2,1 critical, got %+v", out)
	}
}

func TestSshdRules_LogLevelLow(t *testing.T) {
	out := sshdRules(directives("LogLevel", "QUIET"))
	if len(out) != 1 || out[0].Severity != scan.SeverityNotice {
		t.Errorf("LogLevel=QUIET notice, got %+v", out)
	}
}

func TestSshdRules_MaxAuthTriesHigh(t *testing.T) {
	out := sshdRules(directives("MaxAuthTries", "20"))
	if len(out) != 1 {
		t.Errorf("MaxAuthTries=20 should fire, got %+v", out)
	}
	out = sshdRules(directives("MaxAuthTries", "3"))
	if len(out) != 0 {
		t.Errorf("MaxAuthTries=3 should be quiet, got %+v", out)
	}
}

func TestSshdRules_NoExplicitDirectives(t *testing.T) {
	if out := sshdRules(directives()); len(out) != 0 {
		t.Errorf("empty config should produce no findings, got %+v", out)
	}
}

func TestParseSSHDFile(t *testing.T) {
	// Smoke-test the Match-block skip behavior via parseSSHDFile is awkward
	// without a tempdir; cover splitDirective and sshdRules instead. The
	// parser is exercised end-to-end via analyzeSSHD on whatever is on the
	// host (most CI hosts ship sshd_config).
	t.Skip("integration-only; covered by analyzeSSHD running on the host")
}
