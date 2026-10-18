package programs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestApacheRules_ServerTokensFull(t *testing.T) {
	cfg := "ServerTokens Full\n"
	out := apacheRules(cfg, "apache2.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityNotice {
		t.Errorf("ServerTokens Full should be notice, got %+v", out)
	}
}

func TestApacheRules_ServerTokensProd_Quiet(t *testing.T) {
	cfg := "ServerTokens Prod\n"
	out := apacheRules(cfg, "apache2.conf")
	for _, f := range out {
		if strings.Contains(f.Subject, "ServerTokens") {
			t.Errorf("Prod should be quiet: %+v", f)
		}
	}
}

func TestApacheRules_TraceEnable(t *testing.T) {
	cfg := "TraceEnable On\n"
	out := apacheRules(cfg, "apache2.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("TraceEnable On should warn, got %+v", out)
	}
}

func TestApacheRules_DirectoryIndexes(t *testing.T) {
	cfg := `<Directory /var/www>
    Options Indexes FollowSymLinks
</Directory>
`
	out := apacheRules(cfg, "apache2.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("Options Indexes should warn, got %+v", out)
	}
}

func TestApacheRules_SSLProtocolDeprecated(t *testing.T) {
	cases := []string{
		"SSLProtocol all -SSLv2",
		"SSLProtocol all",
		"SSLProtocol +SSLv3 +TLSv1.2",
		"SSLProtocol +TLSv1.1",
	}
	for _, c := range cases {
		out := apacheRules(c, "apache2.conf")
		var found bool
		for _, f := range out {
			if strings.Contains(f.Subject, "SSLProtocol") {
				found = true
				if f.Severity != scan.SeverityError {
					t.Errorf("config %q: expected error severity, got %v", c, f.Severity)
				}
			}
		}
		if !found {
			t.Errorf("config %q should fire SSLProtocol rule, got %+v", c, out)
		}
	}
}

func TestApacheRules_SSLProtocolSafe(t *testing.T) {
	cfg := "SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n"
	out := apacheRules(cfg, "apache2.conf")
	for _, f := range out {
		if strings.Contains(f.Subject, "SSLProtocol") {
			t.Errorf("safe SSLProtocol should be quiet, got %+v", f)
		}
	}
}

func TestApacheRules_WeakCiphers(t *testing.T) {
	cfg := "SSLCipherSuite HIGH:!aNULL:RC4-SHA\n"
	out := apacheRules(cfg, "apache2.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityError {
		t.Errorf("RC4 should fire weak-cipher, got %+v", out)
	}
}

func TestApacheRules_Empty(t *testing.T) {
	if out := apacheRules("", "apache2.conf"); len(out) != 0 {
		t.Errorf("empty config should be quiet, got %+v", out)
	}
}
