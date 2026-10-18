package programs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestNginxRules_ServerTokensOn(t *testing.T) {
	cfg := `
http {
    server_tokens on;
}
`
	out := nginxRules(cfg)
	if len(out) != 1 || !strings.Contains(out[0].Subject, "server_tokens") {
		t.Errorf("got %+v", out)
	}
}

func TestNginxRules_AutoindexOn(t *testing.T) {
	cfg := "    autoindex on;\n"
	out := nginxRules(cfg)
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("autoindex=on should warn, got %+v", out)
	}
}

func TestNginxRules_DeprecatedTLS(t *testing.T) {
	cases := []string{
		"ssl_protocols TLSv1 TLSv1.2;",
		"ssl_protocols TLSv1.1;",
		"ssl_protocols SSLv3 TLSv1.2;",
	}
	for _, c := range cases {
		out := nginxRules(c)
		if len(out) != 1 || out[0].Severity != scan.SeverityError {
			t.Errorf("config %q should fire deprecated TLS, got %+v", c, out)
		}
	}
}

func TestNginxRules_ModernTLSOK(t *testing.T) {
	cfg := "ssl_protocols TLSv1.2 TLSv1.3;"
	out := nginxRules(cfg)
	for _, f := range out {
		if strings.Contains(f.Subject, "deprecated") {
			t.Errorf("modern TLS should not fire deprecated rule, got %+v", f)
		}
	}
}

func TestNginxRules_WeakCiphers(t *testing.T) {
	cfg := "ssl_ciphers RC4-SHA:HIGH:!aNULL;"
	out := nginxRules(cfg)
	if len(out) != 1 || out[0].Severity != scan.SeverityError {
		t.Errorf("RC4 should fire weak-cipher, got %+v", out)
	}
}

func TestNginxRules_Empty(t *testing.T) {
	out := nginxRules("")
	if len(out) != 0 {
		t.Errorf("empty config should be quiet, got %+v", out)
	}
}
