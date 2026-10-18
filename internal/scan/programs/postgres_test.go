package programs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func TestSplitPostgresKV(t *testing.T) {
	cases := map[string][2]string{
		"listen_addresses = '*'":                {"listen_addresses", "*"},
		"ssl=off":                               {"ssl", "off"},
		"max_connections    100":                {"max_connections", "100"},
		"password_encryption = 'scram-sha-256'": {"password_encryption", "scram-sha-256"},
	}
	for in, want := range cases {
		k, v, ok := splitPostgresKV(in)
		if !ok || k != want[0] || v != want[1] {
			t.Errorf("splitPostgresKV(%q) = %q %q ok=%v want %q %q", in, k, v, ok, want[0], want[1])
		}
	}
}

func TestPostgresRules_ListenAll(t *testing.T) {
	for _, val := range []string{"*", "0.0.0.0", "0.0.0.0,127.0.0.1"} {
		out := postgresRules(map[string]string{"listen_addresses": val}, "test")
		if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
			t.Errorf("listen_addresses=%q should warn, got %+v", val, out)
		}
	}
}

func TestPostgresRules_ListenLocalhost_Quiet(t *testing.T) {
	out := postgresRules(map[string]string{"listen_addresses": "localhost"}, "test")
	for _, f := range out {
		if strings.Contains(f.Subject, "listen_addresses") {
			t.Errorf("localhost listen should not warn: %+v", f)
		}
	}
}

func TestPostgresRules_SSLOff(t *testing.T) {
	out := postgresRules(map[string]string{"ssl": "off"}, "test")
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("ssl=off should warn, got %+v", out)
	}
}

func TestPostgresRules_PasswordEncryption(t *testing.T) {
	out := postgresRules(map[string]string{"password_encryption": "md5"}, "test")
	if len(out) != 1 || out[0].Severity != scan.SeverityNotice {
		t.Errorf("password_encryption=md5 should be notice, got %+v", out)
	}
	out = postgresRules(map[string]string{"password_encryption": "scram-sha-256"}, "test")
	if len(out) != 0 {
		t.Errorf("scram-sha-256 should be quiet, got %+v", out)
	}
}

func TestPostgresRules_LogStatementAll(t *testing.T) {
	out := postgresRules(map[string]string{"log_statement": "all"}, "test")
	if len(out) != 1 || out[0].Severity != scan.SeverityNotice {
		t.Errorf("log_statement=all should be notice, got %+v", out)
	}
}

func TestPgHbaRules_TrustAuth(t *testing.T) {
	entries := []pgHbaEntry{
		{Type: "host", Address: "10.0.0.0/8", Method: "trust", Raw: "host all all 10.0.0.0/8 trust"},
	}
	out := pgHbaRules(entries, "pg_hba.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("trust auth should be critical, got %+v", out)
	}
}

func TestPgHbaRules_HostNonSSL(t *testing.T) {
	entries := []pgHbaEntry{
		{Type: "host", Address: "10.0.0.0/8", Method: "scram-sha-256", Raw: "host all all 10.0.0.0/8 scram-sha-256"},
	}
	out := pgHbaRules(entries, "pg_hba.conf")
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("plain host on non-loopback should warn, got %+v", out)
	}
}

func TestPgHbaRules_HostsslOK(t *testing.T) {
	entries := []pgHbaEntry{
		{Type: "hostssl", Address: "10.0.0.0/8", Method: "scram-sha-256", Raw: "hostssl all all 10.0.0.0/8 scram-sha-256"},
	}
	out := pgHbaRules(entries, "pg_hba.conf")
	if len(out) != 0 {
		t.Errorf("hostssl should be quiet, got %+v", out)
	}
}

func TestPgHbaRules_LoopbackOK(t *testing.T) {
	entries := []pgHbaEntry{
		{Type: "host", Address: "127.0.0.1/32", Method: "scram-sha-256", Raw: "host all all 127.0.0.1/32 scram-sha-256"},
	}
	out := pgHbaRules(entries, "pg_hba.conf")
	if len(out) != 0 {
		t.Errorf("loopback host should be quiet, got %+v", out)
	}
}

func TestIsLoopbackCIDR(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1/32": true,
		"127.0.0.0/8":  true,
		"::1/128":      true,
		"localhost":    true,
		"samehost":     true,
		"10.0.0.0/8":   false,
		"0.0.0.0/0":    false,
	}
	for in, want := range cases {
		if got := isLoopbackCIDR(in); got != want {
			t.Errorf("isLoopbackCIDR(%q) = %v want %v", in, got, want)
		}
	}
}
