package programs

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

const nginxConfigPath = "/etc/nginx/nginx.conf"

func analyzeNginx(ctx context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramNginx, Source: nginxConfigPath}

	path, err := exec.LookPath("nginx")
	if err != nil {
		// No nginx on PATH — also try the file as a hint that maybe a
		// custom build is in use. For now treat as skipped.
		if _, statErr := os.Stat(nginxConfigPath); errors.Is(statErr, fs.ErrNotExist) {
			out.Skipped = true
			out.Reason = "nginx binary not on PATH and no /etc/nginx/nginx.conf"
			return out
		}
		out.Skipped = true
		out.Reason = "nginx binary not on PATH"
		return out
	}

	// Syntax check.
	// #nosec G204 -- fixed argv with LookPath result.
	cmd := exec.CommandContext(ctx, path, "-t")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		out.Findings = append(out.Findings, scan.Finding{
			Severity: scan.SeverityError,
			Subject:  "nginx: config failed syntax check (nginx -t)",
			Detail:   strings.TrimSpace(stderr.String()),
		})
		// Continue on; the dump may still parse.
	} else {
		out.Notes = append(out.Notes, "nginx -t passed")
	}

	// Effective config dump. -T includes -t plus prints all included files.
	// #nosec G204 -- fixed argv with LookPath result.
	dump := exec.CommandContext(ctx, path, "-T")
	stdout := &bytes.Buffer{}
	dump.Stdout = stdout
	dump.Stderr = &bytes.Buffer{}
	if err := dump.Run(); err != nil {
		out.Notes = append(out.Notes,
			"nginx -T failed; falling back to /etc/nginx/nginx.conf parse")
		if data, ferr := os.ReadFile(nginxConfigPath); ferr == nil { // #nosec G304
			stdout.Write(data)
		}
	}
	out.Findings = append(out.Findings, nginxRules(stdout.String())...)
	return out
}

var (
	reServerTokensOn = regexp.MustCompile(`(?m)^\s*server_tokens\s+on\s*;`)
	reAutoindexOn    = regexp.MustCompile(`(?m)^\s*autoindex\s+on\s*;`)
	reSSLProtocols   = regexp.MustCompile(`(?m)^\s*ssl_protocols\s+([^;]+);`)
	reSSLCiphers     = regexp.MustCompile(`(?m)^\s*ssl_ciphers\s+([^;]+);`)
)

func nginxRules(config string) []scan.Finding {
	out := []scan.Finding{}

	if reServerTokensOn.MatchString(config) {
		out = append(out, scan.Finding{
			Severity: scan.SeverityNotice,
			Subject:  "nginx: server_tokens on",
			Detail:   "Reveals nginx version in error pages and Server: header. Set to off to reduce fingerprinting.",
		})
	}
	if reAutoindexOn.MatchString(config) {
		out = append(out, scan.Finding{
			Severity: scan.SeverityWarning,
			Subject:  "nginx: autoindex on",
			Detail:   "Directory listings are exposed; verify only intended paths use autoindex.",
		})
	}
	if m := reSSLProtocols.FindStringSubmatch(config); len(m) == 2 {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "tlsv1 ") || strings.HasSuffix(strings.TrimSpace(v), "tlsv1") ||
			strings.Contains(v, "tlsv1.1") || strings.Contains(v, "sslv2") || strings.Contains(v, "sslv3") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityError,
				Subject:  "nginx: deprecated SSL/TLS protocols enabled",
				Detail:   "ssl_protocols includes a deprecated version: " + strings.TrimSpace(m[1]),
			})
		}
	}
	if m := reSSLCiphers.FindStringSubmatch(config); len(m) == 2 {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "rc4") || strings.Contains(v, "des") || strings.Contains(v, "md5") || strings.Contains(v, "null") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityError,
				Subject:  "nginx: weak ssl_ciphers",
				Detail:   "ssl_ciphers references a known-weak family (RC4/DES/MD5/NULL): " + strings.TrimSpace(m[1]),
			})
		}
	}
	return out
}
