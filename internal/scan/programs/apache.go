package programs

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

// apacheConfigCandidates lists the conventional layouts for Debian/Ubuntu
// (apache2) and RHEL/Fedora (httpd). The first one that exists wins.
var apacheConfigCandidates = []string{
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
}

// apacheBinaries lists the known control binaries to try in order.
var apacheBinaries = []string{"apache2ctl", "apachectl", "httpd", "apache2"}

func analyzeApache(ctx context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramApache}

	confPath := ""
	for _, cand := range apacheConfigCandidates {
		if _, err := os.Stat(cand); err == nil {
			confPath = cand
			break
		}
	}
	bin := ""
	for _, name := range apacheBinaries {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
			break
		}
	}
	if confPath == "" && bin == "" {
		out.Skipped = true
		out.Reason = "no apache config or control binary found"
		return out
	}
	out.Source = confPath

	if bin != "" {
		// Syntax check. Both apachectl/apache2ctl support `-t`.
		// #nosec G204 -- LookPath result with a fixed argv.
		cmd := exec.CommandContext(ctx, bin, "-t")
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			out.Notes = append(out.Notes, "apache -t failed (often needs root): "+msg)
		} else {
			out.Notes = append(out.Notes, "apache -t passed")
		}
	}

	if confPath != "" {
		text, err := readApacheTree(confPath)
		if err != nil {
			out.Notes = append(out.Notes, err.Error())
		} else {
			out.Findings = append(out.Findings, apacheRules(text, confPath)...)
		}
	}
	out.Notes = append(out.Notes, "checks apply to text patterns; defaults are not enforced")
	return out
}

// readApacheTree reads the main config plus the most-common include
// directories (conf.d, conf-enabled, sites-enabled) so directives that
// landed via includes are still visible to the rule engine.
func readApacheTree(mainConf string) (string, error) {
	main, err := os.ReadFile(mainConf) // #nosec G304 -- well-known config path
	if err != nil {
		return "", err
	}
	parts := []string{string(main)}
	root := filepath.Dir(mainConf)
	for _, sub := range []string{"conf.d", "conf-enabled", "sites-enabled", "mods-enabled"} {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			continue
		}
		for _, e := range entries {
			if !e.Type().IsRegular() && e.Type()&os.ModeSymlink == 0 {
				continue
			}
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304
			if err != nil {
				continue
			}
			parts = append(parts, string(data))
		}
	}
	return strings.Join(parts, "\n"), nil
}

var (
	reApacheServerTokens    = regexp.MustCompile(`(?im)^\s*ServerTokens\s+(\S+)`)
	reApacheServerSignature = regexp.MustCompile(`(?im)^\s*ServerSignature\s+(\S+)`)
	reApacheTraceEnable     = regexp.MustCompile(`(?im)^\s*TraceEnable\s+(\S+)`)
	reApacheIndexes         = regexp.MustCompile(`(?im)^\s*Options\s+[^#\n]*\bIndexes\b`)
	reApacheSSLProtocol     = regexp.MustCompile(`(?im)^\s*SSLProtocol\s+([^\n#]+)`)
	reApacheSSLCipher       = regexp.MustCompile(`(?im)^\s*SSLCipherSuite\s+([^\n#]+)`)
)

func apacheRules(config, source string) []scan.Finding {
	out := []scan.Finding{}

	if m := reApacheServerTokens.FindStringSubmatch(config); len(m) == 2 {
		v := strings.ToLower(m[1])
		if v == "full" || v == "os" {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "apache: ServerTokens " + m[1],
				Detail:   "Reveals OS / detailed version in error pages and Server: header. Set to Prod. Source: " + source,
			})
		}
	}
	if m := reApacheServerSignature.FindStringSubmatch(config); len(m) == 2 {
		if strings.EqualFold(m[1], "On") || strings.EqualFold(m[1], "EMail") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "apache: ServerSignature " + m[1],
				Detail:   "Adds a server-version footer to error pages. Source: " + source,
			})
		}
	}
	if m := reApacheTraceEnable.FindStringSubmatch(config); len(m) == 2 {
		if strings.EqualFold(m[1], "On") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  "apache: TraceEnable On",
				Detail:   "TRACE is enabled and can amplify XSS in some setups. Source: " + source,
			})
		}
	}
	if reApacheIndexes.MatchString(config) {
		out = append(out, scan.Finding{
			Severity: scan.SeverityWarning,
			Subject:  "apache: directory Indexes option enabled",
			Detail:   "Directory listings are exposed; verify only intended paths use Indexes. Source: " + source,
		})
	}
	if m := reApacheSSLProtocol.FindStringSubmatch(config); len(m) == 2 {
		v := strings.ToLower(m[1])
		// SSLProtocol "all" with no `-TLSv1` exclusions still covers SSLv3+TLSv1+1.1 on older mod_ssl builds.
		if strings.Contains(v, "+sslv2") || strings.Contains(v, "+sslv3") ||
			strings.Contains(v, "+tlsv1 ") || strings.Contains(v, "+tlsv1.1") ||
			(strings.Contains(v, "all") && !strings.Contains(v, "-tlsv1") && !strings.Contains(v, "-sslv3")) {
			out = append(out, scan.Finding{
				Severity: scan.SeverityError,
				Subject:  "apache: SSLProtocol allows deprecated versions",
				Detail:   "SSLProtocol value: " + strings.TrimSpace(m[1]) + ". Source: " + source,
			})
		}
	}
	if m := reApacheSSLCipher.FindStringSubmatch(config); len(m) == 2 {
		v := strings.ToLower(m[1])
		if strings.Contains(v, "rc4") || strings.Contains(v, "des") ||
			strings.Contains(v, "md5") || strings.Contains(v, "null") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityError,
				Subject:  "apache: SSLCipherSuite includes weak ciphers",
				Detail:   "SSLCipherSuite: " + strings.TrimSpace(m[1]) + ". Source: " + source,
			})
		}
	}
	return out
}
