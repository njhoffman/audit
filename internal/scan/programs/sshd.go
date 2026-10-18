package programs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

const (
	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdConfigDir  = "/etc/ssh/sshd_config.d"
)

func analyzeSSHD(ctx context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramSSHD, Source: sshdConfigPath}

	// Quick existence check: no point analyzing if the daemon is not
	// configured on this host.
	if _, err := os.Stat(sshdConfigPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out.Skipped = true
			out.Reason = "/etc/ssh/sshd_config not present"
			return out
		}
		out.Skipped = true
		out.Reason = err.Error()
		return out
	}

	// Try syntax check. `sshd -t -f` is mostly a config-file lint but
	// modern OpenSSH also tries to load host keys, which requires root.
	// We treat the host-keys error as "syntax check skipped" rather than
	// a real syntax failure to avoid a false positive on every
	// unprivileged audit.
	if path, err := exec.LookPath("sshd"); err == nil {
		// #nosec G204 -- fixed argv with a known path.
		cmd := exec.CommandContext(ctx, path, "-t", "-f", sshdConfigPath)
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if strings.Contains(msg, "no hostkeys available") ||
				strings.Contains(msg, "Permission denied") {
				out.Notes = append(out.Notes,
					"sshd -t skipped (run as root to validate): "+msg)
			} else {
				out.Findings = append(out.Findings, scan.Finding{
					Severity: scan.SeverityError,
					Subject:  "sshd: config failed syntax check (sshd -t)",
					Detail:   msg,
				})
			}
		} else {
			out.Notes = append(out.Notes, "sshd -t passed")
		}
	} else {
		out.Notes = append(out.Notes, "sshd binary not on PATH; skipping syntax check")
	}

	directives, parseNotes := loadSSHDDirectives()
	out.Notes = append(out.Notes, parseNotes...)
	out.Findings = append(out.Findings, sshdRules(directives)...)
	out.Notes = append(out.Notes, "checks apply to explicitly-set directives only; OpenSSH defaults are not enforced")
	return out
}

// sshdDirective is one effective directive value. We track the value and
// where it came from so a finding's detail can point at the right file.
type sshdDirective struct {
	Value  string
	Source string
}

// loadSSHDDirectives reads /etc/ssh/sshd_config and *.conf files in
// /etc/ssh/sshd_config.d/, applying first-wins precedence (which is how
// OpenSSH handles top-level Include directives). Match blocks are skipped
// — auditing them requires more context than we have here.
func loadSSHDDirectives() (map[string]sshdDirective, []string) {
	out := map[string]sshdDirective{}
	notes := []string{}

	files := []string{sshdConfigPath}
	entries, err := os.ReadDir(sshdConfigDir)
	if err == nil {
		extras := []string{}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			extras = append(extras, filepath.Join(sshdConfigDir, e.Name()))
		}
		sort.Strings(extras)
		// Drop-in files in /etc/ssh/sshd_config.d are typically Included
		// from the top of sshd_config, so they take precedence.
		files = append(extras, files...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		notes = append(notes, "could not read "+sshdConfigDir+": "+err.Error())
	}

	for _, path := range files {
		merged, err := parseSSHDFile(path)
		if err != nil {
			notes = append(notes, fmt.Sprintf("could not read %s: %s", path, err))
			continue
		}
		for k, v := range merged {
			if _, set := out[k]; !set {
				out[k] = sshdDirective{Value: v, Source: path}
			}
		}
	}
	return out, notes
}

func parseSSHDFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- caller iterates known sshd config paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	inMatch := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Once a Match block opens, subsequent directives apply only to
		// that match. Skip them to avoid double-counting.
		if strings.HasPrefix(strings.ToLower(line), "match ") {
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		// First occurrence wins per OpenSSH semantics.
		k := strings.ToLower(key)
		if _, set := out[k]; !set {
			out[k] = value
		}
	}
	return out, scanner.Err()
}

func splitDirective(line string) (string, string, bool) {
	// sshd_config separates key/value with whitespace; "=" is also
	// accepted by older OpenSSH versions. Treat both.
	for i, r := range line {
		if r == ' ' || r == '\t' || r == '=' {
			key := strings.TrimSpace(line[:i])
			value := strings.TrimSpace(line[i+1:])
			value = strings.TrimLeft(value, "\t =")
			if key == "" {
				return "", "", false
			}
			return key, value, true
		}
	}
	return "", "", false
}

// sshdRules holds the audit logic. Conservative: only fires on explicit
// directives so we do not produce phantom findings for a file that
// happens to be silent.
func sshdRules(d map[string]sshdDirective) []scan.Finding {
	out := []scan.Finding{}
	get := func(k string) (sshdDirective, bool) {
		v, ok := d[strings.ToLower(k)]
		return v, ok
	}

	if v, ok := get("PermitRootLogin"); ok {
		switch strings.ToLower(v.Value) {
		case "yes":
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  "sshd: PermitRootLogin yes",
				Detail:   "Allows root to log in via SSH (including password if PasswordAuthentication is also yes). Source: " + v.Source,
			})
		case "without-password", "prohibit-password":
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "sshd: PermitRootLogin " + v.Value,
				Detail:   "Root SSH login by key is allowed. Some hardening guides require setting this to `no`. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("PasswordAuthentication"); ok {
		if strings.EqualFold(v.Value, "yes") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  "sshd: PasswordAuthentication yes",
				Detail:   "Allows interactive password logins; consider key-only authentication. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("PermitEmptyPasswords"); ok {
		if strings.EqualFold(v.Value, "yes") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  "sshd: PermitEmptyPasswords yes",
				Detail:   "Allows accounts with no password to log in. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("Protocol"); ok {
		if strings.Contains(v.Value, "1") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  "sshd: SSH Protocol 1 enabled",
				Detail:   "Protocol 1 is deprecated and insecure. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("X11Forwarding"); ok {
		if strings.EqualFold(v.Value, "yes") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "sshd: X11Forwarding yes",
				Detail:   "X11 forwarding broadens the local-display attack surface for SSH clients. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("PermitTunnel"); ok {
		if !strings.EqualFold(v.Value, "no") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "sshd: PermitTunnel " + v.Value,
				Detail:   "tun(4) device forwarding is enabled. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("LogLevel"); ok {
		switch strings.ToUpper(v.Value) {
		case "QUIET", "FATAL", "ERROR":
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "sshd: LogLevel " + v.Value,
				Detail:   "Reduces audit visibility; consider INFO or VERBOSE. Source: " + v.Source,
			})
		}
	}
	if v, ok := get("MaxAuthTries"); ok {
		// Heuristic: allow up to 6 by default. Anything looser is a
		// brute-force concession.
		if n := atoiZero(v.Value); n > 6 {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  fmt.Sprintf("sshd: MaxAuthTries %d", n),
				Detail:   "Higher MaxAuthTries widens the brute-force window. Source: " + v.Source,
			})
		}
	}
	return out
}

func atoiZero(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
