package programs

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

const postgresGlob = "/etc/postgresql/*/main/postgresql.conf"

func analyzePostgres(_ context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramPostgres}

	matches, err := filepath.Glob(postgresGlob)
	if err != nil || len(matches) == 0 {
		out.Skipped = true
		out.Reason = "no postgresql.conf under /etc/postgresql/*/main/"
		return out
	}
	sort.Strings(matches)
	confPath := matches[0]
	if len(matches) > 1 {
		out.Notes = append(out.Notes, "multiple postgresql.conf candidates; auditing first: "+confPath)
	}
	out.Source = confPath

	directives, err := readPostgresDirectives(confPath)
	if err != nil {
		out.Skipped = true
		out.Reason = err.Error()
		return out
	}
	out.Findings = append(out.Findings, postgresRules(directives, confPath)...)

	// Sibling pg_hba.conf gets its own rule pass.
	hbaPath := filepath.Join(filepath.Dir(confPath), "pg_hba.conf")
	if hba, err := readPgHba(hbaPath); err == nil {
		out.Findings = append(out.Findings, pgHbaRules(hba, hbaPath)...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		out.Notes = append(out.Notes, "could not read "+hbaPath+": "+err.Error())
	}
	out.Notes = append(out.Notes, "checks apply to explicitly-set directives only; postgres defaults are not enforced")
	return out
}

// readPostgresDirectives parses postgresql.conf KEY = 'value' pairs. The
// official format allows either spaces or `=` between key and value, an
// optional single-quoted value, and `#` comments.
func readPostgresDirectives(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- caller globs a known root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comment.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		k, v, ok := splitPostgresKV(line)
		if !ok {
			continue
		}
		// First-occurrence-wins for our purposes; postgres re-reads but
		// the file is normally a single canonical source.
		if _, set := out[k]; !set {
			out[strings.ToLower(k)] = v
		}
	}
	return out, s.Err()
}

func splitPostgresKV(line string) (string, string, bool) {
	for i, r := range line {
		if r == ' ' || r == '\t' || r == '=' {
			key := strings.TrimSpace(line[:i])
			value := strings.TrimSpace(line[i+1:])
			value = strings.TrimLeft(value, "\t =")
			value = strings.Trim(value, "'\"")
			if key == "" {
				return "", "", false
			}
			return key, value, true
		}
	}
	return "", "", false
}

func postgresRules(d map[string]string, source string) []scan.Finding {
	out := []scan.Finding{}
	get := func(k string) (string, bool) {
		v, ok := d[strings.ToLower(k)]
		return v, ok
	}
	if v, ok := get("listen_addresses"); ok {
		l := strings.ToLower(v)
		if l == "*" || strings.Contains(l, "0.0.0.0") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  "postgres: listen_addresses = " + v,
				Detail:   "PostgreSQL is listening on all interfaces; verify firewall and pg_hba.conf restrictions. Source: " + source,
			})
		}
	}
	if v, ok := get("ssl"); ok {
		if strings.EqualFold(v, "off") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  "postgres: ssl off",
				Detail:   "Connections are unencrypted on the wire. Source: " + source,
			})
		}
	}
	if v, ok := get("password_encryption"); ok {
		if strings.EqualFold(v, "md5") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "postgres: password_encryption = md5",
				Detail:   "MD5 has been deprecated in favor of scram-sha-256 since PostgreSQL 10. Source: " + source,
			})
		}
	}
	if v, ok := get("log_statement"); ok {
		if strings.EqualFold(v, "all") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityNotice,
				Subject:  "postgres: log_statement = all",
				Detail:   "Logs every statement; expect significant disk and CPU overhead in production. Source: " + source,
			})
		}
	}
	return out
}

// pgHbaEntry captures the columns that drive auth-method rules.
type pgHbaEntry struct {
	Type    string // local, host, hostssl, hostnossl
	Address string // for host*: CIDR
	Method  string // trust, peer, md5, scram-sha-256, ...
	Raw     string
}

func readPgHba(path string) ([]pgHbaEntry, error) {
	f, err := os.Open(path) // #nosec G304 -- well-known sibling path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := []pgHbaEntry{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		e := pgHbaEntry{Type: fields[0], Raw: line}
		// local: type, db, user, method
		// host*: type, db, user, address, method
		switch e.Type {
		case "local":
			if len(fields) >= 4 {
				e.Method = fields[len(fields)-1]
			}
		case "host", "hostssl", "hostnossl":
			if len(fields) >= 5 {
				e.Address = fields[3]
				e.Method = fields[len(fields)-1]
			}
		}
		out = append(out, e)
	}
	return out, s.Err()
}

func pgHbaRules(entries []pgHbaEntry, source string) []scan.Finding {
	out := []scan.Finding{}
	for _, e := range entries {
		if strings.EqualFold(e.Method, "trust") {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Subject:  "postgres: pg_hba.conf uses trust auth: " + e.Raw,
				Detail:   "trust accepts the connection without any password check. Source: " + source,
			})
			continue
		}
		// Plain `host` (not hostssl) on a non-loopback address means
		// network logins without forced TLS.
		if strings.EqualFold(e.Type, "host") && e.Address != "" {
			if !isLoopbackCIDR(e.Address) {
				out = append(out, scan.Finding{
					Severity: scan.SeverityWarning,
					Subject:  "postgres: pg_hba.conf allows non-SSL host login: " + e.Raw,
					Detail:   "Use `hostssl` for non-loopback addresses to require TLS. Source: " + source,
				})
			}
		}
	}
	return out
}

func isLoopbackCIDR(addr string) bool {
	a := strings.ToLower(addr)
	return strings.HasPrefix(a, "127.") || strings.HasPrefix(a, "::1") ||
		a == "localhost" || a == "samehost" || a == "samenet" ||
		strings.HasPrefix(a, "127.0.0.1/") || strings.HasPrefix(a, "::1/")
}
