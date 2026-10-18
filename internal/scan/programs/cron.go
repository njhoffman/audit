package programs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/scan"
)

const (
	cronCrontab    = "/etc/crontab"
	cronAnacrontab = "/etc/anacrontab"
	cronDir        = "/etc/cron.d"
)

func analyzeCron(_ context.Context) ProgramResult {
	out := ProgramResult{Program: ProgramCron, Source: cronCrontab}

	files, err := collectCronFiles()
	if err != nil {
		out.Skipped = true
		out.Reason = err.Error()
		return out
	}
	if len(files) == 0 {
		out.Skipped = true
		out.Reason = "no crontab files found"
		return out
	}

	for _, p := range files {
		fi, err := os.Stat(p)
		if err != nil {
			out.Notes = append(out.Notes, "stat "+p+": "+err.Error())
			continue
		}
		out.Findings = append(out.Findings, cronFilePermFindings(p, fi)...)
		findings, err := cronContentFindings(p)
		if err != nil {
			out.Notes = append(out.Notes, "read "+p+": "+err.Error())
			continue
		}
		out.Findings = append(out.Findings, findings...)
	}
	return out
}

func collectCronFiles() ([]string, error) {
	files := []string{}
	for _, p := range []string{cronCrontab, cronAnacrontab} {
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if entries, err := os.ReadDir(cronDir); err == nil {
		extras := []string{}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			extras = append(extras, filepath.Join(cronDir, e.Name()))
		}
		sort.Strings(extras)
		files = append(files, extras...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return files, nil
}

func cronFilePermFindings(path string, fi fs.FileInfo) []scan.Finding {
	out := []scan.Finding{}
	mode := fi.Mode().Perm()
	// World-writable cron files are direct privilege escalation.
	if mode&0o002 != 0 {
		out = append(out, scan.Finding{
			Severity: scan.SeverityCritical,
			Subject:  "cron: world-writable " + path,
			Detail:   fmt.Sprintf("mode %#o. Anyone", mode) + " on the system can append commands run as root.",
		})
	}
	// Group-writable when not owned by root group is suspicious.
	if mode&0o020 != 0 {
		out = append(out, scan.Finding{
			Severity: scan.SeverityWarning,
			Subject:  "cron: group-writable " + path,
			Detail:   fmt.Sprintf("mode %#o. Group write", mode) + " on a cron file can allow privilege escalation through group-membership exploits.",
		})
	}
	return out
}

var reCronHTTPCurl = regexp.MustCompile(`\b(?:curl|wget|fetch)\b[^\n]*\bhttp://`)

func cronContentFindings(path string) ([]scan.Finding, error) {
	f, err := os.Open(path) // #nosec G304 -- caller iterates a fixed root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := []scan.Finding{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if reCronHTTPCurl.MatchString(line) {
			out = append(out, scan.Finding{
				Severity: scan.SeverityWarning,
				Subject:  "cron: insecure HTTP fetch in " + path,
				Detail:   "Cron job downloads via plain http://; switch to https:// to prevent MITM. Line: " + strings.TrimSpace(line),
			})
		}
	}
	return out, s.Err()
}
