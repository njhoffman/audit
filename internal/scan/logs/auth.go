package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var authLogPath = "/var/log/auth.log"

func scanAuth(ctx context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceAuth}

	if entries, ok, err := readSyslogFileFromPath(authLogPath, SourceAuth, opts.MaxLines); err != nil {
		return out, err
	} else if ok {
		out.LinesRead = len(entries)
		out.UsedFallback = authLogPath
		out.Buckets = TopBuckets(entries, opts.TopBuckets)
		out.Findings = ApplyRules(SourceAuth, entries)
		return out, nil
	}

	entries, err := readJournalAuth(ctx, opts.MaxLines)
	if err != nil {
		return out, err
	}
	out.LinesRead = len(entries)
	out.UsedFallback = "journalctl SYSLOG_FACILITY=4 + 10"
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceAuth, entries)
	return out, nil
}

// readJournalAuth queries the auth and authpriv syslog facilities (4 and
// 10). Multiple SYSLOG_FACILITY arguments OR together in journalctl, so a
// single invocation covers both.
func readJournalAuth(ctx context.Context, maxLines int) ([]Entry, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not found: %w", err)
	}
	// #nosec G204 -- fixed argv.
	cmd := exec.CommandContext(ctx, path,
		"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10",
		"-p", "info", "--no-pager", "--output=json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	entries := parseJournalJSON(stdout, maxLines)
	for i := range entries {
		entries[i].Source = SourceAuth
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return entries, fmt.Errorf("journalctl exited %d: %s",
				ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return entries, err
	}
	return entries, nil
}

// readSyslogFileFromPath returns (entries, fileWasUsable, error). Same
// semantics as boot.go's readBootFile: fileWasUsable=false means the file
// was missing or empty so the caller should fall back.
func readSyslogFileFromPath(path string, src Source, maxLines int) ([]Entry, bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if fi.Size() == 0 {
		return nil, false, nil
	}
	f, err := os.Open(path) // #nosec G304 -- well-known log path
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	return readSyslogFile(f, src, maxLines), true, nil
}
