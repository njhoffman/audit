package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var kernLogPath = "/var/log/kern.log"

func scanKern(ctx context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceKern}

	if entries, ok, err := readSyslogFileFromPath(kernLogPath, SourceKern, opts.MaxLines); err != nil {
		return out, err
	} else if ok {
		out.LinesRead = len(entries)
		out.UsedFallback = kernLogPath
		out.Buckets = TopBuckets(entries, opts.TopBuckets)
		out.Findings = ApplyRules(SourceKern, entries)
		return out, nil
	}

	entries, err := readJournalKern(ctx, opts.MaxLines)
	if err != nil {
		return out, err
	}
	out.LinesRead = len(entries)
	out.UsedFallback = "journalctl -k"
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceKern, entries)
	return out, nil
}

// readJournalKern queries kernel-transport messages from the current boot.
// `journalctl -k` is the kernel-only equivalent of `dmesg`, served by the
// journal, so it works without CAP_SYSLOG.
func readJournalKern(ctx context.Context, maxLines int) ([]Entry, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not found: %w", err)
	}
	// #nosec G204 -- fixed argv.
	cmd := exec.CommandContext(ctx, path, "-k", "--no-pager", "--output=json")
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
		entries[i].Source = SourceKern
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
