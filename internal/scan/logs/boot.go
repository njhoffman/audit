package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var bootLogPath = "/var/log/boot.log"

// scanBoot reads /var/log/boot.log if present and non-empty, otherwise
// falls back to `journalctl -b -p err --no-pager` (boot-time errors only).
func scanBoot(ctx context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceBoot}

	if entries, ok, err := readBootFile(opts.MaxLines); err != nil {
		return out, err
	} else if ok {
		out.LinesRead = len(entries)
		out.UsedFallback = bootLogPath
		out.Buckets = TopBuckets(entries, opts.TopBuckets)
		out.Findings = ApplyRules(SourceBoot, entries)
		return out, nil
	}

	entries, err := readJournalBootErrors(ctx, opts.MaxLines)
	if err != nil {
		return out, err
	}
	out.LinesRead = len(entries)
	out.UsedFallback = "journalctl -b -p err"
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceBoot, entries)
	return out, nil
}

// readBootFile returns (entries, fileWasUsable, error). fileWasUsable is
// false when the file is missing or empty so the caller can fall back.
func readBootFile(maxLines int) ([]Entry, bool, error) {
	fi, err := os.Stat(bootLogPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if fi.Size() == 0 {
		return nil, false, nil
	}
	f, err := os.Open(bootLogPath) // #nosec G304 -- well-known log path
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := []Entry{}
	for scanner.Scan() {
		if maxLines > 0 && len(out) >= maxLines {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, Entry{Source: SourceBoot, Message: line, Raw: scanner.Text()})
	}
	return out, true, nil
}

func readJournalBootErrors(ctx context.Context, maxLines int) ([]Entry, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not found: %w", err)
	}
	// #nosec G204 -- fixed argv.
	cmd := exec.CommandContext(ctx, path, "-b", "-p", "err", "--no-pager", "--output=json")
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
		entries[i].Source = SourceBoot
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
