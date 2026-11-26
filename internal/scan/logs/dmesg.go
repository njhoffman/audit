package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var dmesgFile = "/var/log/dmesg"

// scanDmesg prefers the kernel ring buffer via `dmesg`; falls back to
// /var/log/dmesg when the buffer is restricted (kernel.dmesg_restrict=1
// without CAP_SYSLOG).
func scanDmesg(ctx context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceDmesg}

	entries, fallbackUsed, err := readDmesg(ctx, opts.MaxLines)
	if err != nil {
		return out, err
	}
	if fallbackUsed != "" {
		out.UsedFallback = fallbackUsed
	}
	out.LinesRead = len(entries)
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceDmesg, entries)
	return out, nil
}

func readDmesg(ctx context.Context, maxLines int) ([]Entry, string, error) {
	path, err := exec.LookPath("dmesg")
	if err == nil {
		// #nosec G204 -- argv is fixed; path is from LookPath.
		cmd := exec.CommandContext(ctx, path, "--kernel", "--ctime")
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if runErr := cmd.Run(); runErr == nil {
			return parseDmesgLines(stdout.Bytes(), maxLines), "", nil
		} else {
			var ee *exec.ExitError
			if !errors.As(runErr, &ee) {
				return nil, "", fmt.Errorf("dmesg: %w", runErr)
			}
			// Permission denied or kernel.dmesg_restrict — fall through.
		}
	}

	// File fallback. We only treat ENOENT as a non-error (no source).
	f, err := os.Open(dmesgFile) // #nosec G304 -- well-known log path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("open %s: %w", dmesgFile, err)
	}
	defer func() { _ = f.Close() }()

	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, "", err
	}
	return parseDmesgLines(buf.Bytes(), maxLines), dmesgFile, nil
}

// reDmesgPrefix strips two common dmesg line prefixes:
//   - "[Sun Apr 27 03:31:00 2026] " from --ctime output
//   - "[    4.212960] " from raw output
//   - "kernel: " label that some sources prepend
var reDmesgPrefix = regexp.MustCompile(`^\[(?:[A-Za-z]{3} [A-Za-z]{3} +\d+ \d{2}:\d{2}:\d{2} \d{4}|\s*\d+\.\d+)\]\s*(?:kernel:\s*)?`)

func parseDmesgLines(b []byte, maxLines int) []Entry {
	out := []Entry{}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if maxLines > 0 && len(out) >= maxLines {
			break
		}
		line := scanner.Text()
		msg := reDmesgPrefix.ReplaceAllString(line, "")
		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}
		out = append(out, Entry{Source: SourceDmesg, Message: msg, Raw: line})
	}
	return out
}
