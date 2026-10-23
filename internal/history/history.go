// Package history checks shell history without retaining command text.
package history

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/njhoffman/audit/internal/finding"
)

// Options selects files, literal patterns and resource limits.
type Options struct {
	Files    []string
	Patterns []string
	MaxLines int
	MaxBytes int64
}

type entry struct {
	text string
	line int
}

var extended = regexp.MustCompile(`^: [0-9]+:[0-9]+;`)
var timestamp = regexp.MustCompile(`^#[0-9]+$`)

func formatOf(path string, body []byte) string {
	if strings.Contains(filepath.Base(path), "fish") || strings.HasPrefix(string(body), "- cmd: ") {
		return "fish"
	}
	if strings.Contains(filepath.Base(path), "zsh") || extended.Match(body) {
		return "zsh"
	}
	return "bash"
}

// parse recognizes zsh extended/escaped histories, timestamped bash histories
// and fish's command records. Plain histories use one entry per physical line;
// without timestamps bash's literal multiline boundaries cannot be recovered.
func parse(body, format string) []entry {
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	timed := false
	if format == "bash" {
		for _, line := range lines {
			if timestamp.MatchString(line) {
				timed = true
				break
			}
		}
	}
	var out []entry
	var current strings.Builder
	start := 0
	flush := func() {
		if start != 0 {
			out = append(out, entry{current.String(), start})
		}
		current.Reset()
		start = 0
	}
	continuation := false
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if format == "fish" {
			if text, ok := strings.CutPrefix(line, "- cmd: "); ok {
				// Fish escapes backslashes and newlines, unlike YAML strings.
				var b strings.Builder
				for j := 0; j < len(text); j++ {
					if text[j] == '\\' && j+1 < len(text) {
						if text[j+1] == 'n' {
							b.WriteByte('\n')
							j++
							continue
						}
						if text[j+1] == '\\' {
							b.WriteByte('\\')
							j++
							continue
						}
					}
					b.WriteByte(text[j])
				}
				out = append(out, entry{b.String(), i + 1})
			}
			continue
		}
		if timed && timestamp.MatchString(line) {
			flush()
			continue
		}
		if timed && start != 0 {
			current.WriteByte('\n')
			current.WriteString(line)
			continue
		}
		if format == "zsh" {
			if !continuation {
				line = extended.ReplaceAllString(line, "")
			}
			// zsh stores an embedded newline as a backslash plus a newline.
			next := strings.HasSuffix(line, "\\")
			if next {
				line = strings.TrimSuffix(line, "\\")
			}
			if continuation && start != 0 {
				current.WriteByte('\n')
			} else if line != "" || next {
				start = i + 1
			}
			current.WriteString(line)
			if !next {
				flush()
			}
			continuation = next
			continue
		}
		if line != "" {
			start = i + 1
			current.WriteString(line)
			if !timed {
				flush()
			}
		}
	}
	flush()
	return out
}

// Scan returns findings and counts only. Commands and configured pattern values
// never enter findings, errors, the store, exports, or AI prompts.
func Scan(ctx context.Context, o Options) ([]finding.Finding, int, int, []string, error) {
	var fs []finding.Finding
	var errs []string
	files, entries := 0, 0
	seen := map[string]bool{}
	for _, path := range o.Files {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, nil, err
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			errs = append(errs, fmt.Sprintf("%s: cannot read a regular history file", path))
			continue
		}
		f, err := os.Open(path) // #nosec G304 -- configured history files
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		info, err = f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			errs = append(errs, fmt.Sprintf("%s: cannot read a regular history file", path))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(f, o.MaxBytes+1))
		_ = f.Close()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		if int64(len(body)) > o.MaxBytes {
			errs = append(errs, fmt.Sprintf("%s: exceeds shell_history.max_mb", path))
			continue
		}
		es := parse(string(body), formatOf(path, body))
		files++
		entries += len(es)
		byText := map[string]int{}
		var duplicates, large []int
		matches := make([][]int, len(o.Patterns))
		for _, e := range es {
			if err := ctx.Err(); err != nil {
				return nil, 0, 0, nil, err
			}
			text := strings.TrimSpace(e.text)
			if text == "" {
				continue
			}
			byText[text]++
			if byText[text] > 1 {
				duplicates = append(duplicates, e.line)
			}
			if strings.Count(e.text, "\n")+1 >= o.MaxLines {
				large = append(large, e.line)
			}
			for i, p := range o.Patterns {
				if p != "" && strings.Contains(e.text, p) {
					matches[i] = append(matches[i], e.line)
				}
			}
		}
		add := func(check, subject, message string, severity finding.Severity, lines []int) {
			if len(lines) == 0 {
				return
			}
			details := make([]string, 0, min(len(lines), 100))
			for _, line := range lines[:min(len(lines), 100)] {
				details = append(details, fmt.Sprintf("%s:%d", path, line))
			}
			fs = append(fs, finding.Finding{Command: "history", Check: check, Subject: subject, Kind: finding.Issue, Severity: severity,
				Message: fmt.Sprintf("%d %s", len(lines), message), Details: details,
				Hint: "Review these entries locally in your history file; command text is omitted. At most 100 locations are listed."})
		}
		add("history.duplicates", path, "repeated history entries", finding.Notice, duplicates)
		add("history.multiline", path, fmt.Sprintf("history entries with at least %d lines", o.MaxLines), finding.Notice, large)
		for i, lines := range matches {
			add("history.pattern", fmt.Sprintf("%s:pattern-%d", path, i+1), fmt.Sprintf("history entries match shell_history.patterns item %d", i+1), finding.Warning, lines)
		}
	}
	finding.Sort(fs)
	return fs, files, entries, errs, nil
}
