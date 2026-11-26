package logs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// miscRoot is the directory walked by the misc source.
var miscRoot = "/var/log"

// miscMaxFileBytes caps the per-file read so a single huge log can't blow
// up the digest. Files larger than this are still touched (we read up to
// the cap) but a finding signals truncation.
const miscMaxFileBytes int64 = 5 * 1024 * 1024

// miscSkipExtensions covers compressed archives and binary journals that
// would not parse as text.
var miscSkipExtensions = map[string]bool{
	".gz": true, ".bz2": true, ".xz": true, ".zst": true,
	".lz4": true, ".zip": true, ".7z": true,
	".journal": true, ".journal~": true,
}

// miscCoveredBasenames lists files that other sources already cover, so
// the misc walk does not double-count them.
var miscCoveredBasenames = map[string]bool{
	"auth.log": true,
	"boot.log": true,
	"dmesg":    true,
	"kern.log": true,
}

// miscSkipDirs are subdirectories we don't recurse into. /var/log/journal
// is binary journald data.
var miscSkipDirs = map[string]bool{
	"journal": true,
	"private": true, // 0700 root:root, never useful
}

func scanMisc(_ context.Context, opts Options) (SourceResult, error) {
	out := SourceResult{Source: SourceMisc}

	entries, stats, err := walkMisc(miscRoot, opts.MaxLines)
	if err != nil {
		return out, err
	}
	out.LinesRead = len(entries)
	out.Buckets = TopBuckets(entries, opts.TopBuckets)
	out.Findings = ApplyRules(SourceMisc, entries)
	if stats.skipped > 0 || stats.permDenied > 0 || stats.truncated > 0 {
		// surface the walk shape so the user knows what was inspected
		out.UsedFallback = stats.summary()
	}
	return out, nil
}

type miscStats struct {
	read       int
	skipped    int
	permDenied int
	truncated  int
}

func (m miscStats) summary() string {
	return "/var/log walk: " +
		"read=" + itoa(m.read) +
		" skipped=" + itoa(m.skipped) +
		" perm_denied=" + itoa(m.permDenied) +
		" truncated=" + itoa(m.truncated)
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func walkMisc(root string, maxLines int) ([]Entry, miscStats, error) {
	stats := miscStats{}
	all := []Entry{}

	// maxLines is the global cap across the whole walk. Per-file we read
	// at most the remaining budget so a single chatty file can't starve
	// the rest, but more importantly the walk terminates quickly on
	// /var/log directories with many large files.
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if maxLines > 0 && len(all) >= maxLines {
			return filepath.SkipAll
		}
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				stats.permDenied++
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return err
		}
		if path == root {
			return nil
		}
		if d.IsDir() {
			if miscSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			stats.skipped++
			return nil
		}
		if miscCoveredBasenames[d.Name()] {
			stats.skipped++
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if miscSkipExtensions[ext] {
			stats.skipped++
			return nil
		}
		// Skip files with rotated extensions like .log.1, .log.2 — they
		// duplicate already-included content.
		if isRotated(d.Name()) {
			stats.skipped++
			return nil
		}

		// Per-file budget: whatever is left of the global cap, or the
		// configured maxLines if no global cap. Capping at the same
		// value works either way.
		perFileBudget := maxLines
		if maxLines > 0 {
			perFileBudget = maxLines - len(all)
		}
		entries, truncated, err := readMiscFile(path, perFileBudget)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				stats.permDenied++
				return nil
			}
			stats.skipped++
			return nil
		}
		stats.read++
		if truncated {
			stats.truncated++
		}
		all = append(all, entries...)
		return nil
	})
	return all, stats, err
}

// isRotated returns true for filenames like foo.log.1, foo.log.2, etc.
// — a numeric tail suffix on a logfile basename.
func isRotated(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return false
	}
	tail := name[dot+1:]
	if tail == "" {
		return false
	}
	for _, r := range tail {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func readMiscFile(path string, maxLines int) ([]Entry, bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	truncated := fi.Size() > miscMaxFileBytes

	f, err := os.Open(path) // #nosec G304 -- caller iterates a fixed root
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	// Cap by bytes via io.LimitReader plus by lines via readSyslogFile's
	// internal counter. Using both bounds keeps memory predictable on
	// pathological logs.
	entries := readSyslogFile(io.LimitReader(f, miscMaxFileBytes), SourceMisc, maxLines)
	return entries, truncated, nil
}
