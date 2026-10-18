package users

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

// Options reserved for future tuning; scan currently has no knobs.
type Options struct{}

func DefaultOptions() Options { return Options{} }

// Scan reads /etc/passwd, /etc/group, and (best-effort) /etc/shadow and
// returns a scan.Result with a digest plus derived findings.
func Scan(_ context.Context, _ Options) (*scan.Result, error) {
	started := time.Now()

	pwd, err := readPasswd()
	if err != nil {
		return nil, fmt.Errorf("read passwd: %w", err)
	}
	grp, err := readGroup()
	if err != nil {
		return nil, fmt.Errorf("read group: %w", err)
	}

	shd, shadowReadable, shadowErr := readShadow()
	stats := statFiles()

	findings := DeriveFindings(pwd, grp, shd, stats, shadowReadable)

	uidsByRange := map[string]int{"system": 0, "regular": 0, "root": 0}
	for _, e := range pwd {
		switch {
		case e.UID == 0:
			uidsByRange["root"]++
		case e.UID <= SystemAccountUIDMax:
			uidsByRange["system"]++
		default:
			uidsByRange["regular"]++
		}
	}

	res := &scan.Result{
		Kind:       "users",
		StartedAt:  started,
		FinishedAt: time.Now(),
		Summary: map[string]any{
			"users_total":     len(pwd),
			"groups_total":    len(grp),
			"shadow_readable": shadowReadable,
			"users_by_range":  uidsByRange,
			"shadow_skip_reason": func() string {
				if shadowErr != nil {
					return shadowErr.Error()
				}
				return ""
			}(),
		},
		Findings: findings,
	}
	return res, nil
}

func readPasswd() ([]PasswdEntry, error) {
	f, err := os.Open(PathPasswd) // #nosec G304 -- well-known system file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParsePasswd(f), nil
}

func readGroup() ([]GroupEntry, error) {
	f, err := os.Open(PathGroup) // #nosec G304 -- well-known system file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseGroup(f), nil
}

// readShadow returns (entries, readable, errIfReadFailed). When shadow is
// unreadable due to permissions, readable=false and err is the non-nil
// permission error so we can surface why.
func readShadow() ([]ShadowEntry, bool, error) {
	f, err := os.Open(PathShadow) // #nosec G304 -- well-known system file
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	return ParseShadow(f), true, nil
}

func statFiles() map[string]os.FileInfo {
	out := map[string]os.FileInfo{}
	for _, p := range []string{PathPasswd, PathGroup, PathShadow} {
		fi, err := os.Stat(p)
		if err == nil {
			out[p] = fi
		}
	}
	return out
}
