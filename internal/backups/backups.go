// Package backups checks that the workstation is backed up: when each
// backup source last finished, whether it runs on its own, and whether the
// paths that matter are covered.
package backups

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// Command is the audit command name.
const Command = "backups"

// Source is a configured backup: Command prints the time the last backup
// finished (RFC 3339, a date and time, or Unix seconds; empty output means
// never), and Covers are the paths it backs up.
type Source struct {
	Name    string
	Command string
	Covers  []string
}

// Options configure a scan.
type Options struct {
	Env     *exec.Env
	Sources []Source
	// Paths should each be covered by some source.
	Paths  []string
	MaxAge time.Duration
	// DejaDup reads Deja Dup's settings when its command is installed.
	DejaDup bool
	Now     time.Time
}

// Backup is what the scan found about one source.
type Backup struct {
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Last      time.Time `json:"last,omitzero"`
	Scheduled *bool     `json:"scheduled,omitempty"`
	Covers    []string  `json:"covers,omitempty"`
	Excludes  []string  `json:"excludes,omitempty"`
	Backend   string    `json:"backend,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Data is what a backups run stores.
type Data struct {
	Backups []Backup `json:"backups"`
	Paths   []string `json:"paths"`
}

// Result is a finished scan.
type Result struct {
	Findings []finding.Finding
	Stats    []run.Stat
	Data     Data
}

const timeout = 30 * time.Second

// Scan collects every source and checks it.
func Scan(ctx context.Context, o Options) (*Result, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	var bs []Backup
	if o.DejaDup && o.Env.Which("deja-dup") != "" {
		bs = append(bs, dejaDup(ctx, o.Env))
	}
	for _, s := range o.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bs = append(bs, commandSource(ctx, o.Env, s, now))
	}
	paths := make([]string, len(o.Paths))
	for i, p := range o.Paths {
		paths[i] = o.Env.Expand(p)
	}
	res := &Result{Data: Data{Backups: bs, Paths: paths}}
	res.Findings = Analyze(bs, paths, o.MaxAge, now)
	res.Stats = stats(bs, now)
	return res, nil
}

// gsetting reads one org.gnome.DejaDup key as gsettings prints it.
func gsetting(ctx context.Context, env *exec.Env, key string) (string, error) {
	r := env.Run(ctx, "gsettings", []string{"get", "org.gnome.DejaDup", key}, exec.Options{Timeout: timeout})
	if !r.OK() {
		return "", fmt.Errorf("gsettings get org.gnome.DejaDup %s: %s", key, strings.TrimSpace(r.Stderr))
	}
	return strings.TrimSpace(r.Stdout), nil
}

// gvariantStrings reads a GVariant string array (['$HOME', '/srv']); a
// GVariant string ('x') is a one-element list.
func gvariantStrings(s string) []string {
	s = strings.TrimSpace(strings.TrimPrefix(s, "@as"))
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 2 && (part[0] == '\'' || part[0] == '"') {
			part = part[1 : len(part)-1]
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// dejaDupPath expands Deja Dup's symbolic folders.
func dejaDupPath(env *exec.Env, p string) string {
	switch p {
	case "$HOME":
		return env.Home
	case "$TRASH":
		return filepath.Join(env.XDG("XDG_DATA_HOME"), "Trash")
	case "$DOWNLOAD":
		return filepath.Join(env.Home, "Downloads")
	}
	return env.Expand(p)
}

func dejaDup(ctx context.Context, env *exec.Env) Backup {
	b := Backup{Name: "deja-dup", Kind: "deja-dup"}
	last, err := gsetting(ctx, env, "last-backup")
	if err != nil {
		b.Error = err.Error()
		return b
	}
	if v := strings.Trim(last, "'\""); v != "" {
		b.Last = parseTime(v)
	}
	if p, err := gsetting(ctx, env, "periodic"); err == nil {
		on := p == "true"
		b.Scheduled = &on
	}
	if v, err := gsetting(ctx, env, "backend"); err == nil {
		b.Backend = strings.Trim(v, "'\"")
	}
	if v, err := gsetting(ctx, env, "include-list"); err == nil {
		for _, p := range gvariantStrings(v) {
			b.Covers = append(b.Covers, dejaDupPath(env, p))
		}
	}
	if v, err := gsetting(ctx, env, "exclude-list"); err == nil {
		for _, p := range gvariantStrings(v) {
			b.Excludes = append(b.Excludes, dejaDupPath(env, p))
		}
	}
	return b
}

// commandSource runs a configured source's command through sh, so it can
// be a pipeline (restic snapshots --json | jq ...).
func commandSource(ctx context.Context, env *exec.Env, s Source, now time.Time) Backup {
	b := Backup{Name: s.Name, Kind: "command"}
	for _, c := range s.Covers {
		b.Covers = append(b.Covers, env.Expand(c))
	}
	r := env.Run(ctx, "sh", []string{"-c", s.Command}, exec.Options{Timeout: 2 * time.Minute})
	if !r.OK() {
		b.Error = fmt.Sprintf("exit %d: %s", r.Code, lastLine(r.Stderr+"\n"+r.Stdout))
		return b
	}
	out := strings.TrimSpace(r.Stdout)
	if out == "" {
		return b
	}
	if b.Last = parseTime(lastLine(out)); b.Last.IsZero() {
		b.Error = fmt.Sprintf("could not read a time from %q", lastLine(out))
	} else if b.Last.After(now.Add(time.Hour)) {
		b.Error = fmt.Sprintf("reported a time in the future (%s)", b.Last.Format(time.RFC3339))
	}
	return b
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// parseTime reads RFC 3339 (with or without fractions), "2006-01-02
// 15:04:05", a JSON string, or Unix seconds.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	var quoted string
	if json.Unmarshal([]byte(s), &quoted) == nil {
		s = quoted
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// covered reports whether path is inside an included path of b and not
// inside one of its excludes.
func (b Backup) covered(path string) bool {
	inside := func(p, root string) bool {
		rel, err := filepath.Rel(root, p)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
	}
	for _, x := range b.Excludes {
		if inside(path, x) {
			return false
		}
	}
	for _, c := range b.Covers {
		if inside(path, c) {
			return true
		}
	}
	return false
}

// Checks.
const (
	CheckNone        = "backups.none"
	CheckNever       = "backups.never"
	CheckStale       = "backups.stale"
	CheckUnscheduled = "backups.unscheduled"
	CheckUncovered   = "backups.uncovered"
	CheckError       = "backups.error"
)

// Analyze checks the sources against the paths and the age limit.
func Analyze(bs []Backup, paths []string, maxAge time.Duration, now time.Time) []finding.Finding {
	var fs []finding.Finding
	add := func(check, subject string, sev finding.Severity, msg, hint string) {
		fs = append(fs, finding.Finding{Command: Command, Check: check, Subject: subject, Kind: finding.Issue, Severity: sev,
			Message: msg, Hint: hint})
	}
	if len(bs) == 0 {
		add(CheckNone, "backups", finding.Warning, "no backup was found: Deja Dup is not installed and backups.sources is empty",
			"Set up a backup (Deja Dup, restic, borg), and add a non-Deja Dup one to backups.sources with a command that prints its last backup time.")
	}
	for _, b := range bs {
		switch {
		case b.Error != "":
			add(CheckError, b.Name, finding.Error, b.Name+": "+b.Error, "Run the source's command by hand to see why it fails.")
		case b.Last.IsZero():
			add(CheckNever, b.Name, finding.Warning, b.Name+" has never completed a backup",
				"Run a first backup and check that it finishes.")
		case maxAge > 0 && now.Sub(b.Last) > maxAge:
			sev := finding.Warning
			if now.Sub(b.Last) > 4*maxAge {
				sev = finding.Error
			}
			add(CheckStale, b.Name, sev, fmt.Sprintf("%s last finished a backup on %s, %s ago (backups.max_age %s)", b.Name,
				b.Last.Local().Format(time.DateOnly), run.HumanAge(now.Sub(b.Last)), run.HumanAge(maxAge)),
				"Check why the scheduled backup stopped, then run one.")
		}
		if b.Scheduled != nil && !*b.Scheduled {
			add(CheckUnscheduled, b.Name, finding.Notice, b.Name+" does not back up automatically",
				"Turn on automatic backups (Deja Dup: Preferences, Back Up Automatically).")
		}
	}
	for _, p := range paths {
		ok := false
		for _, b := range bs {
			if b.Error == "" && b.covered(p) {
				ok = true
			}
		}
		if !ok && len(bs) > 0 {
			add(CheckUncovered, p, finding.Warning, p+" is in backups.paths but no backup source includes it",
				"Add it to a backup's folders (or to the source's covers in backups.sources).")
		}
	}
	finding.Sort(fs)
	return fs
}

func stats(bs []Backup, now time.Time) []run.Stat {
	out := []run.Stat{{Name: "sources", Value: fmt.Sprint(len(bs))}}
	for _, b := range bs {
		st := run.Stat{Group: "backups", Name: b.Name}
		switch {
		case b.Error != "":
			st.Value = "error"
		case b.Last.IsZero():
			st.Value = "never"
		default:
			st.Value = run.HumanAge(now.Sub(b.Last)) + " ago"
		}
		var notes []string
		if b.Backend != "" {
			notes = append(notes, "to "+b.Backend)
		}
		if b.Scheduled != nil {
			notes = append(notes, map[bool]string{true: "automatic", false: "manual only"}[*b.Scheduled])
		}
		if len(b.Covers) > 0 {
			notes = append(notes, "covers "+strings.Join(b.Covers, ", "))
		}
		st.Note = strings.Join(notes, "; ")
		out = append(out, st)
	}
	return out
}
