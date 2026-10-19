package main

import (
	"strings"
	"testing"
	"time"
)

func TestNext(t *testing.T) {
	v := Version{0, 1, 0}
	for _, c := range []struct {
		level      string
		allowMajor bool
		want       string
	}{
		{Patch, false, "0.1.1"}, {Minor, false, "0.2.0"}, {Major, false, "0.2.0"}, {Major, true, "1.0.0"},
	} {
		got, err := v.Next(c.level, c.allowMajor)
		if err != nil || got.String() != c.want {
			t.Errorf("%s (allow %v) = %s %v, want %s", c.level, c.allowMajor, got, err, c.want)
		}
	}
	if got, _ := (Version{1, 4, 2}).Next(Major, false); got.String() != "2.0.0" {
		t.Errorf("after 1.0 a major bump is major: %s", got)
	}
	if _, err := v.Next("huge", false); err == nil {
		t.Error("unknown level")
	}
}

func TestParseTag(t *testing.T) {
	if v, err := ParseTag("v0.12.3\n"); err != nil || v != (Version{0, 12, 3}) {
		t.Errorf("%v %v", v, err)
	}
	for _, bad := range []string{"0.1.0", "v1.2", "v1.2.3-rc1"} {
		if _, err := ParseTag(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

const log = `# Changelog

## [Unreleased]

### Fixed

- a bug

## [0.1.0] - 2026-04-27

### Added

- first
`

func TestLevel(t *testing.T) {
	body, _, _, err := Unreleased(log)
	if err != nil || body != "### Fixed\n\n- a bug" {
		t.Fatalf("%q %v", body, err)
	}
	for in, want := range map[string]string{
		"### Fixed\n- x":                     Patch,
		"### Added\n- x\n### Fixed\n- y":     Minor,
		"### Changed\n- x":                   Minor,
		"### Added\n- x\n### Removed\n- y":   Major,
		"### Changed\n- BREAKING: renamed x": Major,
	} {
		if got, err := Level(in); err != nil || got != want {
			t.Errorf("Level(%q) = %s %v, want %s", in, got, err, want)
		}
	}
	if _, err := Level("  \n"); err == nil {
		t.Error("an empty section is not releasable")
	}
	if _, _, _, err := Unreleased("# Changelog\n"); err == nil {
		t.Error("no Unreleased section")
	}
}

func TestRewrite(t *testing.T) {
	out, err := Rewrite(log, Version{0, 1, 1}, time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "## [Unreleased]\n\n## [0.1.1] - 2026-10-19\n\n### Fixed\n\n- a bug\n\n## [0.1.0]") {
		t.Errorf("rewrite:\n%s", out)
	}
	body, _, _, _ := Unreleased(out)
	if body != "" {
		t.Errorf("the new Unreleased section is empty: %q", body)
	}
}
