package services

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func enriched(scope Scope, name, load, active string, props Properties) EnrichedUnit {
	return EnrichedUnit{
		Scope: scope,
		Unit:  Unit{Name: name, Load: load, Active: active},
		Props: props,
	}
}

func TestDeriveFindings_Failed(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "broken.service", "loaded", "failed", Properties{
			ActiveState: "failed", SubState: "failed", Result: "exit-code",
			FragmentPath: "/usr/lib/systemd/system/broken.service",
		}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Severity != scan.SeverityCritical {
		t.Errorf("system-failed should be critical, got %q", out[0].Severity)
	}
	if !strings.Contains(out[0].Subject, "broken.service") {
		t.Errorf("subject: %q", out[0].Subject)
	}
}

func TestDeriveFindings_FailedUserIsErrorNotCritical(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeUser, "u.service", "loaded", "failed", Properties{
			FragmentPath: "/home/u/.config/systemd/user/u.service",
		}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) != 1 || out[0].Severity != scan.SeverityError {
		t.Errorf("user-failed should be error, got %+v", out)
	}
}

func TestDeriveFindings_Masked(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "m.service", "masked", "inactive", Properties{}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) != 1 || out[0].Severity != scan.SeverityWarning {
		t.Errorf("masked should warn, got %+v", out)
	}
}

func TestDeriveFindings_LoadError_AlwaysFiresOnError(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "x.service", "error", "inactive", Properties{}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) != 1 || out[0].Severity != scan.SeverityError {
		t.Errorf("load=error inactive: expected one error finding, got %+v", out)
	}
}

func TestDeriveFindings_LoadNotFound_OnlyWhenEnabledOrActive(t *testing.T) {
	cases := []struct {
		name      string
		active    string
		unitState string
		wantFire  bool
	}{
		{"inactive-and-not-enabled", "inactive", "", false},
		{"enabled-but-inactive", "inactive", "enabled", true},
		{"active", "active", "", true},
		{"activating", "activating", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			units := []EnrichedUnit{
				enriched(ScopeSystem, "x.service", "not-found", tc.active,
					Properties{UnitFileState: tc.unitState}),
			}
			out := DeriveFindings(units, FindingOptions{})
			fired := false
			for _, f := range out {
				if f.Check == "load_error" && strings.Contains(f.Detail, "load=not-found") {
					fired = true
					break
				}
			}
			if fired != tc.wantFire {
				t.Errorf("got fired=%v want %v (out=%+v)", fired, tc.wantFire, out)
			}
		})
	}
}

func TestDeriveFindings_MissingFragment(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "ghost.service", "loaded", "active", Properties{
			FragmentPath: "",
		}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) != 1 || out[0].Check != "missing_fragment" || out[0].Subject != "system/ghost.service" {
		t.Errorf("missing fragment: %+v", out)
	}
}

func TestDeriveFindings_HighRestart(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "flap.service", "loaded", "active", Properties{
			FragmentPath: "/x", NRestarts: 7, Restart: "always",
		}),
	}
	out := DeriveFindings(units, FindingOptions{HighRestartCount: 5})
	if len(out) != 1 || out[0].Check != "restarts" || !strings.Contains(out[0].Detail, "restarted 7") {
		t.Errorf("high restart: %+v", out)
	}
}

func TestDeriveFindings_HighRestartDisabledAtZero(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "x.service", "loaded", "active", Properties{
			FragmentPath: "/x", NRestarts: 100,
		}),
	}
	out := DeriveFindings(units, FindingOptions{HighRestartCount: 0})
	for _, f := range out {
		if f.Check == "restarts" {
			t.Errorf("expected no high-restart finding, got %+v", f)
		}
	}
}

func TestDeriveFindings_SortsBySeverityDesc(t *testing.T) {
	units := []EnrichedUnit{
		enriched(ScopeSystem, "a.service", "masked", "inactive", Properties{}),
		enriched(ScopeSystem, "b.service", "loaded", "failed", Properties{
			ActiveState: "failed", FragmentPath: "/usr/lib/systemd/system/b.service",
		}),
	}
	out := DeriveFindings(units, FindingOptions{})
	if len(out) < 2 {
		t.Fatalf("want >=2 findings, got %d", len(out))
	}
	if severityRank(out[0].Severity) < severityRank(out[1].Severity) {
		t.Errorf("findings not sorted by severity desc: %+v", out)
	}
}
