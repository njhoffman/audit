package services

import (
	"fmt"
	"os"
	"sort"

	"github.com/njhoffman/audit/internal/scan"
)

// EnrichedUnit pairs a list-units row with its detailed properties.
type EnrichedUnit struct {
	Scope Scope
	Unit
	Props Properties
}

// FindingOptions tunes which checks fire.
type FindingOptions struct {
	CheckUnitFilePerms bool
	HighRestartCount   int // flag NRestarts >= this; 0 disables
}

func DefaultFindingOptions() FindingOptions {
	return FindingOptions{
		CheckUnitFilePerms: true,
		HighRestartCount:   5,
	}
}

// DeriveFindings walks the enriched units and produces findings for failed,
// masked, errored-load, missing-fragment, and (optionally) world-writable
// unit-file conditions.
func DeriveFindings(units []EnrichedUnit, opts FindingOptions) []scan.Finding {
	out := []scan.Finding{}

	failed := []EnrichedUnit{}
	masked := []EnrichedUnit{}
	loadErr := []EnrichedUnit{}
	missingFrag := []EnrichedUnit{}
	highRestart := []EnrichedUnit{}

	for _, u := range units {
		if u.Active == "failed" {
			failed = append(failed, u)
		}
		switch u.Load {
		case "masked":
			masked = append(masked, u)
		case "error":
			// systemd hit a parse/load error — always actionable.
			loadErr = append(loadErr, u)
		case "not-found":
			// not-found is only signal when the unit is enabled, active,
			// or activating; otherwise it's a leftover dependency reference
			// from another unit and not a real misconfiguration.
			if u.Props.UnitFileState == "enabled" || (u.Active != "" && u.Active != "inactive") {
				loadErr = append(loadErr, u)
			}
		}
		// Missing FragmentPath on a non-masked, non-template unit means the
		// unit file vanished while the unit is still loaded — a strong
		// "configuration drift" signal.
		if u.Load == "loaded" && u.Props.FragmentPath == "" {
			missingFrag = append(missingFrag, u)
		}
		if opts.HighRestartCount > 0 && u.Props.NRestarts >= opts.HighRestartCount {
			highRestart = append(highRestart, u)
		}
	}

	for _, u := range failed {
		sev := scan.SeverityCritical
		if u.Scope == ScopeUser {
			sev = scan.SeverityError
		}
		out = append(out, scan.Finding{
			Severity: sev,
			Check:    "failed",
			Subject:  unitSubject(u),
			Detail: fmt.Sprintf("failed: ActiveState=%s SubState=%s Result=%s Description=%q",
				u.Props.ActiveState, u.Props.SubState, u.Props.Result, u.Description),
		})
	}
	for _, u := range masked {
		out = append(out, scan.Finding{
			Severity: scan.SeverityWarning,
			Check:    "masked",
			Subject:  unitSubject(u),
			Detail:   "Masked units cannot be started even if other units depend on them.",
		})
	}
	for _, u := range loadErr {
		out = append(out, scan.Finding{
			Severity: scan.SeverityError,
			Check:    "load_error",
			Subject:  unitSubject(u),
			Detail:   fmt.Sprintf("load=%s Active=%s Sub=%s Description=%q", u.Load, u.Active, u.Sub, u.Description),
		})
	}
	for _, u := range missingFrag {
		out = append(out, scan.Finding{
			Severity: scan.SeverityWarning,
			Check:    "missing_fragment",
			Subject:  unitSubject(u),
			Detail:   "No FragmentPath. Loaded unit with no on-disk fragment — likely the unit file was deleted while the unit remained loaded.",
		})
	}
	for _, u := range highRestart {
		out = append(out, scan.Finding{
			Severity: scan.SeverityNotice,
			Check:    "restarts",
			Subject:  unitSubject(u),
			Detail:   fmt.Sprintf("restarted %d time(s) (Restart=%s Result=%s); investigate flapping.", u.Props.NRestarts, u.Props.Restart, u.Props.Result),
		})
	}

	if opts.CheckUnitFilePerms {
		out = append(out, unitFilePermFindings(units)...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

// unitSubject names a unit with its bus scope, e.g. "user/foo.service".
func unitSubject(u EnrichedUnit) string {
	return fmt.Sprintf("%s/%s", u.Scope, u.Name)
}

func severityRank(s scan.Severity) int {
	switch s {
	case scan.SeverityCritical:
		return 5
	case scan.SeverityError:
		return 4
	case scan.SeverityWarning:
		return 3
	case scan.SeverityNotice:
		return 2
	case scan.SeverityInfo:
		return 1
	}
	return 0
}

// unitFilePermFindings flags world-writable unit files. systemd refuses to
// load them in some configurations, but more importantly they are a real
// privilege-escalation hazard: anyone can rewrite the ExecStart.
func unitFilePermFindings(units []EnrichedUnit) []scan.Finding {
	seen := map[string]bool{}
	out := []scan.Finding{}
	for _, u := range units {
		path := u.Props.FragmentPath
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := fi.Mode().Perm()
		if mode&0o002 != 0 {
			out = append(out, scan.Finding{
				Severity: scan.SeverityCritical,
				Check:    "unit_file_writable",
				Subject:  path,
				Detail: fmt.Sprintf("mode=%o unit=%s — anyone on the system can rewrite ExecStart and gain privileges.",
					mode, u.Name),
			})
		}
	}
	return out
}
