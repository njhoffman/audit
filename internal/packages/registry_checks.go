package packages

import (
	"fmt"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

// Registry check ids.
const (
	CheckOutdated     = "registry.outdated"
	CheckMajorBehind  = "registry.major_behind"
	CheckDeprecated   = "registry.deprecated"
	CheckYanked       = "registry.yanked"
	CheckArchived     = "registry.archived"
	CheckUnmaintained = "registry.unmaintained"
	CheckFetchError   = "registry.error"
)

// RegistryChecks run over cached registry data (State.Meta). They make no
// network calls; `audit packages registry` refreshes the cache.
var RegistryChecks = []finding.Check[*State]{
	{ID: CheckOutdated, Fn: outdated(false)},
	{ID: CheckMajorBehind, Fn: outdated(true)},
	{ID: CheckDeprecated, Fn: deprecated},
	{ID: CheckYanked, Fn: yanked},
	{ID: CheckArchived, Fn: archived},
	{ID: CheckUnmaintained, Fn: unmaintained},
	{ID: CheckFetchError, Fn: fetchErrors},
}

// metaItem is a package with cached registry data, one per Key.
type metaItem struct {
	Package
	Meta Meta
}

// withMeta lists the packages that have cached registry data, in inventory
// order. Go binaries of one module are reported once.
func (s *State) withMeta() []metaItem {
	var out []metaItem
	seen := map[string]bool{}
	for _, inv := range s.Inventories {
		for _, p := range inv.Packages {
			m, ok := s.Meta[p.Key()]
			if !ok || seen[p.Key()] || p.Registry() == "" {
				continue
			}
			seen[p.Key()] = true
			out = append(out, metaItem{p, m})
		}
	}
	return out
}

func subject(p Package) string { return p.Manager + ":" + p.ID() }

// UpdateHint is the command that updates p to its latest release.
func UpdateHint(p Package) string { return strings.Join(UpdateCommand(p), " ") }

// ManagerUpdateHint updates every package of a manager at once.
var ManagerUpdateHint = map[string]string{
	"uv":    "uv tool upgrade --all",
	"pnpm":  "pnpm update -g --latest",
	"cargo": "cargo install-update -a (cargo-update), or cargo install each crate",
	"go":    "go install <package>@latest for each binary",
	"gem":   "gem update --user-install",
	"gh":    "gh extension upgrade --all",
}

// Age renders how long ago t was in the largest whole unit ("3 months").
func Age(d time.Duration) string {
	day := 24 * time.Hour
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Hour:
		return plural(max(int(d/time.Minute), 1), "minute")
	case d < day:
		return plural(int(d/time.Hour), "hour")
	case d < 30*day:
		return plural(int(d/day), "day")
	case d < 365*day:
		return plural(int(d/(30*day)), "month")
	}
	return plural(int(d/(365*day)), "year")
}

// released dates the latest release. Findings become stored task titles, so
// they carry the date rather than an age that would change every day.
func (s *State) released(m Meta) string {
	if m.LatestAt.IsZero() {
		return ""
	}
	return "released " + m.LatestAt.UTC().Format(time.DateOnly)
}

func outdated(major bool) func(*State) []finding.Finding {
	return func(s *State) []finding.Finding {
		var hits []metaItem
		count := map[string]int{}
		for _, it := range s.withMeta() {
			g := VersionGap(it.Manager, it.Version, it.Meta.Latest)
			if !g.Behind() || (g == GapMajor) != major {
				continue
			}
			hits = append(hits, it)
			count[it.Manager]++
		}
		out := make([]finding.Finding, 0, len(hits))
		for _, it := range hits {
			msg := fmt.Sprintf("%s -> %s (%s", it.Version, it.Meta.Latest, VersionGap(it.Manager, it.Version, it.Meta.Latest))
			if r := s.released(it.Meta); r != "" {
				msg += "; " + r
			}
			f := finding.Finding{Severity: finding.Info, Subject: subject(it.Package), Message: msg + ")",
				Hint: UpdateHint(it.Package)}
			if major {
				f.Severity = finding.Notice
				f.Message += ": a major release, check the changelog before updating"
			} else {
				n := count[it.Manager]
				noun := "packages"
				if n == 1 {
					noun = "package"
				}
				f.Group = &finding.Group{ID: it.Manager, Title: fmt.Sprintf("Update %d outdated %s %s", n, it.Manager, noun),
					Hint: ManagerUpdateHint[it.Manager]}
			}
			// Grouped findings become one task listing their messages, so the
			// note goes in the message rather than the details.
			if uf, ok := s.UpdateFailures[it.Key()]; ok && uf.From == it.Version {
				f.Message += fmt.Sprintf("; last update attempt failed on %s: %s", uf.At.UTC().Format(time.DateOnly), uf.Reason)
			}
			out = append(out, f)
		}
		return out
	}
}

func deprecated(s *State) []finding.Finding {
	var out []finding.Finding
	for _, it := range s.withMeta() {
		if it.Meta.Deprecated == "" {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: subject(it.Package),
			Message: fmt.Sprintf("%s is deprecated: %s", it.Name, it.Meta.Deprecated),
			Hint:    "Find a replacement and uninstall it.",
		})
	}
	return out
}

func yanked(s *State) []finding.Finding {
	var out []finding.Finding
	for _, it := range s.withMeta() {
		if !it.Meta.InstalledYanked || it.Meta.Installed != it.Version {
			continue
		}
		f := finding.Finding{
			Severity: finding.Warning, Subject: subject(it.Package),
			Message: fmt.Sprintf("installed version %s was yanked from %s", it.Version, it.Registry()),
			Hint:    UpdateHint(it.Package),
		}
		if it.Meta.Latest == "" || it.Meta.Latest == it.Version {
			f.Hint = "Install another version; this one was withdrawn."
		}
		out = append(out, f)
	}
	return out
}

func archived(s *State) []finding.Finding {
	var out []finding.Finding
	for _, it := range s.withMeta() {
		if !it.Meta.Archived {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Warning, Subject: subject(it.Package),
			Message: fmt.Sprintf("the repository of %s is archived (%s); it gets no more fixes", it.Name, it.Meta.Repo),
			Hint:    "Look for a maintained fork or replacement.",
		})
	}
	return out
}

func unmaintained(s *State) []finding.Finding {
	if s.UnmaintainedAfter <= 0 || s.Now.IsZero() {
		return nil
	}
	var out []finding.Finding
	for _, it := range s.withMeta() {
		if it.Meta.LatestAt.IsZero() || it.Meta.Archived || it.Meta.Deprecated != "" || s.Now.Sub(it.Meta.LatestAt) < s.UnmaintainedAfter {
			continue
		}
		out = append(out, finding.Finding{
			Kind: finding.Suggestion, Severity: finding.Info, Subject: subject(it.Package),
			Message: fmt.Sprintf("%s has had no release since %s (latest %s)", it.Name, it.Meta.LatestAt.UTC().Format(time.DateOnly), it.Meta.Latest),
			Hint:    "Check whether it is still maintained, or set packages.registry.unmaintained_after.",
		})
	}
	return out
}

func fetchErrors(s *State) []finding.Finding {
	var out []finding.Finding
	for _, it := range s.withMeta() {
		if it.Meta.Error == "" {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: subject(it.Package),
			Message: "registry lookup failed: " + it.Meta.Error,
		})
	}
	return out
}
