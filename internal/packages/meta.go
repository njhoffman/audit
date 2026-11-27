package packages

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Registries a package can be looked up in.
const (
	RegistryPyPI     = "pypi"
	RegistryNpm      = "npm"
	RegistryCrates   = "crates.io"
	RegistryGoProxy  = "goproxy"
	RegistryRubygems = "rubygems"
	RegistryGitHub   = "github"
	// RegistryGit is a git remote's branch head, for crates installed with
	// cargo install --git (a pinned rev or tag has none to follow).
	RegistryGit = "git"
)

// ID is the package's identity in its registry: the module path for go,
// owner/repo for gh, the name otherwise. Several go binaries built from one
// module share an ID.
func (p Package) ID() string {
	if p.Ident != "" {
		return p.Ident
	}
	return p.Name
}

// Key identifies a package across managers: manager:id.
func (p Package) Key() string { return MetaKey(p.Manager, p.ID()) }

// MetaKey builds the key Meta and tags are stored under.
func MetaKey(manager, id string) string { return manager + ":" + id }

// Registry names where the latest version of p is published, or "" when it
// was installed from git, a path or an unknown source.
func (p Package) Registry() string {
	switch p.Manager {
	case "uv":
		if p.Source == "pypi" {
			return RegistryPyPI
		}
	case "pnpm":
		if p.Source == "npm" {
			return RegistryNpm
		}
	case "cargo":
		if p.Source == "crates.io" {
			return RegistryCrates
		}
		if strings.HasPrefix(p.Source, "git:") && p.Revision != "" && !strings.Contains(p.Source, "?rev=") &&
			!strings.Contains(p.Source, "?tag=") {
			return RegistryGit
		}
	case "go":
		if p.Ident != "" && p.Version != "" && p.Version != "(devel)" {
			return RegistryGoProxy
		}
	case "gem":
		if p.Source == "rubygems" {
			return RegistryRubygems
		}
	case "gh", BinsManager:
		if p.Ident != "" {
			return RegistryGitHub
		}
	}
	return ""
}

// SourceKind is "git", "local" or "registry", from where p was installed.
func (p Package) SourceKind() string {
	s := p.Source
	switch {
	case p.Manager == "go" && (p.Version == "(devel)" || p.Ident == ""):
		return "local"
	case strings.HasPrefix(s, "git:") || strings.HasPrefix(s, "git+"):
		return "git"
	case strings.HasPrefix(s, "path:") || strings.HasPrefix(s, "/"):
		return "local"
	}
	return "registry"
}

// Meta is what a registry says about a package. It is cached so the
// inventory can show it without network access; CheckedAt says how old the
// version data is and DescribedAt how old the descriptive fields are.
type Meta struct {
	Manager  string    `json:"manager"`
	ID       string    `json:"id"`
	Registry string    `json:"registry,omitempty"`
	Latest   string    `json:"latest,omitempty"`
	LatestAt time.Time `json:"latest_at,omitzero"`
	// Installed is the version installed when the registry was checked;
	// InstalledYanked applies to it only.
	Installed       string `json:"installed,omitempty"`
	InstalledYanked bool   `json:"installed_yanked,omitempty"`
	// InstalledAt is when the installed version was released, where the
	// registry dates every version (PyPI, npm, crates.io).
	InstalledAt time.Time `json:"installed_at,omitzero"`
	// Deprecated holds the registry's deprecation message ("" when none).
	Deprecated  string    `json:"deprecated,omitempty"`
	Archived    bool      `json:"archived,omitempty"`
	Description string    `json:"description,omitempty"`
	Repo        string    `json:"repo,omitempty"`
	Homepage    string    `json:"homepage,omitempty"`
	License     string    `json:"license,omitempty"`
	Keywords    []string  `json:"keywords,omitempty"`
	CheckedAt   time.Time `json:"checked_at,omitzero"`
	DescribedAt time.Time `json:"described_at,omitzero"`
	// TaggedAt is when AI tags were last assigned, so tags the user removed
	// are not put back by a later run without --ai-retag.
	TaggedAt time.Time `json:"tagged_at,omitzero"`
	// Error is the last fetch failure; the other fields keep the last good
	// answer.
	Error string `json:"error,omitempty"`
	// Local marks an entry LocalMeta built from a system manager's own
	// answer; it is never saved.
	Local bool `json:"local,omitempty"`
}

// Key is the meta's manager:id.
func (m Meta) Key() string { return MetaKey(m.Manager, m.ID) }

// Tag sources.
const (
	TagAuto = "auto"
	TagUser = "user"
	TagAI   = "ai"
)

// Tag labels a package for filtering. Auto tags are derived at display time
// and never stored.
type Tag struct {
	Manager string `json:"manager"`
	ID      string `json:"id"`
	Tag     string `json:"tag"`
	Source  string `json:"source"`
}

// NormalizeTag lowercases a tag and joins words with dashes.
func NormalizeTag(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), "-")
}

// AutoTags are the tags every package gets from its inventory: its manager,
// runtime, "git" or "local" when not from a registry, and "mine" when its
// repository belongs to githubUser.
func AutoTags(p Package, m *Meta, githubUser string) []string {
	tags := []string{p.Manager}
	if p.Runtime != "" {
		tags = append(tags, NormalizeTag(p.Runtime))
	}
	if p.Kind != "" {
		tags = append(tags, p.Kind)
	}
	if k := p.SourceKind(); k != "registry" {
		tags = append(tags, k)
	}
	if githubUser != "" && ownedBy(p, m, githubUser) {
		tags = append(tags, "mine")
	}
	return tags
}

func ownedBy(p Package, m *Meta, user string) bool {
	user = strings.ToLower(user)
	cands := []string{p.Source}
	if p.Manager == "gh" || strings.HasPrefix(p.Ident, "github.com/") {
		cands = append(cands, "github.com/"+strings.TrimPrefix(p.Ident, "github.com/"))
	}
	if m != nil {
		cands = append(cands, m.Repo, m.Homepage)
	}
	for _, c := range cands {
		c = strings.ToLower(c)
		if strings.Contains(c, "github.com/"+user+"/") || strings.HasPrefix(c, "github:"+user+"/") {
			return true
		}
	}
	return false
}

// Item is a package joined with its cached registry data and tags.
type Item struct {
	Package
	Meta *Meta    `json:"meta,omitempty"`
	Tags []string `json:"tags,omitempty"`
	Gap  Gap      `json:"gap,omitempty"`
}

// Annotated is an inventory whose packages carry registry data and tags.
type Annotated struct {
	Inventory
	Items []Item `json:"items"`
	// CheckedAt is the oldest registry check among the manager's packages
	// that have a registry (zero when none was checked).
	CheckedAt time.Time `json:"checked_at,omitzero"`
	// Unchecked counts packages with a registry and no cached data.
	Unchecked int `json:"unchecked,omitempty"`
}

// Annotate joins inventories with cached metadata (by Key) and stored tags
// (by Key). Tags are sorted and deduplicated, auto tags included.
func Annotate(invs []Inventory, metas map[string]Meta, tags map[string][]string, githubUser string) []Annotated {
	out := make([]Annotated, 0, len(invs))
	for _, inv := range invs {
		a := Annotated{Inventory: inv}
		for _, p := range inv.Packages {
			it := Item{Package: p}
			if m, ok := metas[p.Key()]; ok {
				it.Meta = &m
				switch {
				case m.Local:
					it.Gap = LocalGap(p.Version, m.Latest)
				case m.Latest != "":
					it.Gap = p.GapTo(m.Latest)
				}
			}
			it.Tags = mergeTags(AutoTags(p, it.Meta, githubUser), tags[p.Key()])
			if p.Registry() != "" {
				switch {
				case it.Meta == nil || it.Meta.CheckedAt.IsZero():
					a.Unchecked++
				case a.CheckedAt.IsZero() || it.Meta.CheckedAt.Before(a.CheckedAt):
					a.CheckedAt = it.Meta.CheckedAt
				}
			}
			a.Items = append(a.Items, it)
		}
		out = append(out, a)
	}
	return out
}

func mergeTags(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, t := range l {
			if t != "" && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Query selects packages in the inventory view.
type Query struct {
	// Tags must all be present.
	Tags []string
	// Find matches the name, id, description or an executable, ignoring case.
	Find string
	// Outdated keeps packages behind their latest release.
	Outdated bool
	// Managers, when set, keeps only these managers' packages.
	Managers []string
	// Gaps, when set, keeps only packages this far behind (patch, minor,
	// major, update).
	Gaps []Gap
}

// Empty reports whether the query keeps everything.
func (q Query) Empty() bool {
	return len(q.Tags) == 0 && q.Find == "" && !q.Outdated && len(q.Managers) == 0 && len(q.Gaps) == 0
}

// Gap levels a query or an update can select.
var GapLevels = []Gap{GapPatch, GapMinor, GapMajor, GapUpdate}

// ParseGaps reads gap levels ("patch,minor"); "all" is every level.
func ParseGaps(vals []string) ([]Gap, error) {
	var out []Gap
	for _, v := range vals {
		v = strings.ToLower(strings.TrimSpace(v))
		switch {
		case v == "":
			continue
		case v == "all":
			return slices.Clone(GapLevels), nil
		case slices.Contains(GapLevels, Gap(v)):
			if !slices.Contains(out, Gap(v)) {
				out = append(out, Gap(v))
			}
		default:
			return nil, fmt.Errorf("unknown update level %q (want patch, minor, major, update or all)", v)
		}
	}
	return out, nil
}

// Match reports whether it passes the query.
func (q Query) Match(it Item) bool {
	for _, t := range q.Tags {
		if !slices.Contains(it.Tags, NormalizeTag(t)) {
			return false
		}
	}
	if q.Outdated && !it.Gap.Behind() {
		return false
	}
	if len(q.Managers) > 0 && !slices.Contains(q.Managers, it.Manager) {
		return false
	}
	if len(q.Gaps) > 0 && !slices.Contains(q.Gaps, it.Gap) {
		return false
	}
	if q.Find != "" {
		f := strings.ToLower(q.Find)
		hay := []string{it.Name, it.ID()}
		hay = append(hay, it.Executables...)
		if it.Meta != nil {
			hay = append(hay, it.Meta.Description)
			hay = append(hay, it.Meta.Keywords...)
		}
		found := false
		for _, h := range hay {
			if strings.Contains(strings.ToLower(h), f) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Filter applies q to every inventory, dropping managers left empty unless
// the query keeps everything.
func (q Query) Filter(as []Annotated) []Annotated {
	if q.Empty() {
		return as
	}
	var out []Annotated
	for _, a := range as {
		var items []Item
		for _, it := range a.Items {
			if q.Match(it) {
				items = append(items, it)
			}
		}
		if len(items) > 0 {
			a.Items = items
			out = append(out, a)
		}
	}
	return out
}

// Ref is a package named on the command line: "manager:name" or "name".
type Ref struct {
	Manager string
	Name    string
}

// ParseRef splits a "manager:name" reference. A prefix that is not a manager
// name is part of the package name.
func ParseRef(s string) Ref {
	if m, n, ok := strings.Cut(s, ":"); ok && slices.Contains(Names(), m) {
		return Ref{Manager: m, Name: n}
	}
	return Ref{Name: s}
}

// String is the ref as typed.
func (r Ref) String() string {
	if r.Manager == "" {
		return r.Name
	}
	return r.Manager + ":" + r.Name
}

// Find returns the packages r names, matching name or id. Go binaries built
// from one module collapse to a single match.
func (r Ref) Find(invs []Inventory) []Package {
	var out []Package
	seen := map[string]bool{}
	for _, inv := range invs {
		if r.Manager != "" && inv.Manager != r.Manager {
			continue
		}
		for _, p := range inv.Packages {
			if (p.Name == r.Name || p.ID() == r.Name) && !seen[p.Key()] {
				seen[p.Key()] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// LatestCells are the LATEST and RELEASED cells of an inventory row. A
// package from a registry with no cached data shows "unchecked"; one whose
// last lookup failed and has nothing cached shows "lookup failed". RELEASED
// is the latest release's age, followed by the installed version's when
// that is another, dated version: "2 months ago (yours 1 year)".
func LatestCells(it Item, now time.Time) (latest, released string) {
	m := it.Meta
	switch {
	case it.Registry() == "" && (m == nil || !m.Local):
		return "", ""
	case m == nil || m.CheckedAt.IsZero():
		return "unchecked", ""
	case m.Latest == "" && m.Error != "":
		return "lookup failed", ""
	}
	latest = m.Latest
	if latest == "" {
		latest = "no releases"
	}
	var marks []string
	if m.Deprecated != "" {
		marks = append(marks, "deprecated")
	}
	if m.Archived {
		marks = append(marks, "archived")
	}
	if m.InstalledYanked && m.Installed == it.Version {
		marks = append(marks, "yanked")
	}
	if len(marks) > 0 {
		latest += " (" + strings.Join(marks, ", ") + ")"
	}
	if !m.LatestAt.IsZero() {
		released = Age(now.Sub(m.LatestAt)) + " ago"
		if at := InstalledReleased(it); !at.IsZero() && it.Version != m.Latest {
			released += " (yours " + Age(now.Sub(at)) + ")"
		}
	}
	return latest, released
}

// InstalledReleased is when the installed version of it was released, or
// zero when the cache does not date it or dates another version.
func InstalledReleased(it Item) time.Time {
	if m := it.Meta; m != nil && m.Installed == it.Version {
		return m.InstalledAt
	}
	return time.Time{}
}

// RegistryNote says how old a manager's registry data is ("" when none of
// its packages come from a registry).
func RegistryNote(a Annotated, now time.Time) string {
	switch {
	case a.CheckedAt.IsZero() && a.Unchecked > 0:
		return "registry never checked; run audit packages registry"
	case a.CheckedAt.IsZero():
		return ""
	}
	s := "registry checked " + Age(now.Sub(a.CheckedAt)) + " ago"
	if a.Unchecked > 0 {
		s += fmt.Sprintf(" (%d unchecked)", a.Unchecked)
	}
	return s
}

// Coverage says how complete an outdated view is: of the packages it
// covers, how many have a known position against their latest release, how
// many have a registry but were never looked up, and how many lookups
// failed. An empty outdated list only means "all current" when Unchecked
// and Failed are zero.
type Coverage struct {
	Packages  int
	Known     int
	Unchecked int
	Failed    int
	// Unknown have data whose versions do not compare (a commit, a local
	// build) or no registry at all.
	Unknown int
	// OldestCheck is the oldest registry lookup among the checked packages.
	OldestCheck time.Time
}

// CoverageOf counts as over every item.
func CoverageOf(as []Annotated) Coverage {
	var c Coverage
	for _, a := range as {
		for _, it := range a.Items {
			c.Packages++
			reg := it.Registry() != ""
			switch {
			case it.Meta != nil && it.Meta.Error != "":
				c.Failed++
			case reg && (it.Meta == nil || it.Meta.CheckedAt.IsZero()):
				c.Unchecked++
			case it.Gap == GapUnknown:
				c.Unknown++
			default:
				c.Known++
			}
			if reg && it.Meta != nil && !it.Meta.CheckedAt.IsZero() && (c.OldestCheck.IsZero() || it.Meta.CheckedAt.Before(c.OldestCheck)) {
				c.OldestCheck = it.Meta.CheckedAt
			}
		}
	}
	return c
}

// GitRef is the remote URL a git-installed crate came from and the ref it
// follows: refs/heads/BRANCH for ?branch=, else HEAD.
func (p Package) GitRef() (url, ref string) {
	src := strings.TrimPrefix(p.Source, "git:")
	url, query, _ := strings.Cut(src, "?")
	ref = "HEAD"
	for _, kv := range strings.Split(query, "&") {
		if b, ok := strings.CutPrefix(kv, "branch="); ok && b != "" {
			ref = "refs/heads/" + b
		}
	}
	return url, ref
}

// shortRev is the first 8 characters of a commit.
func shortRev(r string) string {
	if len(r) > 8 {
		return r[:8]
	}
	return r
}

// VersionKey is the version an update must change: a git crate's version
// with its commit (its version often stays put while the commit moves),
// else the version.
func (p Package) VersionKey() string {
	if p.Revision != "" {
		return p.Version + "@" + shortRev(p.Revision)
	}
	return p.Version
}

// GapTo is how far p is behind latest: for a git crate, a different
// commit at the head it follows is an update; otherwise VersionGap.
func (p Package) GapTo(latest string) Gap {
	if p.Registry() != RegistryGit {
		return VersionGap(p.Manager, p.Version, latest)
	}
	switch {
	case latest == "":
		return GapUnknown
	case strings.HasPrefix(p.Revision, latest) || strings.HasPrefix(latest, p.Revision):
		return GapCurrent
	}
	return GapUpdate
}
