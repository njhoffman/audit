package packages

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// Gap is how far an installed version trails the latest published one.
type Gap string

const (
	GapCurrent Gap = "current"
	GapPatch   Gap = "patch"
	GapMinor   Gap = "minor"
	GapMajor   Gap = "major"
	// GapAhead means the installed version is newer than the latest release
	// (a prerelease or a build from source).
	GapAhead Gap = "ahead"
	// GapUnknown means one of the versions could not be parsed.
	GapUnknown Gap = ""
)

// Behind reports whether the gap calls for an update.
func (g Gap) Behind() bool { return g == GapPatch || g == GapMinor || g == GapMajor }

// version is a parsed version: dotted release numbers, then an optional
// qualifier ranked against a final release.
type version struct {
	release []int
	// qualRank orders qualifiers: dev < alpha < beta < rc < final < post.
	qualRank int
	qualNum  int
	rest     string
}

const (
	rankDev = iota
	rankAlpha
	rankBeta
	rankRC
	rankFinal
	rankPost
)

// qualifiers maps the spellings package ecosystems use (PEP 440, semver,
// rubygems) to a rank. Longest spellings come first so "alpha" is not read
// as "a" followed by "lpha".
var qualifiers = []struct {
	word string
	rank int
}{
	{"preview", rankRC}, {"alpha", rankAlpha}, {"beta", rankBeta}, {"post", rankPost},
	{"pre", rankRC}, {"dev", rankDev}, {"rev", rankPost}, {"rc", rankRC},
	{"a", rankAlpha}, {"b", rankBeta}, {"c", rankRC}, {"r", rankPost},
}

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	s, _, _ = strings.Cut(s, "+") // build metadata never orders versions
	var v version
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i {
			break
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return v, false
		}
		v.release = append(v.release, n)
		i = j
		if i+1 < len(s) && s[i] == '.' && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	if len(v.release) == 0 {
		return v, false
	}
	q := strings.ToLower(strings.TrimLeft(s[i:], ".-_"))
	if q == "" {
		v.qualRank = rankFinal
		return v, true
	}
	// An unrecognized qualifier ("nightly", a semver identifier) is still a
	// prerelease: semver ranks every prerelease below its release.
	v.qualRank, v.rest = rankAlpha, q
	for _, w := range qualifiers {
		if strings.HasPrefix(q, w.word) {
			v.qualRank, q = w.rank, strings.TrimLeft(q[len(w.word):], ".-_")
			j := 0
			for j < len(q) && q[j] >= '0' && q[j] <= '9' {
				j++
			}
			v.qualNum, _ = strconv.Atoi(q[:j])
			v.rest = q[j:]
			break
		}
	}
	return v, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (v version) part(i int) int {
	if i < len(v.release) {
		return v.release[i]
	}
	return 0
}

func (v version) compare(o version) int {
	for i := range max(len(v.release), len(o.release)) {
		if c := cmpInt(v.part(i), o.part(i)); c != 0 {
			return c
		}
	}
	if c := cmpInt(v.qualRank, o.qualRank); c != 0 {
		return c
	}
	if c := cmpInt(v.qualNum, o.qualNum); c != 0 {
		return c
	}
	return strings.Compare(v.rest, o.rest)
}

// CompareVersions orders two version strings of the given manager: -1, 0 or
// 1. ok is false when either cannot be parsed (a git sha, "(devel)").
func CompareVersions(manager, a, b string) (c int, ok bool) {
	if manager == "go" {
		va, vb := goVersion(a), goVersion(b)
		if !semver.IsValid(va) || !semver.IsValid(vb) {
			return 0, false
		}
		return semver.Compare(va, vb), true
	}
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)
	if !okA || !okB || isCommit(a) || isCommit(b) {
		return 0, false
	}
	return pa.compare(pb), true
}

// isCommit reports whether v looks like an abbreviated git commit, which gh
// records for extensions pinned to no release ("1a2b3c4" would otherwise
// parse as release 1).
func isCommit(v string) bool {
	if len(v) < 7 || len(v) > 40 {
		return false
	}
	letter := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'f':
			letter = true
		case r < '0' || r > '9':
			return false
		}
	}
	// A date-style version (20240101) is all digits.
	return letter
}

func goVersion(s string) string {
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	return s
}

// VersionGap says how far installed trails latest. A difference in the
// prerelease part only counts as a patch.
func VersionGap(manager, installed, latest string) Gap {
	c, ok := CompareVersions(manager, installed, latest)
	switch {
	case !ok:
		return GapUnknown
	case c == 0:
		return GapCurrent
	case c > 0:
		return GapAhead
	}
	if manager == "go" {
		installed, latest = strings.TrimPrefix(installed, "v"), strings.TrimPrefix(latest, "v")
	}
	a, _ := parseVersion(installed)
	b, _ := parseVersion(latest)
	switch {
	case a.part(0) != b.part(0):
		return GapMajor
	case a.part(1) != b.part(1):
		return GapMinor
	}
	return GapPatch
}

// IsPrerelease reports whether v carries a prerelease qualifier.
func IsPrerelease(v string) bool {
	p, ok := parseVersion(v)
	return ok && p.qualRank < rankFinal
}
