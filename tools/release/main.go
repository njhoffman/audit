// Command release cuts a semantic-version release: it picks the bump from
// the CHANGELOG's Unreleased section (or takes one), turns that section into
// a dated version section, commits, tags vX.Y.Z and pushes the branch and
// the tag. Run it through `just release [patch|minor|major]`.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	osexec "os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const changelog = "CHANGELOG.md"

// Version is a release version.
type Version struct{ Major, Minor, Patch int }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

var tagRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// ParseTag reads "v1.2.3".
func ParseTag(tag string) (Version, error) {
	m := tagRe.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return Version{}, fmt.Errorf("%q is not a vMAJOR.MINOR.PATCH tag", tag)
	}
	var n [3]int
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	return Version{n[0], n[1], n[2]}, nil
}

// Bump levels.
const (
	Patch = "patch"
	Minor = "minor"
	Major = "major"
)

// Next is v bumped by level. Before 1.0.0 a major bump only moves the minor
// (semver's 0.x convention) unless allowMajor is set, so 1.0.0 is a
// deliberate choice.
func (v Version) Next(level string, allowMajor bool) (Version, error) {
	switch level {
	case Major:
		if v.Major == 0 && !allowMajor {
			return Version{0, v.Minor + 1, 0}, nil
		}
		return Version{v.Major + 1, 0, 0}, nil
	case Minor:
		return Version{v.Major, v.Minor + 1, 0}, nil
	case Patch:
		return Version{v.Major, v.Minor, v.Patch + 1}, nil
	}
	return v, fmt.Errorf("unknown bump %q (want patch, minor or major)", level)
}

// Unreleased returns the body of the "## [Unreleased]" section and its
// line range in lines.
func Unreleased(text string) (body string, start, end int, err error) {
	lines := strings.Split(text, "\n")
	start = -1
	for i, l := range lines {
		if strings.HasPrefix(l, "## [Unreleased]") {
			start = i
			continue
		}
		if start >= 0 && strings.HasPrefix(l, "## ") {
			return strings.TrimSpace(strings.Join(lines[start+1:i], "\n")), start, i, nil
		}
	}
	if start < 0 {
		return "", 0, 0, errors.New("CHANGELOG.md has no ## [Unreleased] section")
	}
	return strings.TrimSpace(strings.Join(lines[start+1:], "\n")), start, len(lines), nil
}

// Level infers the bump from the Unreleased section: removals or a line
// marked BREAKING are major, additions, changes and deprecations minor,
// anything else (Fixed, Security) a patch.
func Level(body string) (string, error) {
	if strings.TrimSpace(body) == "" {
		return "", errors.New("the Unreleased section is empty; nothing to release")
	}
	level := Patch
	for _, l := range strings.Split(body, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "### Removed"), strings.Contains(strings.ToUpper(t), "BREAKING"):
			return Major, nil
		case strings.HasPrefix(t, "### Added"), strings.HasPrefix(t, "### Changed"), strings.HasPrefix(t, "### Deprecated"):
			level = Minor
		}
	}
	return level, nil
}

// Rewrite turns the Unreleased section into "## [X.Y.Z] - date" under a new
// empty Unreleased heading.
func Rewrite(text string, v Version, date time.Time) (string, error) {
	_, start, _, err := Unreleased(text)
	if err != nil {
		return "", err
	}
	lines := strings.Split(text, "\n")
	head := append([]string{}, lines[:start+1]...)
	head = append(head, "", fmt.Sprintf("## [%s] - %s", v, date.Format("2006-01-02")))
	return strings.Join(append(head, lines[start+1:]...), "\n"), nil
}

func git(dry bool, args ...string) (string, error) {
	if dry && len(args) > 0 && (args[0] == "commit" || args[0] == "tag" || args[0] == "push") {
		fmt.Println("would run: git", strings.Join(args, " "))
		return "", nil
	}
	out, err := osexec.Command("git", args...).CombinedOutput() // #nosec G204 -- fixed git subcommands
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func run(level string, dry, noPush, allowMajor bool) error {
	if s, err := git(false, "status", "--porcelain"); err != nil || s != "" {
		if err == nil {
			err = errors.New("the working tree has uncommitted changes; commit them first")
		}
		return err
	}
	branch, err := git(false, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return err
	}
	if branch != "main" {
		return fmt.Errorf("releases are cut from main, not %s", branch)
	}
	last, err := git(false, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*")
	if err != nil {
		return err
	}
	cur, err := ParseTag(last)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(changelog)
	if err != nil {
		return err
	}
	body, _, _, err := Unreleased(string(raw))
	if err != nil {
		return err
	}
	inferred, err := Level(body)
	if err != nil {
		return err
	}
	if level == "" {
		level = inferred
	}
	next, err := cur.Next(level, allowMajor)
	if err != nil {
		return err
	}
	tag := "v" + next.String()
	fmt.Printf("%s -> %s (%s)\n", last, tag, level)
	text, err := Rewrite(string(raw), next, time.Now())
	if err != nil {
		return err
	}
	if dry {
		fmt.Println("would rewrite CHANGELOG.md and release", tag)
	} else if err := os.WriteFile(changelog, []byte(text), 0o644); err != nil { // #nosec G306 G703 -- fixed path of a tracked doc
		return err
	}
	steps := [][]string{
		{"commit", "-q", "-m", "Release " + tag, "--", changelog},
		{"tag", "-a", tag, "-m", "Release " + tag},
	}
	if !noPush {
		steps = append(steps, []string{"push", "--atomic", "origin", "main", tag})
	}
	if !dry {
		if _, err := git(false, "add", changelog); err != nil {
			return err
		}
	}
	for _, s := range steps {
		if _, err := git(dry, s...); err != nil {
			return err
		}
	}
	if noPush {
		fmt.Printf("tagged %s; push with: git push --atomic origin main %s\n", tag, tag)
	} else if !dry {
		fmt.Println("released", tag)
	}
	return nil
}

func main() {
	dry := flag.Bool("n", false, "show what would happen without changing anything")
	noPush := flag.Bool("no-push", false, "commit and tag but do not push")
	allowMajor := flag.Bool("allow-major", false, "let a major bump leave 0.x (release 1.0.0)")
	flag.Parse()
	level := flag.Arg(0)
	if err := run(level, *dry, *noPush, *allowMajor); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}
