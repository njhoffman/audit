package core

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scan/programs"
	"github.com/njhoffman/audit/internal/system"
)

// ProgramPackageStore supplies the saved package inventories and registry
// cache the program checks are matched against (implemented by
// *store.Store).
type ProgramPackageStore interface {
	InventoryStore
	MetaStore
}

// CheckProgramShadowed is raised when a program's copy that runs is older
// than one further down PATH.
const CheckProgramShadowed = "programs.shadowed"

// programPackages matches each analyzed program to the package of its
// executables, from the last saved packages run, and describes it: a stat
// per program and a finding when a shadowed copy is newer. It returns the
// matches for the run data.
func (s *SystemScanner) programPackages(ctx context.Context, res *system.Result, now time.Time) []packages.ProgramPackages {
	part, ok := res.Data.Parts["programs"]
	if !ok || s.Packages == nil || s.Env == nil {
		return nil
	}
	per, _ := part["per_program"].([]programs.ProgramResult)
	managers := append(packages.Names(), packages.SystemNames()...)
	slices.Sort(managers)
	managers = slices.Compact(managers)
	invs, err := s.Packages.LatestInventories(ctx, managers)
	if err != nil {
		res.Errors = append(res.Errors, "programs: read saved packages: "+err.Error())
		return nil
	}
	if len(invs) == 0 {
		res.Stats = append(res.Stats, run.Stat{Group: "programs", Name: "packages", Value: "unknown", Note: "run audit packages to match programs to their packages"})
		return nil
	}
	metas, err := s.Packages.PackageMeta(ctx)
	if err != nil {
		res.Errors = append(res.Errors, "programs: read registry cache: "+err.Error())
		return nil
	}
	as := packages.Annotate(invs, packages.LocalMeta(invs, metas, now), nil, "")
	dpkg := s.Dpkg
	if dpkg == nil {
		dpkg = func(path string) string { return dpkgOwner(ctx, s.Env, path) }
	}
	owner := func(path string) (string, *packages.Item) { return packages.OwnerOf(path, as, dpkg) }
	resolve := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	var out []packages.ProgramPackages
	for _, pr := range per {
		if pr.Skipped {
			continue
		}
		pp := packages.ResolveProgram(string(pr.Program), programs.Executables[pr.Program], s.Env.WhichAll, resolve, owner)
		if len(pp.Copies) == 0 {
			continue
		}
		out = append(out, pp)
		res.Stats = append(res.Stats, programStat(pp, now))
		if c := pp.NewerShadowed(); c != nil {
			runs := pp.Copies[0]
			res.Findings = append(res.Findings, finding.Finding{
				Command: system.Command, Check: CheckProgramShadowed, Subject: pp.Program, Kind: finding.Issue, Severity: finding.Notice,
				Message: fmt.Sprintf("%s runs %s (%s %s), but %s further down PATH is newer (%s %s)", pp.Program, runs.Path,
					copyOwner(runs), runs.Item.Version, c.Path, copyOwner(*c), c.Item.Version),
				Details: copyLines(pp),
				Hint:    "Remove or update the copy that runs, or put the newer one's directory first on PATH.",
			})
		}
	}
	finding.Sort(res.Findings)
	return out
}

// programStat says which package the program that runs comes from, its
// update state and the shadowed copies.
func programStat(pp packages.ProgramPackages, now time.Time) run.Stat {
	st := run.Stat{Group: "programs", Name: pp.Program + " package"}
	runs := pp.Copies[0]
	var notes []string
	switch {
	case runs.Item != nil:
		st.Value = fmt.Sprintf("%s %s (%s)", runs.Item.Name, runs.Item.Version, runs.Manager)
		latest, released := packages.LatestCells(*runs.Item, now)
		switch {
		case runs.Item.Gap != packages.GapCurrent && runs.Item.Gap != packages.GapUnknown && runs.Item.Gap != packages.GapAhead:
			notes = append(notes, fmt.Sprintf("%s update to %s; audit packages update -M %s", runs.Item.Gap, latest, runs.Manager))
		case latest != "" && latest != "unchecked":
			notes = append(notes, "up to date")
		}
		if released != "" {
			notes = append(notes, "latest released "+released)
		}
	case runs.Manager != "":
		st.Value = runs.Manager + " (package unknown)"
	default:
		st.Value = "no package"
		notes = append(notes, runs.Path+" belongs to no package manager audit reads")
	}
	for _, c := range pp.Shadowed() {
		notes = append(notes, "also "+c.Path+": "+copyOwner(c)+versionOf(c)+", shadowed")
	}
	st.Note = strings.Join(notes, "; ")
	return st
}

func copyOwner(c packages.ProgramCopy) string {
	switch {
	case c.Item != nil:
		return c.Manager + " " + c.Item.Name
	case c.Manager != "":
		return c.Manager
	}
	return "no package"
}

func versionOf(c packages.ProgramCopy) string {
	if c.Item != nil && c.Item.Version != "" {
		return " " + c.Item.Version
	}
	return ""
}

func copyLines(pp packages.ProgramPackages) []string {
	out := make([]string, len(pp.Copies))
	for i, c := range pp.Copies {
		out[i] = c.Path + ": " + copyOwner(c) + versionOf(c)
	}
	return out
}

// dpkgOwner is the apt package that installed path, or "": dpkg-query -S
// knows a path by the name it was unpacked under, so on a merged-/usr
// system /sbin/x and /usr/sbin/x are both tried.
func dpkgOwner(ctx context.Context, env *exec.Env, path string) string {
	cands := []string{path}
	if rest, ok := strings.CutPrefix(path, "/usr/"); ok {
		cands = append(cands, "/"+rest)
	} else {
		cands = append(cands, "/usr"+path)
	}
	for _, p := range cands {
		r := env.Run(ctx, "dpkg-query", []string{"-S", p}, exec.Options{Timeout: 10 * time.Second})
		if !r.OK() {
			continue
		}
		for _, line := range strings.Split(r.Stdout, "\n") {
			if strings.HasPrefix(line, "diversion ") {
				continue
			}
			if pkg, file, ok := strings.Cut(line, ": "); ok && strings.TrimSpace(file) == p {
				pkg, _, _ = strings.Cut(pkg, ",")
				return strings.TrimSpace(pkg)
			}
		}
	}
	return ""
}
