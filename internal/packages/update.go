package packages

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Update statuses.
const (
	UpdateOK      = "updated"
	UpdateFailed  = "failed"
	UpdateSkipped = "skipped"
)

// OutputTail is how much of a failed command's output is kept.
const OutputTail = 4096

// UpdateCommand is the argv that updates p to its latest release, nil for an
// unknown manager. Every manager is updated one package at a time so each
// failure is reported against the package that caused it.
func UpdateCommand(p Package) []string {
	switch p.Manager {
	case "uv":
		return []string{"uv", "tool", "upgrade", p.Name}
	case "pnpm":
		return []string{"pnpm", "add", "-g", p.Name + "@latest"}
	case "cargo":
		return []string{"cargo", "install", "--locked", p.Name}
	case "go":
		pkg := p.Source
		if pkg == "" {
			pkg = p.Ident
		}
		return []string{"go", "install", pkg + "@latest"}
	case "gem":
		return []string{"gem", "update", "--user-install", p.Name}
	case "gh":
		return []string{"gh", "extension", "upgrade", p.Name}
	}
	return nil
}

// Matches reports whether r names p, by name or id.
func (r Ref) Matches(p Package) bool {
	return (r.Manager == "" || r.Manager == p.Manager) && (p.Name == r.Name || p.ID() == r.Name)
}

// PlanOptions select what an update plan covers.
type PlanOptions struct {
	// Refs names the packages to update; empty means every outdated one.
	Refs []Ref
	// Major allows updates across a major version.
	Major bool
	// Exclude lists packages never updated (packages.update.exclude).
	Exclude []Ref
}

// Planned is one package of an update plan.
type Planned struct {
	Package
	Latest  string   `json:"latest,omitempty"`
	Gap     Gap      `json:"gap,omitempty"`
	Command []string `json:"command,omitempty"`
	// Skip says why the package is not updated; "" means it is.
	Skip string `json:"skip,omitempty"`
}

// Plan is what an update would do.
type Plan struct {
	Items []Planned `json:"items"`
	// NotFromRegistry counts unnamed packages installed from git or a path,
	// which have no latest version to update to.
	NotFromRegistry int `json:"not_from_registry"`
	// Unmatched lists refs that name no installed package.
	Unmatched []string `json:"unmatched,omitempty"`
}

// Runnable lists the items that will be updated.
func (p Plan) Runnable() []Planned {
	var out []Planned
	for _, it := range p.Items {
		if it.Skip == "" {
			out = append(out, it)
		}
	}
	return out
}

// PlanUpdates decides what to update from the inventory and the registry
// cache. Without refs it lists the packages behind their latest release,
// skipping excluded ones and major bumps; with refs it lists exactly the
// named packages and says why any of them cannot be updated. Go binaries are
// planned one by one, since each is installed by its own package path.
func PlanUpdates(invs []Inventory, metas map[string]Meta, o PlanOptions) Plan {
	var plan Plan
	named := len(o.Refs) > 0
	matched := make([]bool, len(o.Refs))
	seen := map[string]bool{}
	for _, inv := range invs {
		if !inv.Available {
			continue
		}
		for _, p := range inv.Packages {
			if named {
				hit := false
				for i, r := range o.Refs {
					if r.Matches(p) {
						matched[i], hit = true, true
					}
				}
				if !hit {
					continue
				}
			}
			cmd := UpdateCommand(p)
			if seen[strings.Join(cmd, " ")] {
				continue
			}
			seen[strings.Join(cmd, " ")] = true
			it, ok := planOne(p, metas, o, named)
			if !ok {
				if named {
					continue
				}
				if p.Registry() == "" {
					plan.NotFromRegistry++
				}
				continue
			}
			it.Command = cmd
			plan.Items = append(plan.Items, it)
		}
	}
	for i, r := range o.Refs {
		if !matched[i] {
			plan.Unmatched = append(plan.Unmatched, r.String())
		}
	}
	return plan
}

// planOne plans p. ok is false when p is not part of the plan at all: an
// unnamed package that is current, or whose position cannot be told.
func planOne(p Package, metas map[string]Meta, o PlanOptions, named bool) (Planned, bool) {
	it := Planned{Package: p}
	if p.Registry() == "" {
		switch {
		case p.Manager == "go" && p.Version == "(devel)":
			it.Skip = "built from a local checkout (devel)"
		default:
			it.Skip = fmt.Sprintf("installed from %s, not a registry", sourceOr(p.Source, "an unknown source"))
		}
		return it, named
	}
	m, ok := metas[p.Key()]
	if !ok || m.Latest == "" {
		it.Skip = "latest version unknown; run audit packages registry"
		return it, named
	}
	it.Latest = m.Latest
	it.Gap = VersionGap(p.Manager, p.Version, m.Latest)
	switch {
	case it.Gap == GapCurrent || it.Gap == GapAhead:
		it.Skip = "already at the latest release"
		return it, named
	case it.Gap == GapUnknown && !named:
		return it, false
	}
	switch {
	case slices.ContainsFunc(o.Exclude, func(r Ref) bool { return r.Matches(p) }):
		it.Skip = "excluded by packages.update.exclude"
	case it.Gap == GapMajor && !o.Major:
		it.Skip = "major release; pass --major to update"
	case UpdateCommand(p) == nil:
		it.Skip = "no update command for " + p.Manager
	}
	return it, true
}

func sourceOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// UpdateResult is the outcome of one planned update.
type UpdateResult struct {
	Manager  string        `json:"manager"`
	Name     string        `json:"name"`
	ID       string        `json:"id"`
	From     string        `json:"from,omitempty"`
	To       string        `json:"to,omitempty"`
	Latest   string        `json:"latest,omitempty"`
	Status   string        `json:"status"`
	Command  string        `json:"command,omitempty"`
	Code     int           `json:"code"`
	Duration time.Duration `json:"duration"`
	// Reason is one line on why it failed or was skipped.
	Reason string `json:"reason,omitempty"`
	// Output is the tail of a failed command's output (stderr, or stdout
	// when stderr is empty).
	Output string `json:"output,omitempty"`
}

// Key is the result's package key.
func (r UpdateResult) Key() string { return MetaKey(r.Manager, r.ID) }

// Update is one run of audit packages update.
type Update struct {
	ID         int64          `json:"id"`
	Host       string         `json:"host,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Items      []UpdateResult `json:"items"`
}

// Counts tallies the results by status.
func (u Update) Counts() (updated, failed, skipped int) {
	for _, it := range u.Items {
		switch it.Status {
		case UpdateOK:
			updated++
		case UpdateFailed:
			failed++
		default:
			skipped++
		}
	}
	return updated, failed, skipped
}

// Summary is "12 updated, 2 failed, 3 skipped".
func (u Update) Summary() string {
	up, failed, skipped := u.Counts()
	return fmt.Sprintf("%d updated, %d failed, %d skipped", up, failed, skipped)
}

// RunOptions control RunUpdates.
type RunOptions struct {
	// Timeout bounds one update command.
	Timeout time.Duration
	// StopOnError skips the remaining updates after the first failure.
	StopOnError bool
	// OnStart and OnDone are called around each update command.
	OnStart func(Planned)
	OnDone  func(Planned, UpdateResult)
}

// RunUpdates runs the plan's update commands one after another in env and
// reports a result per plan item, skipped ones included. A zero exit counts
// as updated until Verify compares it with a fresh inventory. After an
// interruption the remaining items are skipped.
func RunUpdates(ctx context.Context, env *exec.Env, plan Plan, o RunOptions) []UpdateResult {
	out := make([]UpdateResult, 0, len(plan.Items))
	stop := ""
	for _, it := range plan.Items {
		r := UpdateResult{Manager: it.Manager, Name: it.Name, ID: it.ID(), From: it.Version, Latest: it.Latest,
			Status: UpdateSkipped, Command: strings.Join(it.Command, " "), Reason: it.Skip}
		if ctx.Err() != nil {
			stop = "not run: interrupted"
		}
		switch {
		case it.Skip != "":
		case stop != "":
			r.Reason = stop
		default:
			if o.OnStart != nil {
				o.OnStart(it)
			}
			start := time.Now()
			res := env.Run(ctx, it.Command[0], it.Command[1:], exec.Options{Timeout: o.Timeout})
			r.Duration, r.Code = time.Since(start), res.Code
			switch {
			case ctx.Err() != nil:
				r.Reason = "interrupted"
			case res.OK():
				r.Status = UpdateOK
			default:
				r.Status = UpdateFailed
				r.Output = Tail(res.Stderr, OutputTail)
				if strings.TrimSpace(r.Output) == "" {
					r.Output = Tail(res.Stdout, OutputTail)
				}
				r.Reason = failReason(res, o.Timeout, r.Output)
				if o.StopOnError {
					stop = "not run: an earlier update failed"
				}
			}
			if o.OnDone != nil {
				o.OnDone(it, r)
			}
		}
		out = append(out, r)
	}
	return out
}

func failReason(res exec.Result, timeout time.Duration, output string) string {
	switch res.Code {
	case exec.ExitTimeout:
		return fmt.Sprintf("timed out after %s", timeout)
	case exec.ExitNotFound:
		return "command not found"
	}
	reason := fmt.Sprintf("exit status %d", res.Code)
	if line := LastLine(output); line != "" {
		reason += ": " + line
	}
	return reason
}

// Verify checks the updated results against an inventory taken after the
// updates: a package still at its old version, or gone, failed even though
// its command exited 0. Updated results get their new version.
func Verify(results []UpdateResult, invs []Inventory) {
	now := map[string]Package{}
	for _, inv := range invs {
		for _, p := range inv.Packages {
			now[p.Manager+"\x00"+p.Name] = p
		}
	}
	for i := range results {
		r := &results[i]
		if r.Status != UpdateOK {
			continue
		}
		p, ok := now[r.Manager+"\x00"+r.Name]
		switch {
		case !ok:
			r.Status, r.Reason = UpdateFailed, "no longer installed after the update"
		case p.Version == r.From:
			r.Status, r.Reason = UpdateFailed, "the command succeeded but the version is still "+r.From
		default:
			r.To = p.Version
		}
	}
}

// Tail keeps the last n bytes of s, starting at a line boundary when one is
// within reach.
func Tail(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return "..." + "\n" + s
}

// LastLine is the last non-blank line of s, trimmed.
func LastLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// UpdateFailure is a package's last update attempt when it failed.
type UpdateFailure struct {
	At     time.Time `json:"at"`
	From   string    `json:"from"`
	Reason string    `json:"reason"`
}
