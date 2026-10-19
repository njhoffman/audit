package repos

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/njhoffman/audit/internal/packages"
)

// KindSync marks repo sync results in the saved update history.
const KindSync = "sync"

// Sync actions, in the order a repo's items run.
const (
	ActionSetURL  = "set-url"
	ActionSetHead = "set-head"
	ActionRename  = "rename-branch"
	ActionTrack   = "track"
	ActionPull    = "fast-forward"
	ActionPush    = "push"
	ActionMove    = "move"
	ActionLink    = "relink"
)

// SyncOptions select what a sync covers.
type SyncOptions struct {
	// Refs limit the sync to these repos (path, slug, owner/name or name).
	Refs []string
	// Push pushes the user's own repos that are only ahead.
	Push bool
	// Move moves clones under the ghq root to their host/owner/name path.
	Move    bool
	GhqRoot string
	// Links are the symlinks of repos.link_dirs, repointed after a move.
	Links []Link
	User  string
}

// MatchRef reports whether ref names the repo: its path, slug, owner/name
// or name.
func (r Repo) MatchRef(ref string) bool {
	ref = strings.ToLower(strings.TrimSuffix(ref, "/"))
	slug := strings.ToLower(r.Slug())
	return strings.ToLower(r.Path) == ref || slug == ref || strings.HasSuffix(slug, "/"+ref)
}

// planned builds one plan item for a repo.
func planned(r Repo, action, from, to string, argv ...string) packages.Planned {
	return packages.Planned{Kind: KindSync, Package: packages.Package{Manager: action, Name: r.Slug(), Ident: r.Path,
		Location: r.Path, Version: from}, Latest: to, Command: argv}
}

func skip(r Repo, action, from, reason string) packages.Planned {
	it := planned(r, action, from, "")
	it.Skip = reason
	return it
}

func gitArgs(path string, args ...string) []string {
	return append([]string{"git", "-C", path}, args...)
}

// MovedURL is url with owner/name replaced by fullName, keeping its form
// (ssh, scp or https).
func MovedURL(url, owner, name, fullName string) string {
	old := owner + "/" + name
	i := strings.LastIndex(strings.ToLower(url), strings.ToLower(old))
	if i < 0 {
		return ""
	}
	return url[:i] + fullName + url[i+len(old):]
}

// PlanSync plans the sync of items: migrations first (new origin URL after
// a rename, the renamed default branch), then a fast-forward for clean
// repos behind their upstream, a push of the user's own repos that are only
// ahead (with Push), and a move to the ghq path (with Move). Repos with
// local changes, an operation in progress or diverged history are listed
// with the reason and left alone. Without refs, only repos with something
// to do are listed.
func PlanSync(items []Item, o SyncOptions) (packages.Plan, []string) {
	var plan packages.Plan
	matched := make([]bool, len(o.Refs))
	// claimed holds move destinations already planned, so two clones never
	// race for one path.
	claimed := map[string]bool{}
	for _, it := range items {
		r := it.Repo
		named := false
		for i, ref := range o.Refs {
			if r.MatchRef(ref) {
				matched[i], named = true, true
			}
		}
		if len(o.Refs) > 0 && !named {
			continue
		}
		before := len(plan.Items)
		plan.Items = append(plan.Items, planRepo(it, o, claimed)...)
		if named && len(plan.Items) == before {
			plan.Items = append(plan.Items, skip(r, ActionPull, RepoStateLine(r), "nothing to do"))
		}
	}
	var unmatched []string
	for i, ref := range o.Refs {
		if !matched[i] {
			unmatched = append(unmatched, ref)
		}
	}
	return plan, unmatched
}

// RepoStateLine is a compact ahead/behind for the plan's FROM column.
func RepoStateLine(r Repo) string {
	return fmt.Sprintf("+%d -%d", r.Ahead, r.Behind)
}

func planRepo(it Item, o SyncOptions, claimed map[string]bool) []packages.Planned {
	r := it.Repo
	var out []packages.Planned
	if r.Error != "" || r.Remotes == 0 {
		return nil
	}
	m := it.Meta
	if m != nil && m.Error == "" && m.Moved != "" && r.OnGitHub() {
		if u := MovedURL(r.Remote, r.Owner, r.Name, m.Moved); u != "" {
			out = append(out, planned(r, ActionSetURL, r.Remote, u, gitArgs(r.Path, "remote", "set-url", "origin", u)...))
		}
	}
	if m != nil && m.Error == "" && m.DefaultBranch != "" && r.RemoteHEAD != "" && r.RemoteHEAD != m.DefaultBranch {
		old, nw := r.RemoteHEAD, m.DefaultBranch
		out = append(out, planned(r, ActionSetHead, old, nw, gitArgs(r.Path, "remote", "set-head", "origin", "--auto")...))
		if r.Branch == old && !r.Detached {
			// Renaming a branch leaves the working tree alone, so only an
			// operation in progress stands in the way.
			if r.Operation == "" {
				out = append(out,
					planned(r, ActionRename, old, nw, gitArgs(r.Path, "branch", "-m", old, nw)...),
					planned(r, ActionTrack, "origin/"+old, "origin/"+nw, gitArgs(r.Path, "branch", "--set-upstream-to=origin/"+nw, nw)...))
			} else {
				out = append(out, skip(r, ActionRename, old, "a "+r.Operation+" is in progress; rename the branch after it"))
			}
		}
	}
	state := RepoStateLine(r)
	switch {
	case r.Behind == 0:
	case r.Operation != "":
		out = append(out, skip(r, ActionPull, state, "a "+r.Operation+" is in progress"))
	case r.Dirty() || r.Conflicts > 0:
		out = append(out, skip(r, ActionPull, state, "uncommitted changes"))
	case r.Detached || r.Upstream == "":
		out = append(out, skip(r, ActionPull, state, "not on a branch that tracks an upstream"))
	case r.Ahead > 0:
		out = append(out, skip(r, ActionPull, state, fmt.Sprintf("diverged (%d ahead, %d behind); merge or rebase by hand", r.Ahead, r.Behind)))
	default:
		out = append(out, planned(r, ActionPull, state, "+0 -0", gitArgs(r.Path, "merge", "--ff-only", "--quiet", "@{upstream}")...))
	}
	if r.Ahead > 0 && r.Behind == 0 && r.Upstream != "" && !r.Detached {
		switch {
		case !o.Push:
			out = append(out, skip(r, ActionPush, state, "unpushed commits; pass --push to push your own repos"))
		case !r.Mine(o.User):
			out = append(out, skip(r, ActionPush, state, "not your repo; push to your fork by hand"))
		default:
			out = append(out, planned(r, ActionPush, state, "+0 -0", gitArgs(r.Path, "push", "--quiet")...))
		}
	}
	if o.Move && o.GhqRoot != "" && r.Host != "" && r.Owner != "" {
		root := filepath.Clean(o.GhqRoot)
		name, owner := r.Name, r.Owner
		if m != nil && m.Moved != "" {
			if mo, mn, ok := strings.Cut(m.Moved, "/"); ok {
				owner, name = mo, mn
			}
		}
		want := filepath.Join(root, r.Host, owner, name)
		if strings.HasPrefix(r.Path, root+string(filepath.Separator)) && !strings.EqualFold(r.Path, want) {
			if _, err := os.Stat(want); err == nil || claimed[strings.ToLower(want)] {
				out = append(out, skip(r, ActionMove, r.Path, want+" is already taken"))
				return out
			}
			claimed[strings.ToLower(want)] = true
			out = append(out, planned(r, ActionMove, r.Path, want,
				"sh", "-c", `mkdir -p "$(dirname "$2")" && mv -n -T "$1" "$2"`, "move", r.Path, want))
			for _, l := range o.Links {
				if l.Target == r.Path || filepath.Clean(l.Target) == r.Path {
					out = append(out, planned(r, ActionLink, l.Target, want, "ln", "-sfn", want, l.Path))
				}
			}
		}
	}
	return out
}

// VerifySync checks sync results against the repos scanned afterwards, by
// path (and by the new path after a move).
func VerifySync(results []packages.UpdateResult, after []Repo) {
	byPath := map[string]Repo{}
	for _, r := range after {
		byPath[r.Path] = r
	}
	for i := range results {
		res := &results[i]
		if res.Status != packages.UpdateOK || res.Kind != KindSync {
			continue
		}
		r, ok := byPath[res.ID]
		fail := func(reason string) { res.Status, res.Reason = packages.UpdateFailed, reason }
		switch res.Manager {
		case ActionMove:
			_, stillThere := byPath[res.ID]
			switch _, moved := byPath[res.Latest]; {
			case !moved:
				fail("no repository at " + res.Latest + " after the move")
			case stillThere:
				fail("the clone is still at " + res.ID)
			default:
				res.To = res.Latest
			}
			continue
		case ActionLink:
			res.To = res.Latest
			continue
		}
		if !ok {
			// Moved later in the same sync: the move item verifies it.
			res.To = res.Latest
			continue
		}
		switch res.Manager {
		case ActionPull:
			if r.Behind > 0 {
				fail(fmt.Sprintf("still %d behind after the fast-forward", r.Behind))
			}
		case ActionPush:
			if r.Ahead > 0 {
				fail(fmt.Sprintf("still %d ahead after the push", r.Ahead))
			}
		case ActionSetURL:
			if r.Remote != StripCredentials(res.Latest) {
				fail("origin is still " + r.Remote)
			}
		case ActionSetHead:
			if r.RemoteHEAD != res.Latest {
				fail("origin/HEAD is still " + r.RemoteHEAD)
			}
		case ActionRename:
			if r.Branch != res.Latest {
				fail("the branch is still " + r.Branch)
			}
		case ActionTrack:
			if r.Upstream != res.Latest {
				fail("the upstream is " + r.Upstream)
			}
		}
		if res.Status == packages.UpdateOK {
			res.To = res.Latest
		}
	}
}
