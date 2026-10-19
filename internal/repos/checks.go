package repos

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/finding"
)

// State is what the checks read.
type State struct {
	Repos []Repo
	Links []Link
	// Meta is the GitHub cache by Repo.Key.
	Meta map[string]Meta
	// User is the GitHub login whose repos are "mine".
	User string
	// GhqRoot is where ghq keeps repos as host/owner/name; "" skips the
	// layout check.
	GhqRoot string
	// StaleFetch is how old a last fetch may be before ahead/behind counts
	// are called out as stale.
	StaleFetch time.Duration
	Now        time.Time
}

// Mine reports whether r belongs to user.
func (r Repo) Mine(user string) bool { return user != "" && strings.EqualFold(r.Owner, user) }

// Checks lists the repo checks in run order.
var Checks = []finding.Check[*State]{
	{ID: "repo.error", Fn: repoError},
	{ID: "repo.operation", Fn: inProgress},
	{ID: "repo.dirty", Fn: dirty},
	{ID: "repo.unpushed", Fn: unpushed},
	{ID: "repo.no_remote", Fn: noRemote},
	{ID: "repo.missing", Fn: missing},
	{ID: "repo.moved", Fn: moved},
	{ID: "repo.default_branch", Fn: defaultBranch},
	{ID: "repo.duplicate", Fn: duplicate},
	{ID: "repo.behind", Fn: behind},
	{ID: "repo.untracked", Fn: untracked},
	{ID: "repo.stash", Fn: stashed},
	{ID: "repo.no_upstream", Fn: noUpstream},
	{ID: "repo.detached", Fn: detached},
	{ID: "repo.stale_fetch", Fn: staleFetch},
	{ID: "repo.layout", Fn: layout},
	{ID: "repo.archived", Fn: archived},
	{ID: "links.broken", Fn: brokenLinks},
}

func each(s *State, fn func(Repo) *finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, r := range s.Repos {
		if f := fn(r); f != nil {
			if f.Subject == "" {
				f.Subject = r.Path
			}
			out = append(out, *f)
		}
	}
	return out
}

func group(id, title, hint string) *finding.Group {
	return &finding.Group{ID: id, Title: title, Hint: hint}
}

func repoError(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Error == "" {
			return nil
		}
		return &finding.Finding{Severity: finding.Warning, Message: r.Path + ": " + r.Error,
			Hint: "Run git status there; the repository may be corrupt or owned by another user."}
	})
}

func inProgress(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Operation == "" && r.Conflicts == 0 {
			return nil
		}
		op := r.Operation
		if op == "" {
			op = "merge"
		}
		msg := fmt.Sprintf("a %s is in progress in %s", op, r.Path)
		if r.Conflicts > 0 {
			msg += fmt.Sprintf(" with %d conflicted file(s)", r.Conflicts)
		}
		return &finding.Finding{Severity: finding.Warning, Message: msg,
			Hint: fmt.Sprintf("Finish it (git %s --continue) or abandon it (git %s --abort).", op, op)}
	})
}

func dirty(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if !r.Dirty() || r.Operation != "" {
			return nil
		}
		return &finding.Finding{Severity: finding.Notice,
			Message: fmt.Sprintf("%s has uncommitted changes (%d staged, %d modified)", r.Path, r.Staged, r.Modified),
			Hint:    "Commit or stash them; sync never touches a repository with local changes."}
	})
}

func unpushed(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Ahead == 0 {
			return nil
		}
		hint := "Push them (audit repos sync --push for your own repos), or they exist only here."
		if !r.Mine(s.User) {
			hint = "Local commits on someone else's repo: push them to your fork, or they exist only here."
		}
		return &finding.Finding{Severity: finding.Notice,
			Message: fmt.Sprintf("%s has %d commit(s) on %s not pushed to %s", r.Path, r.Ahead, r.Branch, r.Upstream), Hint: hint}
	})
}

func noRemote(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Remotes > 0 || r.Empty || r.Error != "" {
			return nil
		}
		return &finding.Finding{Severity: finding.Notice, Message: r.Path + " has no remote, so it is not backed up anywhere",
			Hint: "Add a remote (gh repo create --source . --private --push) or delete it if it is scratch work."}
	})
}

func meta(s *State, r Repo) (Meta, bool) {
	m, ok := s.Meta[r.Key()]
	return m, ok && m.Error == ""
}

func missing(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if m, ok := meta(s, r); !ok || !m.Missing {
			return nil
		}
		return &finding.Finding{Severity: finding.Warning, Subject: r.Path,
			Message: fmt.Sprintf("%s no longer exists on GitHub (deleted, or private to its owner)", r.Slug()),
			Hint:    "Keep the clone if you need it (it is now the only copy you have) and remove the remote, or delete it."}
	})
}

func moved(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		m, ok := meta(s, r)
		if !ok || m.Moved == "" {
			return nil
		}
		return &finding.Finding{Severity: finding.Notice,
			Message: fmt.Sprintf("%s/%s was renamed or transferred to %s", r.Owner, r.Name, m.Moved),
			Hint:    "audit repos sync updates the remote URL (and can move the clone to its new ghq path)."}
	})
}

func defaultBranch(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		m, ok := meta(s, r)
		if !ok || m.DefaultBranch == "" || r.RemoteHEAD == "" || r.RemoteHEAD == m.DefaultBranch {
			return nil
		}
		return &finding.Finding{Severity: finding.Notice,
			Message: fmt.Sprintf("%s's default branch is now %s (the clone still has %s)", r.Slug(), m.DefaultBranch, r.RemoteHEAD),
			Hint:    "audit repos sync retargets origin/HEAD and, when you are on the old branch, switches to the new one."}
	})
}

func duplicate(s *State) []finding.Finding {
	byKey := map[string][]string{}
	for _, r := range s.Repos {
		if r.Host != "" && r.Owner != "" {
			byKey[r.Key()] = append(byKey[r.Key()], r.Path)
		}
	}
	keys := make([]string, 0, len(byKey))
	for k, ps := range byKey {
		if len(ps) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]finding.Finding, 0, len(keys))
	for _, k := range keys {
		out = append(out, finding.Finding{Severity: finding.Warning, Subject: k, Details: byKey[k],
			Message: fmt.Sprintf("%s is cloned %d times", k, len(byKey[k])),
			Hint:    "Keep one clone; work split across copies is easy to lose."})
	}
	return out
}

func behind(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Behind == 0 {
			return nil
		}
		msg := fmt.Sprintf("%s is %d commit(s) behind %s", r.Path, r.Behind, r.Upstream)
		if !r.LastFetch.IsZero() {
			msg += " as of " + r.LastFetch.UTC().Format(time.DateOnly)
		}
		return &finding.Finding{Severity: finding.Info, Message: msg, Hint: "audit repos sync",
			Group: group("behind", "Sync the repos behind their remotes", "audit repos sync fast-forwards the clean ones")}
	})
}

func untracked(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Untracked == 0 {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: fmt.Sprintf("%s has %d untracked file(s)", r.Path, r.Untracked),
			Group: group("untracked", "Commit, ignore or delete untracked files", "add them to .gitignore or git clean -n to review")}
	})
}

func stashed(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Stashes == 0 {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: fmt.Sprintf("%s has %d stash entr(ies)", r.Path, r.Stashes),
			Group: group("stash", "Apply or drop old stashes", "git stash list; git stash show -p stash@{N}")}
	})
}

func noUpstream(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if r.Upstream != "" || r.Detached || r.Remotes == 0 || r.Empty || r.Error != "" {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: fmt.Sprintf("%s: branch %s tracks no remote branch", r.Path, r.Branch),
			Group: group("no_upstream", "Set an upstream for branches that track nothing", "git push -u origin BRANCH")}
	})
}

func detached(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		if !r.Detached {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: r.Path + " has a detached HEAD",
			Group: group("detached", "Check out a branch in detached repos", "git switch -")}
	})
}

func staleFetch(s *State) []finding.Finding {
	if s.StaleFetch <= 0 {
		return nil
	}
	return each(s, func(r Repo) *finding.Finding {
		if r.Remotes == 0 || r.Error != "" || !r.LastFetch.IsZero() && s.Now.Sub(r.LastFetch) < s.StaleFetch {
			return nil
		}
		when := "never fetched"
		if !r.LastFetch.IsZero() {
			when = "last fetched " + r.LastFetch.UTC().Format(time.DateOnly)
		}
		return &finding.Finding{Severity: finding.Info, Message: fmt.Sprintf("%s: %s, so ahead/behind may be wrong", r.Path, when),
			Group: group("stale_fetch", "Fetch repos that have not been fetched lately", "audit repos refresh")}
	})
}

// GhqPath is where ghq keeps r under root.
func GhqPath(root string, r Repo) string {
	return filepath.Join(root, r.Host, r.Owner, r.Name)
}

func layout(s *State) []finding.Finding {
	if s.GhqRoot == "" {
		return nil
	}
	root := filepath.Clean(s.GhqRoot)
	return each(s, func(r Repo) *finding.Finding {
		if !strings.HasPrefix(r.Path, root+string(filepath.Separator)) || r.Host == "" || r.Owner == "" {
			return nil
		}
		want := GhqPath(root, r)
		if strings.EqualFold(r.Path, want) {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: fmt.Sprintf("%s is cloned from %s but lives at %s", r.Slug(), r.Remote, r.Path),
			Group: group("layout", "Move clones to the ghq path of their remote", "audit repos sync --move")}
	})
}

func archived(s *State) []finding.Finding {
	return each(s, func(r Repo) *finding.Finding {
		m, ok := meta(s, r)
		if !ok || !m.Archived {
			return nil
		}
		return &finding.Finding{Severity: finding.Info, Message: r.Slug() + " is archived on GitHub; it gets no more updates",
			Group: group("archived", "Review clones of archived repos", "keep, replace with a maintained fork, or delete")}
	})
}

func brokenLinks(s *State) []finding.Finding {
	var out []finding.Finding
	for _, l := range s.Links {
		switch {
		case l.Broken:
			out = append(out, finding.Finding{Severity: finding.Warning, Subject: l.Path,
				Message: fmt.Sprintf("%s points at %s, which does not exist", l.Path, l.Target),
				Hint:    "Remove the link, or re-clone the repo it pointed at."})
		case l.NotRepo:
			out = append(out, finding.Finding{Severity: finding.Info, Subject: l.Path,
				Message: fmt.Sprintf("%s points at %s, which is not a git repository", l.Path, l.Target)})
		}
	}
	return out
}

// Item is a repo joined with its GitHub data and tags.
type Item struct {
	Repo
	Meta *Meta    `json:"meta,omitempty"`
	Tags []string `json:"tags,omitempty"`
	// IsMine marks the user's own repos.
	IsMine bool `json:"mine"`
}

// NormalizeTag lowercases a tag and joins words with dashes.
func NormalizeTag(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.ReplaceAll(s, "_", " "))), "-")
}

// AutoTags derives tags: the host's first label, mine or others, the
// language, fork, archived, local (no remote) and the GitHub topics.
func AutoTags(r Repo, m *Meta, user string) []string {
	var tags []string
	if r.Host != "" {
		tags = append(tags, strings.Split(r.Host, ".")[0])
	}
	switch {
	case r.Remotes == 0:
		tags = append(tags, "local")
	case r.Mine(user):
		tags = append(tags, "mine")
	case r.Owner != "":
		tags = append(tags, "others")
	}
	if r.Language != "" {
		tags = append(tags, NormalizeTag(r.Language))
	}
	if m != nil && m.Error == "" {
		if m.Fork {
			tags = append(tags, "fork")
		}
		if m.Archived {
			tags = append(tags, "archived")
		}
		for _, t := range m.Topics {
			tags = append(tags, NormalizeTag(t))
		}
	}
	return tags
}

// Annotate joins repos with metadata (by Key) and stored tags (by Key).
func Annotate(rs []Repo, metas map[string]Meta, tags map[string][]string, user string) []Item {
	out := make([]Item, 0, len(rs))
	for _, r := range rs {
		it := Item{Repo: r, IsMine: r.Mine(user)}
		if m, ok := metas[r.Key()]; ok {
			it.Meta = &m
		}
		seen := map[string]bool{}
		for _, t := range append(AutoTags(r, it.Meta, user), tags[r.Key()]...) {
			if t != "" && !seen[t] {
				seen[t] = true
				it.Tags = append(it.Tags, t)
			}
		}
		sort.Strings(it.Tags)
		out = append(out, it)
	}
	return out
}

// Query filters items for the list.
type Query struct {
	Tags []string
	Find string
	// Owner is "mine", "others" or an owner name.
	Owner string
	// Dirty keeps repos with anything local to lose: changes, untracked
	// files, stashes, unpushed commits or an operation in progress.
	Dirty bool
	// Outdated keeps repos behind their upstream.
	Outdated bool
}

// Empty reports whether q keeps everything.
func (q Query) Empty() bool {
	return len(q.Tags) == 0 && q.Find == "" && q.Owner == "" && !q.Dirty && !q.Outdated
}

// Match reports whether it passes q.
func (q Query) Match(it Item) bool {
	for _, t := range q.Tags {
		if !slices.Contains(it.Tags, NormalizeTag(t)) {
			return false
		}
	}
	switch strings.ToLower(q.Owner) {
	case "":
	case "mine":
		if !it.IsMine {
			return false
		}
	case "others":
		if it.IsMine || it.Owner == "" {
			return false
		}
	default:
		if !strings.EqualFold(it.Owner, q.Owner) {
			return false
		}
	}
	if q.Dirty && it.Clean() && it.Stashes == 0 && it.Ahead == 0 {
		return false
	}
	if q.Outdated && it.Behind == 0 {
		return false
	}
	if q.Find != "" {
		f := strings.ToLower(q.Find)
		hay := []string{it.Path, it.Slug()}
		if it.Meta != nil {
			hay = append(hay, it.Meta.Description)
		}
		if !slices.ContainsFunc(hay, func(h string) bool { return strings.Contains(strings.ToLower(h), f) }) {
			return false
		}
	}
	return true
}

// Filter keeps the items q matches.
func (q Query) Filter(items []Item) []Item {
	var out []Item
	for _, it := range items {
		if q.Match(it) {
			out = append(out, it)
		}
	}
	return out
}

// Analyze runs every repo check.
func Analyze(s *State) []finding.Finding {
	fs := finding.RunChecks(Command, s, Checks)
	finding.Sort(fs)
	return fs
}
