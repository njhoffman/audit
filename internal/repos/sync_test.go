package repos

import (
	"reflect"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/packages"
)

func syncSummary(p packages.Plan) map[string]string {
	out := map[string]string{}
	for _, it := range p.Items {
		v := strings.Join(it.Command, " ")
		if it.Skip != "" {
			v = "skip: " + it.Skip
		}
		out[it.Manager+" "+it.Name] = v
	}
	return out
}

func TestMovedURL(t *testing.T) {
	for _, c := range [][2]string{
		{"git@github.com:old/name.git", "git@github.com:new/repo.git"},
		{"https://github.com/Old/Name", "https://github.com/new/repo"},
		{"ssh://git@github.com/old/name.git", "ssh://git@github.com/new/repo.git"},
	} {
		h, o, n := ParseRemote(c[0])
		_ = h
		if got := MovedURL(c[0], o, n, "new/repo"); got != c[1] {
			t.Errorf("%s -> %s, want %s", c[0], got, c[1])
		}
	}
	if MovedURL("https://elsewhere/x", "a", "b", "c/d") != "" {
		t.Error("no owner/name in the URL")
	}
}

func TestPlanSync(t *testing.T) {
	gh := "/h/ghq"
	repo := func(name string, mod func(*Repo)) Item {
		r := Repo{Path: gh + "/github.com/me/" + name, Host: "github.com", Owner: "me", Name: name, Remote: "git@github.com:me/" + name + ".git",
			Remotes: 1, Branch: "main", Upstream: "origin/main", RemoteHEAD: "main"}
		mod(&r)
		return Item{Repo: r, IsMine: r.Owner == "me"}
	}
	items := []Item{
		repo("behind", func(r *Repo) { r.Behind = 2 }),
		repo("dirty", func(r *Repo) { r.Behind, r.Modified = 1, 1 }),
		repo("diverged", func(r *Repo) { r.Behind, r.Ahead = 1, 1 }),
		repo("ahead", func(r *Repo) { r.Ahead = 3 }),
		repo("theirs", func(r *Repo) { r.Owner, r.Ahead = "them", 1; r.Path = gh + "/github.com/them/theirs" }),
		repo("rebasing", func(r *Repo) { r.Behind, r.Operation = 1, "rebase" }),
		repo("clean", func(r *Repo) {}),
		repo("renamed", func(r *Repo) { r.Branch, r.Upstream, r.RemoteHEAD = "master", "origin/master", "master" }),
	}
	items[7].Meta = &Meta{Moved: "me/renamed2", DefaultBranch: "main"}
	plan, unmatched := PlanSync(items, SyncOptions{User: "me"})
	want := map[string]string{
		"fast-forward github.com/me/behind":   "git -C " + gh + "/github.com/me/behind merge --ff-only --quiet @{upstream}",
		"fast-forward github.com/me/dirty":    "skip: uncommitted changes",
		"fast-forward github.com/me/diverged": "skip: diverged (1 ahead, 1 behind); merge or rebase by hand",
		"push github.com/me/ahead":            "skip: unpushed commits; pass --push to push your own repos",
		"push github.com/them/theirs":         "skip: unpushed commits; pass --push to push your own repos",
		"fast-forward github.com/me/rebasing": "skip: a rebase is in progress",
		"set-url github.com/me/renamed":       "git -C " + gh + "/github.com/me/renamed remote set-url origin git@github.com:me/renamed2.git",
		"set-head github.com/me/renamed":      "git -C " + gh + "/github.com/me/renamed remote set-head origin --auto",
		"rename-branch github.com/me/renamed": "git -C " + gh + "/github.com/me/renamed branch -m master main",
		"track github.com/me/renamed":         "git -C " + gh + "/github.com/me/renamed branch --set-upstream-to=origin/main main",
	}
	if got := syncSummary(plan); !reflect.DeepEqual(got, want) || len(unmatched) != 0 {
		t.Errorf("plan:\n%v\nwant\n%v", got, want)
	}
	if plan.Items[len(plan.Items)-4].Manager != ActionSetURL {
		t.Errorf("migrations come before the pull: %+v", plan.Items[len(plan.Items)-4])
	}

	plan, _ = PlanSync(items, SyncOptions{User: "me", Push: true, Refs: []string{"ahead", "theirs", "clean"}})
	want = map[string]string{
		"push github.com/me/ahead":         "git -C " + gh + "/github.com/me/ahead push --quiet",
		"push github.com/them/theirs":      "skip: not your repo; push to your fork by hand",
		"fast-forward github.com/me/clean": "skip: nothing to do",
	}
	if got := syncSummary(plan); !reflect.DeepEqual(got, want) {
		t.Errorf("named with --push:\n%v", got)
	}
	if _, unmatched := PlanSync(items, SyncOptions{Refs: []string{"nope"}}); !reflect.DeepEqual(unmatched, []string{"nope"}) {
		t.Errorf("unmatched: %v", unmatched)
	}

	misplaced := repo("x", func(r *Repo) { r.Path = gh + "/github.com/someone/else-x" })
	plan, _ = PlanSync([]Item{misplaced}, SyncOptions{Move: true, GhqRoot: gh,
		Links: []Link{{Path: "/h/git/x", Target: gh + "/github.com/someone/else-x"}}})
	twin := misplaced
	twin.Path = gh + "/github.com/another/x"
	plan2, _ := PlanSync([]Item{misplaced, twin}, SyncOptions{Move: true, GhqRoot: gh})
	if got := syncSummary(plan2); len(plan2.Items) != 2 || !strings.HasPrefix(got["move github.com/me/x"], "skip: ") &&
		!strings.Contains(got["move github.com/me/x"], "mv -n") {
		t.Errorf("two clones of one repo: %v", got)
	}
	if plan2.Items[1].Skip != gh+"/github.com/me/x is already taken" {
		t.Errorf("the second move is skipped: %+v", plan2.Items[1])
	}
	if got := syncSummary(plan); !strings.Contains(got["move github.com/me/x"], `mv -n -T "$1" "$2" move `+gh+"/github.com/someone/else-x "+gh+"/github.com/me/x") ||
		got["relink github.com/me/x"] != "ln -sfn "+gh+"/github.com/me/x /h/git/x" {
		t.Errorf("move: %v", got)
	}
}

func TestVerifySync(t *testing.T) {
	rs := []packages.UpdateResult{
		{Kind: KindSync, Manager: ActionPull, ID: "/a", Latest: "+0 -0", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionPull, ID: "/b", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionSetURL, ID: "/a", Latest: "git@github.com:n/r.git", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionRename, ID: "/a", Latest: "main", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionMove, ID: "/old", Latest: "/new", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionMove, ID: "/old2", Latest: "/nowhere", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionMove, ID: "/b", Latest: "/new", Status: packages.UpdateOK},
		{Kind: KindSync, Manager: ActionPush, ID: "/b", Status: packages.UpdateFailed, Reason: "exit status 1"},
	}
	VerifySync(rs, []Repo{
		{Path: "/a", Remote: "git@github.com:n/r.git", Branch: "main"},
		{Path: "/b", Behind: 2},
		{Path: "/new"},
	})
	got := make([]string, len(rs))
	for i, r := range rs {
		got[i] = r.Status + ":" + r.Reason
	}
	want := []string{"updated:", "failed:still 2 behind after the fast-forward", "updated:", "updated:", "updated:",
		"failed:no repository at /nowhere after the move", "failed:the clone is still at /b", "failed:exit status 1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}
