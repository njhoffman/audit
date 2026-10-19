package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
)

func newReposCmd(a *app) *cobra.Command {
	var q repos.Query
	c, f := scanCommand(a, "repos", "Find git repositories and check their state",
		`Find the git repositories under repos.roots (the ghq root and home, without
the checkouts other tools manage) and check them: uncommitted changes,
untracked files, stashes, unpushed commits, branches behind or without an
upstream, detached heads, merges or rebases in progress, repos with no
remote, duplicate clones, clones outside their ghq path, and broken links
in repos.link_dirs. GitHub data (renames, default branch, archived,
deleted, topics) comes from the cache audit repos refresh fills.

A scan never touches the network: ahead and behind are as of each repo's
last fetch, which the list shows. --tag, --find, --owner, --dirty and
--outdated filter the list and imply --list.`,
		func() (core.Scanner, error) { return a.reposScanner(), nil },
		func(ctx context.Context, p *render.Printer, r *run.Run) {
			items, err := a.repoItems(ctx, r, q)
			if err != nil {
				a.log.Warn("load repos", "err", err)
				return
			}
			if len(items) == 0 && !q.Empty() {
				sayln(a.out, "No repos match the filter.")
				return
			}
			p.Repos(items, a.env.Home)
		})
	fl := c.Flags()
	fl.StringSliceVarP(&q.Tags, "tag", "t", nil, "list only repos with all of these tags (implies --list)")
	fl.StringVarP(&q.Find, "find", "f", "", "list only repos whose path, name or description contains this text (implies --list)")
	fl.StringVarP(&q.Owner, "owner", "O", "", "list only repos of this owner, or mine / others (implies --list)")
	fl.BoolVarP(&q.Dirty, "dirty", "d", false, "list only repos with local work: changes, untracked files, stashes or unpushed commits (implies --list)")
	fl.BoolVarP(&q.Outdated, "outdated", "u", false, "list only repos behind their upstream (implies --list)")
	f.impliesList = func() bool { return !q.Empty() }
	f.jsonExtra = func(ctx context.Context, r *run.Run) (any, error) { return a.repoItems(ctx, r, q) }
	c.AddCommand(newReposRefreshCmd(a), newReposTagCmd(a), newReposInfoCmd(a))
	return c
}

func (a *app) reposScanner() *core.ReposScanner {
	// Which repos are "mine" needs the login; it is asked of gh once and
	// remembered.
	s := core.NewRepos(a.cfg, a.env, a.githubUser(context.Background(), true))
	s.Meta, s.Now = a.store, timeNow()
	return s
}

// repoItems joins the saved repos with the GitHub cache and tags.
func (a *app) repoItems(ctx context.Context, r *run.Run, q repos.Query) ([]repos.Item, error) {
	var d repos.Data
	if len(r.Data) > 0 {
		if err := json.Unmarshal(r.Data, &d); err != nil {
			return nil, fmt.Errorf("read repos: %w", err)
		}
	}
	metas, err := a.store.RepoMeta(ctx)
	if err != nil {
		return nil, err
	}
	tags, err := a.store.RepoTags(ctx)
	if err != nil {
		return nil, err
	}
	return q.Filter(repos.Annotate(d.Repos, metas, tags, a.githubUser(ctx, false))), nil
}

func newReposRefreshCmd(a *app) *cobra.Command {
	var force, noFetch, asJSON, list bool
	c := &cobra.Command{
		Use:   "refresh",
		Short: "Fetch every repo and refresh the GitHub data, then rescan",
		Long: `Run git fetch --all --prune in every repo with a remote (repos.concurrency at
a time, repos.fetch_timeout each, never prompting for credentials), ask
GitHub about the github.com repos through gh api graphql (50 per request;
entries younger than repos.meta_max_age are reused unless --force), and
save a fresh scan so ahead/behind and the GitHub checks are current.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			s := a.reposScanner()
			s.Fetch, s.Lookup, s.LookupForce = !noFetch, true, force
			f := &scanFlags{rescan: true, report: !list && !asJSON, list: list, json: asJSON,
				jsonExtra: func(ctx context.Context, r *run.Run) (any, error) { return a.repoItems(ctx, r, repos.Query{}) }}
			view := func(ctx context.Context, p *render.Printer, r *run.Run) {
				if items, err := a.repoItems(ctx, r, repos.Query{}); err == nil {
					p.Repos(items, a.env.Home)
				}
			}
			return a.runScan(ctx, s, f, view)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&force, "force", "F", false, "ask GitHub about every repo, ignoring the cache age")
	fl.BoolVarP(&noFetch, "no-fetch", "N", false, "only refresh the GitHub data; do not fetch")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the run and the repos as JSON")
	fl.BoolVarP(&list, "list", "l", false, "print findings one per line plus the repos")
	c.MarkFlagsMutuallyExclusive("json", "list")
	return c
}

// findRepo resolves a repo argument against the saved scan: a path, a slug
// (host/owner/name), owner/name or a name, which must be unambiguous.
func (a *app) findRepo(ctx context.Context, arg string) (repos.Item, error) {
	r, err := a.engine.Saved(ctx, repos.Command, "")
	if err != nil {
		return repos.Item{}, err
	}
	if r == nil {
		return repos.Item{}, fmt.Errorf("no saved repos scan; run `audit repos -r` first")
	}
	items, err := a.repoItems(ctx, r, repos.Query{})
	if err != nil {
		return repos.Item{}, err
	}
	want := strings.ToLower(strings.TrimSuffix(a.env.Expand(arg), "/"))
	var hits []repos.Item
	for _, it := range items {
		slug := strings.ToLower(it.Slug())
		if strings.ToLower(it.Path) == want || slug == want || strings.HasSuffix(slug, "/"+want) {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return repos.Item{}, fmt.Errorf("no repo matches %q", arg)
	case 1:
		return hits[0], nil
	}
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = h.Path
	}
	return repos.Item{}, fmt.Errorf("%q matches %d repos (%s); give the path or owner/name", arg, len(hits), strings.Join(names, ", "))
}

func newReposTagCmd(a *app) *cobra.Command {
	var remove bool
	c := &cobra.Command{
		Use:   "tag REPO TAG...",
		Short: "Add (or with -d remove) your own tags on a repo",
		Long: `Add tags to a repo, or remove them with --delete. Automatic tags (host, mine,
others, local, language, fork, archived and GitHub topics) are derived and
cannot be removed. Tags are lowercased with words joined by dashes. Filter
the list with audit repos --tag.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			it, err := a.findRepo(ctx, args[0])
			if err != nil {
				return err
			}
			tags := make([]string, 0, len(args)-1)
			for _, t := range args[1:] {
				if n := repos.NormalizeTag(t); n != "" {
					tags = append(tags, n)
				}
			}
			if err := a.store.SetRepoTags(ctx, it.Key(), tags, remove); err != nil {
				return err
			}
			verb := "Tagged"
			if remove {
				verb = "Untagged"
			}
			say(a.out, "%s %s: %s\n", verb, it.Slug(), strings.Join(tags, " "))
			return nil
		},
	}
	c.Flags().BoolVarP(&remove, "delete", "d", false, "remove the tags instead of adding them")
	return c
}

func newReposInfoCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "info REPO",
		Short: "Show what audit knows about one repo",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			it, err := a.findRepo(c.Context(), args[0])
			if err != nil {
				return err
			}
			if asJSON {
				return a.writeJSON(it)
			}
			rows := [][]string{{"path", it.Path}, {"remote", it.Remote}, {"branch", it.Branch}, {"upstream", it.Upstream},
				{"state", render.RepoState(it.Repo)}, {"language", it.Language}, {"tags", strings.Join(it.Tags, " ")}}
			if !it.LastFetch.IsZero() {
				rows = append(rows, []string{"last fetch", it.LastFetch.Local().Format("2006-01-02 15:04")})
			}
			if m := it.Meta; m != nil {
				rows = append(rows, []string{"github", m.FullName}, []string{"description", m.Description},
					[]string{"default branch", m.DefaultBranch}, []string{"stars", fmt.Sprint(m.Stars)})
				if m.Parent != "" {
					rows = append(rows, []string{"fork of", m.Parent})
				}
				if m.Moved != "" {
					rows = append(rows, []string{"moved to", m.Moved})
				}
				if m.Error != "" {
					rows = append(rows, []string{"lookup error", m.Error})
				}
			}
			var keep [][]string
			for _, r := range rows {
				if r[1] != "" {
					keep = append(keep, r)
				}
			}
			a.printer().Table([]string{"FIELD", "VALUE"}, keep)
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the repo as JSON")
	return c
}
