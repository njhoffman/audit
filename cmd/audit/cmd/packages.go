package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/registry"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/version"
)

// settingGitHubUser remembers the detected GitHub login.
const settingGitHubUser = "github_user"

// aiTagBatch is how many packages one tagging prompt covers.
const aiTagBatch = 50

func newPackagesCmd(a *app) *cobra.Command {
	var managers []string
	var q packages.Query
	c, f := scanCommand(a, "packages", "Inventory user package managers and check their installs",
		`Inventory packages installed by user-level package managers (`+strings.Join(packages.Names(), ", ")+`)
and check for broken or shadowed executables, runtime drift, stale runtime
directories and misplaced installs. --list prints the inventory with the
latest release of each package, how long ago it was published and its tags.

Registry data (latest versions, descriptions, deprecations) is cached by
audit packages registry; this command only reads the cache and shows how
old it is. --tag, --find and --outdated filter the inventory and imply
--list.`,
		func() (core.Scanner, error) { return a.packagesScanner(splitList(managers)) },
		func(ctx context.Context, p *render.Printer, r *run.Run) {
			as, err := a.annotated(ctx, r, q)
			if err != nil {
				a.log.Warn("load registry cache", "err", err)
				return
			}
			if len(as) == 0 && !q.Empty() {
				sayln(a.out, "No packages match the filter.")
				return
			}
			p.Packages(as)
		})
	fl := c.Flags()
	fl.StringSliceVarP(&managers, "manager", "M", nil, "inventory only these managers: "+strings.Join(packages.Names(), ", "))
	fl.StringSliceVarP(&q.Tags, "tag", "t", nil, "list only packages with all of these tags (repeatable; implies --list)")
	fl.StringVarP(&q.Find, "find", "f", "", "list only packages whose name, description or executables contain this text (implies --list)")
	fl.BoolVarP(&q.Outdated, "outdated", "u", false, "list only packages behind their latest release (implies --list)")
	f.impliesList = func() bool { return !q.Empty() }
	f.jsonExtra = func(ctx context.Context, r *run.Run) (any, error) { return a.annotated(ctx, r, q) }
	c.AddCommand(newPackagesRegistryCmd(a), newPackagesOutdatedCmd(a), newPackagesUpdateCmd(a), newPackagesInfoCmd(a), newPackagesTagCmd(a), newRuntimesCmd(a), newBinsCmd(a))
	return c
}

// packagesScanner builds the packages scanner over the registry cache.
func (a *app) packagesScanner(managers []string) (*core.PackagesScanner, error) {
	s, err := core.NewPackages(a.cfg, a.env, managers)
	if err != nil {
		return nil, err
	}
	s.Meta, s.Updates, s.Runtimes, s.Now = a.store, a.store, a.store, timeNow()
	for i, m := range s.Managers {
		if b, ok := m.(packages.Bins); ok {
			b.Tracked = func() (map[string]packages.TrackedBin, error) { return a.store.TrackedBins(context.Background()) }
			s.Managers[i] = b
		}
	}
	return s, nil
}

// registryRefresh is the configured registry lookup, limited to refs when
// any are given.
func (a *app) registryRefresh(refs []packages.Ref, force bool) *core.RegistryRefresh {
	rc := a.cfg.Packages.Registry
	return &core.RegistryRefresh{
		Options: registry.Options{MaxAge: rc.MaxAge, MetadataMaxAge: rc.MetadataMaxAge, Concurrency: rc.Concurrency,
			Timeout: rc.Timeout, Force: force},
		UserAgent: "audit/" + version.Version + " (+https://github.com/njhoffman/audit)",
		Only:      refs,
		Looker:    a.looker,
	}
}

func parseRefs(args []string) []packages.Ref {
	refs := make([]packages.Ref, len(args))
	for i, arg := range args {
		refs[i] = packages.ParseRef(arg)
	}
	return refs
}

// githubUser is the login whose repositories count as "mine": the config
// value, else the remembered one, else (when detect is set) gh's answer,
// which is then remembered. It is "" when unknown.
func (a *app) githubUser(ctx context.Context, detect bool) string {
	if a.cfg.GitHubUser != "" {
		return a.cfg.GitHubUser
	}
	u, err := a.store.Setting(ctx, settingGitHubUser)
	if err != nil {
		a.log.Warn("read setting", "key", settingGitHubUser, "err", err)
	}
	if u != "" || !detect {
		return u
	}
	if u, err = registry.GitHubUser(ctx, a.env); err != nil {
		a.log.Info("github user not detected; set github_user to tag your own packages", "err", err)
		return ""
	}
	if err := a.store.SetSetting(ctx, settingGitHubUser, u); err != nil {
		a.log.Warn("save setting", "key", settingGitHubUser, "err", err)
	}
	return u
}

// annotated joins r's inventory with the registry cache and tags, filtered
// by q.
func (a *app) annotated(ctx context.Context, r *run.Run, q packages.Query) ([]packages.Annotated, error) {
	var d packages.Data
	if len(r.Data) > 0 {
		if err := json.Unmarshal(r.Data, &d); err != nil {
			return nil, fmt.Errorf("read packages inventory: %w", err)
		}
	}
	metas, err := a.store.PackageMeta(ctx)
	if err != nil {
		return nil, err
	}
	tags, err := a.store.PackageTags(ctx)
	if err != nil {
		return nil, err
	}
	metas = packages.LocalMeta(d.Inventories, metas, r.FinishedAt)
	as := packages.Annotate(d.Inventories, metas, store.TagsByKey(tags), a.githubUser(ctx, false))
	return q.Filter(as), nil
}

// savedInventory loads the newest full packages inventory.
func (a *app) savedInventory(ctx context.Context) (*run.Run, []packages.Inventory, error) {
	r, err := a.engine.Saved(ctx, packages.Command, "")
	if err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, nil, fmt.Errorf("%w for audit packages; run `audit packages -r` first", core.ErrNoSavedRun)
	}
	var d packages.Data
	if err := json.Unmarshal(r.Data, &d); err != nil {
		return nil, nil, fmt.Errorf("read packages inventory: %w", err)
	}
	return r, d.Inventories, nil
}

// findOne resolves a package reference, failing when it matches none or
// several packages.
func findOne(invs []packages.Inventory, arg string) (packages.Package, error) {
	ref := packages.ParseRef(arg)
	found := ref.Find(invs)
	switch len(found) {
	case 0:
		return packages.Package{}, fmt.Errorf("no installed package matches %q", arg)
	case 1:
		return found[0], nil
	}
	keys := make([]string, len(found))
	for i, p := range found {
		keys[i] = p.Key()
	}
	return packages.Package{}, fmt.Errorf("%q matches %s; name one as manager:name", arg, strings.Join(keys, ", "))
}

func newPackagesRegistryCmd(a *app) *cobra.Command {
	var managers []string
	var force, aiTags, aiRetag, asJSON, list bool
	c := &cobra.Command{
		Use:   "registry [package...]",
		Short: "Look packages up in their registries and refresh the cache",
		Long: `Look installed packages up in their registries (PyPI, npm, crates.io, the
Go module proxy, rubygems.org and GitHub through gh), cache the latest
version, release date, description, repository, homepage, license, keywords,
deprecation and archive status, then rescan packages so findings and tasks
reflect the new data.

Entries younger than packages.registry.max_age are reused unless --force is
given; named packages are always looked up. A package may be named as
manager:name when the name is ambiguous.

--ai-tags asks the AI CLI (ai.provider) to tag packages that have not been tagged yet, from
the packages.tags vocabulary; --ai-retag tags them all again. Tags you
removed with audit packages tag -d are not put back without --ai-retag.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			s, err := a.packagesScanner(splitList(managers))
			if err != nil {
				return err
			}
			refs := parseRefs(args)
			s.Refresh = a.registryRefresh(refs, force)
			a.githubUser(ctx, true)
			res, err := a.engine.Execute(ctx, s, a.progress(!asJSON))
			if err != nil {
				return err
			}
			a.log.Info("scan saved", "command", res.Run.Command, "findings", len(res.Run.Findings), "tasks changed", res.TaskChanges)
			if !asJSON && !a.flags.quiet {
				for _, st := range res.Run.Stats {
					if st.Group == "registry" && st.Name == "looked up" {
						say(a.errOut, "registry: looked up %s\n", st.Value)
					}
				}
				if res.TaskChanges > 0 {
					say(a.errOut, "%d task(s) updated; see `audit todo --cmd %s`.\n", res.TaskChanges, packages.Command)
				}
			}
			if aiTags || aiRetag {
				if err := a.aiTag(ctx, res.Run, refs, aiRetag, !asJSON); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					say(a.errOut, "AI tagging failed: %v\n", err)
				}
			}
			view := func(ctx context.Context, p *render.Printer, r *run.Run) {
				if as, err := a.annotated(ctx, r, packages.Query{}); err == nil {
					p.Packages(as)
				}
			}
			f := &scanFlags{report: !list && !asJSON, list: list, json: asJSON,
				jsonExtra: func(ctx context.Context, r *run.Run) (any, error) { return a.annotated(ctx, r, packages.Query{}) }}
			return a.runScan(ctx, s, f, view)
		},
	}
	fl := c.Flags()
	fl.StringSliceVarP(&managers, "manager", "M", nil, "look up only these managers: "+strings.Join(packages.Names(), ", "))
	fl.BoolVarP(&force, "force", "F", false, "look everything up, ignoring the age of cached entries")
	fl.BoolVarP(&aiTags, "ai-tags", "a", false, "tag untagged packages through the AI CLI (ai.provider)")
	fl.BoolVarP(&aiRetag, "ai-retag", "A", false, "like --ai-tags, but tag every package again")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the run and the annotated inventory as JSON")
	fl.BoolVarP(&list, "list", "l", false, "print findings one per line plus the inventory")
	c.MarkFlagsMutuallyExclusive("json", "list")
	return c
}

// aiTag tags the packages of r that have registry data and, unless retag is
// set, no AI tags yet. refs limits it to named packages.
func (a *app) aiTag(ctx context.Context, r *run.Run, refs []packages.Ref, retag, showProgress bool) error {
	as, err := a.annotated(ctx, r, packages.Query{})
	if err != nil {
		return err
	}
	metas, err := a.store.PackageMeta(ctx)
	if err != nil {
		return err
	}
	var invs []packages.Inventory
	for _, an := range as {
		invs = append(invs, an.Inventory)
	}
	named := map[string]bool{}
	for _, ref := range refs {
		for _, p := range ref.Find(invs) {
			named[p.Key()] = true
		}
	}
	var todo []packages.Item
	seen := map[string]bool{}
	for _, an := range as {
		for _, it := range an.Items {
			k := it.Key()
			if it.Meta == nil || seen[k] || (len(refs) > 0 && !named[k]) || (!retag && !it.Meta.TaggedAt.IsZero()) {
				continue
			}
			seen[k] = true
			todo = append(todo, it)
		}
	}
	if len(todo) == 0 {
		if showProgress && !a.flags.quiet {
			sayln(a.errOut, "AI tagging: every package with registry data is tagged; use --ai-retag to tag again.")
		}
		return nil
	}
	client := a.aiClient("")
	rep := a.progress(showProgress)
	defer rep.Done()
	rep.Phase("asking the AI for tags", (len(todo)+aiTagBatch-1)/aiTagBatch)
	tagged := 0
	var updated []packages.Meta
	var errs []error
	for start := 0; start < len(todo); start += aiTagBatch {
		batch := todo[start:min(start+aiTagBatch, len(todo))]
		resp, err := client.Ask(ctx, llm.Request{System: packages.TagSystem, Prompt: packages.TagPrompt(batch, a.cfg.Packages.Tags)}, retag)
		rep.Step(fmt.Sprintf("%d package(s)", len(batch)))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			errs = append(errs, err)
			continue
		}
		answer, err := packages.ParseTagAnswer(resp.Text, batch, a.cfg.Packages.Tags)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		keys := make([]string, 0, len(answer))
		for k := range answer {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m := metas[k]
			if err := a.store.ReplaceAITags(ctx, m.Manager, m.ID, answer[k]); err != nil {
				return err
			}
			m.TaggedAt = timeNow()
			updated = append(updated, m)
			tagged++
		}
	}
	if err := a.store.SavePackageMeta(ctx, updated); err != nil {
		return err
	}
	rep.Done()
	if showProgress && !a.flags.quiet {
		say(a.errOut, "AI tagging: tagged %d of %d package(s).\n", tagged, len(todo))
	}
	return errors.Join(errs...)
}

func newPackagesInfoCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "info <package>",
		Short: "Show the cached registry details and tags of one package",
		Long: `Show what audit knows about one installed package: installed and latest
version, release age, description, repository, homepage, license, keywords,
deprecation, tags and where it was installed. Reads the saved inventory and
the registry cache; no scan or network access. Name the package as
manager:name when the name is ambiguous.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			r, invs, err := a.savedInventory(ctx)
			if err != nil {
				return err
			}
			p, err := findOne(invs, args[0])
			if err != nil {
				return err
			}
			it, tags, err := a.packageItem(ctx, r, p)
			if err != nil {
				return err
			}
			if asJSON {
				return a.writeJSON(struct {
					packages.Item
					StoredTags []packages.Tag `json:"stored_tags"`
				}{it, tags})
			}
			a.printer().PackageInfo(it, tags)
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the package as JSON")
	return c
}

// packageItem is p annotated, with its stored tags.
func (a *app) packageItem(ctx context.Context, r *run.Run, p packages.Package) (packages.Item, []packages.Tag, error) {
	as, err := a.annotated(ctx, r, packages.Query{})
	if err != nil {
		return packages.Item{}, nil, err
	}
	var it packages.Item
	for _, an := range as {
		for _, x := range an.Items {
			if x.Key() == p.Key() && it.Name == "" {
				it = x
			}
		}
	}
	all, err := a.store.PackageTags(ctx)
	if err != nil {
		return it, nil, err
	}
	tags := []packages.Tag{}
	for _, t := range all {
		if packages.MetaKey(t.Manager, t.ID) == p.Key() {
			tags = append(tags, t)
		}
	}
	return it, tags, nil
}

func newPackagesTagCmd(a *app) *cobra.Command {
	var del, asJSON bool
	c := &cobra.Command{
		Use:   "tag [package [tag...]]",
		Short: "List, add or remove package tags",
		Long: `Without arguments, list every tag in use with how many packages carry it.
With a package, show its tags; with a package and tags, add them as your
own tags, or remove them with --delete (whatever assigned them). Automatic
tags (manager, runtime, git, local, mine) are derived and cannot be removed.
Tags are lowercased and words joined with dashes. Filter the inventory by
tag with audit packages --tag.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			r, invs, err := a.savedInventory(ctx)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				if del {
					return errors.New("--delete needs a package and the tags to remove")
				}
				return a.listTags(ctx, r, asJSON)
			}
			p, err := findOne(invs, args[0])
			if err != nil {
				return err
			}
			var tags []string
			for _, t := range args[1:] {
				if t = packages.NormalizeTag(t); t != "" {
					tags = append(tags, t)
				}
			}
			switch {
			case del && len(tags) == 0:
				return errors.New("--delete needs the tags to remove")
			case del:
				n, err := a.store.RemovePackageTags(ctx, p.Manager, p.ID(), tags)
				if err != nil {
					return err
				}
				if n < len(tags) && !a.flags.quiet {
					say(a.errOut, "%d of %d tag(s) were not stored on %s (automatic tags cannot be removed).\n", len(tags)-n, len(tags), p.Key())
				}
			case len(tags) > 0:
				add := make([]packages.Tag, len(tags))
				for i, t := range tags {
					add[i] = packages.Tag{Manager: p.Manager, ID: p.ID(), Tag: t, Source: packages.TagUser}
				}
				if err := a.store.AddPackageTags(ctx, add); err != nil {
					return err
				}
			}
			it, stored, err := a.packageItem(ctx, r, p)
			if err != nil {
				return err
			}
			if asJSON {
				return a.writeJSON(struct {
					Key        string         `json:"key"`
					Tags       []string       `json:"tags"`
					StoredTags []packages.Tag `json:"stored_tags"`
				}{p.Key(), it.Tags, stored})
			}
			sayln(a.out, p.Key()+": "+strings.Join(it.Tags, " "))
			return nil
		},
	}
	c.Flags().BoolVarP(&del, "delete", "d", false, "remove the given tags instead of adding them")
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print as JSON")
	return c
}

type tagUse struct {
	Tag      string         `json:"tag"`
	Packages int            `json:"packages"`
	Sources  map[string]int `json:"sources"`
}

// listTags prints every tag on the saved inventory with its package count
// and where the tag came from.
func (a *app) listTags(ctx context.Context, r *run.Run, asJSON bool) error {
	as, err := a.annotated(ctx, r, packages.Query{})
	if err != nil {
		return err
	}
	stored, err := a.store.PackageTags(ctx)
	if err != nil {
		return err
	}
	source := map[string]string{}
	for _, t := range stored {
		source[packages.MetaKey(t.Manager, t.ID)+" "+t.Tag] = t.Source
	}
	uses := map[string]*tagUse{}
	seen := map[string]bool{}
	for _, an := range as {
		for _, it := range an.Items {
			if seen[it.Key()] {
				continue
			}
			seen[it.Key()] = true
			for _, t := range it.Tags {
				u := uses[t]
				if u == nil {
					u = &tagUse{Tag: t, Sources: map[string]int{}}
					uses[t] = u
				}
				src := source[it.Key()+" "+t]
				if src == "" {
					src = packages.TagAuto
				}
				u.Packages++
				u.Sources[src]++
			}
		}
	}
	out := make([]tagUse, 0, len(uses))
	for _, u := range uses {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packages != out[j].Packages {
			return out[i].Packages > out[j].Packages
		}
		return out[i].Tag < out[j].Tag
	})
	if asJSON {
		return a.writeJSON(out)
	}
	rows := make([][]string, len(out))
	for i, u := range out {
		var srcs []string
		for _, s := range []string{packages.TagAuto, packages.TagUser, packages.TagAI} {
			if n := u.Sources[s]; n > 0 {
				srcs = append(srcs, fmt.Sprintf("%s %d", s, n))
			}
		}
		rows[i] = []string{u.Tag, fmt.Sprint(u.Packages), strings.Join(srcs, ", ")}
	}
	a.printer().Table([]string{"TAG", "PACKAGES", "SOURCES"}, rows)
	return nil
}
