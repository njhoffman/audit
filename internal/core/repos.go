package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
)

// RepoMetaStore holds cached GitHub data (implemented by *store.Store).
type RepoMetaStore interface {
	RepoMeta(ctx context.Context) (map[string]repos.Meta, error)
	SaveRepoMeta(ctx context.Context, ms []repos.Meta) error
}

// ReposScanner finds and inspects git repositories.
type ReposScanner struct {
	Env         *exec.Env
	Options     repos.Options
	LinkDirs    []string
	GhqRoot     string
	Concurrency int
	StaleFetch  time.Duration
	User        string
	// Meta, when set, supplies the GitHub cache to the checks.
	Meta RepoMetaStore
	// Fetch runs git fetch in every repo with a remote before inspecting.
	Fetch        bool
	FetchTimeout time.Duration
	// Lookup, when set, refreshes GitHub data older than MetaMaxAge (all of
	// it with LookupForce).
	Lookup      bool
	LookupForce bool
	MetaMaxAge  time.Duration
	Now         time.Time
}

// NewRepos builds the repos scanner from the config.
func NewRepos(cfg *config.Config, env *exec.Env, user string) *ReposScanner {
	rc := cfg.Repos
	expand := func(ps []string) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = env.Expand(p)
		}
		return out
	}
	excl := make([]string, len(rc.Exclude))
	for i, e := range rc.Exclude {
		if strings.HasPrefix(e, "**/") {
			excl[i] = e
		} else {
			excl[i] = env.Expand(e)
		}
	}
	root := rc.GhqRoot
	if root == "" {
		if r := env.Run(context.Background(), "git", []string{"config", "--global", "--get", "ghq.root"},
			exec.Options{Timeout: 5 * time.Second}); r.OK() && strings.TrimSpace(r.Stdout) != "" {
			root = strings.TrimSpace(r.Stdout)
		} else {
			root = filepath.Join(env.Home, "ghq")
		}
	}
	root = env.Expand(root)
	if _, err := os.Stat(root); err != nil {
		root = ""
	}
	return &ReposScanner{Env: env, Options: repos.Options{Roots: expand(rc.Roots), Exclude: excl, MaxDepth: rc.MaxDepth},
		LinkDirs: expand(rc.LinkDirs), GhqRoot: root, Concurrency: rc.Concurrency, StaleFetch: rc.StaleFetch, User: user,
		FetchTimeout: rc.FetchTimeout, MetaMaxAge: rc.MetaMaxAge}
}

// Command implements Scanner.
func (*ReposScanner) Command() string { return repos.Command }

// Scope implements Scanner.
func (*ReposScanner) Scope() string { return "" }

// FetchEnv keeps git from prompting for credentials or host keys in the
// background.
func (s *ReposScanner) FetchEnv() *exec.Env {
	vars := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
	if s.Env.Get("GIT_SSH_COMMAND") == "" {
		vars["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
	}
	return s.Env.WithVars(vars)
}

// FetchAll runs git fetch --all --prune in each path, concurrency at a
// time, and returns one error line per failure.
func FetchAll(ctx context.Context, env *exec.Env, paths []string, concurrency int, timeout time.Duration, onDone func(string)) []string {
	var mu sync.Mutex
	var errs []string
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range max(1, concurrency) {
		wg.Go(func() {
			for p := range jobs {
				r := env.Run(ctx, "git", []string{"-C", p, "fetch", "--all", "--prune", "--quiet"}, exec.Options{Timeout: timeout})
				if !r.OK() && ctx.Err() == nil {
					line := strings.TrimSpace(r.Stderr)
					if i := strings.LastIndexByte(line, '\n'); i >= 0 {
						line = line[i+1:]
					}
					if r.Code == exec.ExitTimeout {
						line = "timed out after " + timeout.String()
					}
					mu.Lock()
					errs = append(errs, fmt.Sprintf("fetch %s: %s", p, line))
					mu.Unlock()
				}
				if onDone != nil {
					onDone(p)
				}
			}
		})
	}
	for _, p := range paths {
		if ctx.Err() != nil {
			break
		}
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return errs
}

// Scan implements Scanner.
func (s *ReposScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	now := s.Now
	if now.IsZero() {
		now = time.Now()
	}
	rep.Phase("finding repositories", 0)
	paths := repos.Discover(s.Options)
	var errs []string
	if s.Fetch {
		rep.Phase("fetching", len(paths))
		errs = append(errs, FetchAll(ctx, s.FetchEnv(), paths, s.Concurrency, s.FetchTimeout, func(p string) { rep.Step(filepath.Base(p)) })...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	rep.Phase("inspecting repositories", len(paths))
	rs := repos.InspectAll(ctx, s.Env, paths, s.Concurrency, func(r repos.Repo) { rep.Step(filepath.Base(r.Path)) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	links := repos.Links(s.LinkDirs)
	var metas map[string]repos.Meta
	if s.Meta != nil {
		var err error
		if metas, err = s.Meta.RepoMeta(ctx); err != nil {
			return nil, fmt.Errorf("load repo cache: %w", err)
		}
		if s.Lookup {
			n := 0
			for _, r := range rs {
				if r.OnGitHub() {
					n++
				}
			}
			rep.Phase("asking GitHub", n)
			updated := repos.LookupGitHub(ctx, s.Env, rs, metas, s.MetaMaxAge, s.LookupForce, now, func(k int) {
				for range k {
					rep.Step("")
				}
			})
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := s.Meta.SaveRepoMeta(ctx, updated); err != nil {
				return nil, fmt.Errorf("save repo cache: %w", err)
			}
			for _, m := range updated {
				metas[m.Key] = m
				if m.Error != "" {
					errs = append(errs, fmt.Sprintf("GitHub %s: %s", m.Key, m.Error))
				}
			}
		}
	}
	rep.Phase("checking repositories", 0)
	fs := repos.Analyze(&repos.State{Repos: rs, Links: links, Meta: metas, User: s.User, GhqRoot: s.GhqRoot,
		StaleFetch: s.StaleFetch, Now: now})
	data, err := json.Marshal(repos.Data{Repos: rs, Links: links})
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: fs, Stats: repoStats(rs, metas, s.User, now), Data: data, Errors: errs}, nil
}

func repoStats(rs []repos.Repo, metas map[string]repos.Meta, user string, now time.Time) []run.Stat {
	mine, dirty, behind, ahead, gh := 0, 0, 0, 0, 0
	var oldest time.Time
	for _, r := range rs {
		if r.Mine(user) {
			mine++
		}
		if !r.Clean() {
			dirty++
		}
		if r.Behind > 0 {
			behind++
		}
		if r.Ahead > 0 {
			ahead++
		}
		if r.OnGitHub() {
			gh++
			if m, ok := metas[r.Key()]; ok && (oldest.IsZero() || m.CheckedAt.Before(oldest)) {
				oldest = m.CheckedAt
			}
		}
	}
	checked := "never; run audit repos refresh"
	switch age := run.HumanAge(now.Sub(oldest)); {
	case oldest.IsZero():
	case age == "just now":
		checked = "just now"
	default:
		checked = "oldest " + age + " ago"
	}
	return []run.Stat{
		{Name: "repos", Value: fmt.Sprint(len(rs)), Note: fmt.Sprintf("%d mine", mine)},
		{Name: "local changes", Value: fmt.Sprint(dirty)},
		{Name: "unpushed", Value: fmt.Sprint(ahead)},
		{Name: "behind", Value: fmt.Sprint(behind)},
		{Group: "github", Name: "checked", Value: checked},
	}
}
