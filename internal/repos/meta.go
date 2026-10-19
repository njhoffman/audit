package repos

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Meta is what GitHub says about a repository, cached by Repo.Key.
type Meta struct {
	Key string `json:"key"`
	// FullName is owner/name as GitHub reports it now; it differs from the
	// remote when the repo was renamed or transferred (see Moved).
	FullName      string    `json:"full_name,omitempty"`
	Description   string    `json:"description,omitempty"`
	Homepage      string    `json:"homepage,omitempty"`
	Topics        []string  `json:"topics,omitempty"`
	Archived      bool      `json:"archived,omitempty"`
	Fork          bool      `json:"fork,omitempty"`
	Parent        string    `json:"parent,omitempty"`
	DefaultBranch string    `json:"default_branch,omitempty"`
	Stars         int       `json:"stars,omitempty"`
	PushedAt      time.Time `json:"pushed_at,omitzero"`
	// Moved is the new owner/name when GitHub redirects the remote's.
	Moved string `json:"moved,omitempty"`
	// Missing means GitHub knows no such repository (deleted, or private to
	// someone else).
	Missing   bool      `json:"missing,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
}

// OnGitHub reports whether r's remote is on github.com.
func (r Repo) OnGitHub() bool { return r.Host == "github.com" && r.Owner != "" && r.Name != "" }

// githubBatch is how many repositories one GraphQL query asks about.
const githubBatch = 50

const repoFields = `nameWithOwner description homepageUrl isArchived isFork parent { nameWithOwner }
defaultBranchRef { name } stargazerCount pushedAt repositoryTopics(first: 20) { nodes { topic { name } } }`

type ghRepo struct {
	NameWithOwner string `json:"nameWithOwner"`
	Description   string `json:"description"`
	HomepageURL   string `json:"homepageUrl"`
	IsArchived    bool   `json:"isArchived"`
	IsFork        bool   `json:"isFork"`
	Parent        *struct {
		NameWithOwner string `json:"nameWithOwner"`
	} `json:"parent"`
	DefaultBranchRef *struct {
		Name string `json:"name"`
	} `json:"defaultBranchRef"`
	StargazerCount int    `json:"stargazerCount"`
	PushedAt       string `json:"pushedAt"`
	Topics         struct {
		Nodes []struct {
			Topic struct {
				Name string `json:"name"`
			} `json:"topic"`
		} `json:"nodes"`
	} `json:"repositoryTopics"`
}

// GitHubQuery is one GraphQL query asking about every repo, aliased r0, r1...
func GitHubQuery(rs []Repo) string {
	var b strings.Builder
	b.WriteString("query {")
	for i, r := range rs {
		fmt.Fprintf(&b, " r%d: repository(owner: %q, name: %q) { %s }", i, r.Owner, r.Name, repoFields)
	}
	b.WriteString(" }")
	return b.String()
}

// ParseGitHub turns a GraphQL answer for rs into metas. A null repository
// with a NOT_FOUND error is Missing; other errors are recorded per repo.
func ParseGitHub(out string, rs []Repo, now time.Time) ([]Meta, error) {
	var resp struct {
		Data   map[string]*ghRepo `json:"data"`
		Errors []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Path    []any  `json:"path"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("unexpected answer from gh api graphql: %w", err)
	}
	errs := map[string]string{}
	notFound := map[string]bool{}
	for _, e := range resp.Errors {
		if len(e.Path) == 0 {
			continue
		}
		alias, _ := e.Path[0].(string)
		if e.Type == "NOT_FOUND" {
			notFound[alias] = true
		} else {
			errs[alias] = e.Message
		}
	}
	if resp.Data == nil && len(resp.Errors) > 0 && len(notFound) == 0 {
		return nil, fmt.Errorf("gh api graphql: %s", resp.Errors[0].Message)
	}
	out2 := make([]Meta, 0, len(rs))
	for i, r := range rs {
		alias := fmt.Sprintf("r%d", i)
		m := Meta{Key: r.Key(), CheckedAt: now}
		g := resp.Data[alias]
		switch {
		case g != nil:
			m.FullName, m.Description, m.Homepage = g.NameWithOwner, g.Description, g.HomepageURL
			m.Archived, m.Fork, m.Stars = g.IsArchived, g.IsFork, g.StargazerCount
			if g.Parent != nil {
				m.Parent = g.Parent.NameWithOwner
			}
			if g.DefaultBranchRef != nil {
				m.DefaultBranch = g.DefaultBranchRef.Name
			}
			if t, err := time.Parse(time.RFC3339, g.PushedAt); err == nil {
				m.PushedAt = t
			}
			for _, n := range g.Topics.Nodes {
				m.Topics = append(m.Topics, n.Topic.Name)
			}
			if !strings.EqualFold(g.NameWithOwner, r.Owner+"/"+r.Name) {
				m.Moved = g.NameWithOwner
			}
		case notFound[alias]:
			m.Missing = true
		case errs[alias] != "":
			m.Error = errs[alias]
		default:
			m.Error = "no answer from GitHub"
		}
		out2 = append(out2, m)
	}
	return out2, nil
}

// LookupGitHub asks GitHub about the github.com repos among rs whose cache
// entry is older than maxAge (all with force), in batches, and returns the
// new entries. A failed batch keeps the previous answers with the error
// noted.
func LookupGitHub(ctx context.Context, env *exec.Env, rs []Repo, cache map[string]Meta, maxAge time.Duration,
	force bool, now time.Time, onBatch func(int)) []Meta {
	var todo []Repo
	seen := map[string]bool{}
	for _, r := range rs {
		if !r.OnGitHub() || seen[r.Key()] {
			continue
		}
		seen[r.Key()] = true
		if m, ok := cache[r.Key()]; ok && !force && m.Error == "" && now.Sub(m.CheckedAt) < maxAge {
			continue
		}
		todo = append(todo, r)
	}
	var out []Meta
	for start := 0; start < len(todo); start += githubBatch {
		if ctx.Err() != nil {
			return out
		}
		batch := todo[start:min(start+githubBatch, len(todo))]
		res := env.Run(ctx, "gh", []string{"api", "graphql", "-f", "query=" + GitHubQuery(batch)},
			exec.Options{Timeout: 2 * time.Minute})
		metas, err := ParseGitHub(res.Stdout, batch, now)
		if err != nil {
			msg := err.Error()
			if res.Code == exec.ExitNotFound {
				msg = "gh not found"
			} else if s := firstLine(res.Stderr); s != "" {
				msg = s
			}
			for _, r := range batch {
				m := cache[r.Key()]
				m.Key, m.Error, m.CheckedAt = r.Key(), msg, now
				out = append(out, m)
			}
		} else {
			out = append(out, metas...)
		}
		if onBatch != nil {
			onBatch(len(batch))
		}
	}
	return out
}
