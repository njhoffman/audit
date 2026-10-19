package repos

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

func TestGitHubQueryAndParse(t *testing.T) {
	rs := []Repo{
		{Host: "github.com", Owner: "o", Name: "a"},
		{Host: "github.com", Owner: "o", Name: "old"},
		{Host: "github.com", Owner: "o", Name: "gone"},
		{Host: "github.com", Owner: "o", Name: "err"},
	}
	q := GitHubQuery(rs)
	if !strings.Contains(q, `r0: repository(owner: "o", name: "a")`) || !strings.Contains(q, `r3: repository(owner: "o", name: "err")`) {
		t.Errorf("query: %s", q)
	}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	out := `{"data":{
	 "r0":{"nameWithOwner":"o/a","description":"A","isArchived":true,"isFork":true,"parent":{"nameWithOwner":"up/a"},
	       "defaultBranchRef":{"name":"main"},"stargazerCount":3,"pushedAt":"2026-10-01T00:00:00Z",
	       "repositoryTopics":{"nodes":[{"topic":{"name":"cli"}}]}},
	 "r1":{"nameWithOwner":"o2/new","defaultBranchRef":null,"repositoryTopics":{"nodes":[]}},
	 "r2":null,"r3":null},
	 "errors":[{"type":"NOT_FOUND","path":["r2"],"message":"Could not resolve"},{"type":"FORBIDDEN","path":["r3"],"message":"SAML"}]}`
	ms, err := ParseGitHub(out, rs, now)
	if err != nil || len(ms) != 4 {
		t.Fatalf("%+v %v", ms, err)
	}
	if m := ms[0]; m.Key != "github.com/o/a" || !m.Archived || !m.Fork || m.Parent != "up/a" || m.DefaultBranch != "main" ||
		m.Stars != 3 || m.Topics[0] != "cli" || m.Moved != "" || !m.CheckedAt.Equal(now) || m.PushedAt.IsZero() {
		t.Errorf("a: %+v", m)
	}
	if ms[1].Moved != "o2/new" || !ms[2].Missing || ms[3].Error != "SAML" || ms[3].Missing {
		t.Errorf("moved/missing/error: %+v %+v %+v", ms[1], ms[2], ms[3])
	}
	if _, err := ParseGitHub("not json", rs, now); err == nil {
		t.Error("bad output")
	}
	if _, err := ParseGitHub(`{"errors":[{"message":"Bad credentials"}]}`, rs, now); err == nil || !strings.Contains(err.Error(), "Bad credentials") {
		t.Errorf("a failed query: %v", err)
	}
}

func TestLookupGitHub(t *testing.T) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	var rs []Repo
	for i := range 55 {
		rs = append(rs, Repo{Host: "github.com", Owner: "o", Name: fmt.Sprintf("r%d", i)})
	}
	rs = append(rs, Repo{Host: "gitlab.com", Owner: "o", Name: "x"}, rs[0])
	cache := map[string]Meta{
		"github.com/o/r0": {Key: "github.com/o/r0", CheckedAt: now.Add(-time.Hour)},
		"github.com/o/r1": {Key: "github.com/o/r1", CheckedAt: now.Add(-48 * time.Hour), Description: "kept"},
	}
	fake := &exec.Fake{}
	fake.Add([]string{"gh", "api", "graphql"}, exec.Result{Code: 1, Stderr: "HTTP 502: Bad gateway"})
	var batches []int
	ms := LookupGitHub(ctx, &exec.Env{Vars: map[string]string{}, Runner: fake}, rs, cache, 24*time.Hour, false, now,
		func(n int) { batches = append(batches, n) })
	if len(fake.Calls) != 2 || len(batches) != 2 || batches[0] != 50 || batches[1] != 4 || len(ms) != 54 {
		t.Fatalf("54 stale github repos in 2 batches: calls %d batches %v metas %d", len(fake.Calls), batches, len(ms))
	}
	for _, m := range ms {
		if m.Key == "github.com/o/r1" && (m.Description != "kept" || m.Error != "HTTP 502: Bad gateway") {
			t.Errorf("a failed batch keeps the old answer: %+v", m)
		}
	}
	fake.Calls = nil
	LookupGitHub(ctx, &exec.Env{Vars: map[string]string{}, Runner: fake}, rs[:1], cache, 24*time.Hour, true, now, nil)
	if len(fake.Calls) != 1 {
		t.Errorf("force: %v", fake.Calls)
	}
}
