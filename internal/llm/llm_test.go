package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
)

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type memCache struct {
	m      map[string]store.CachedResponse
	getErr error
	puts   int
}

func (c *memCache) CacheGet(_ context.Context, hash string) (*store.CachedResponse, error) {
	if c.getErr != nil {
		return nil, c.getErr
	}
	if v, ok := c.m[hash]; ok {
		return &v, nil
	}
	return nil, nil
}

func (c *memCache) CachePut(_ context.Context, hash string, v store.CachedResponse) error {
	if c.m == nil {
		c.m = map[string]store.CachedResponse{}
	}
	c.m[hash] = v
	c.puts++
	return nil
}

const okJSON = `{"type":"result","subtype":"success","is_error":false,"result":"## Verdict\n\nfine","total_cost_usd":0.012}`

func client(f *exec.Fake, cache Cache) *Client {
	return &Client{Runner: f, Model: "sonnet", Timeout: time.Minute, Cache: cache, Now: func() time.Time { return now }}
}

func TestAskRunsCLIAndCaches(t *testing.T) {
	f := &exec.Fake{}
	f.AddOutput(okJSON, "claude", "-p")
	cache := &memCache{}
	c := client(f, cache)
	req := Request{System: "sys", Prompt: "payload"}

	resp, err := c.Ask(context.Background(), req, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "## Verdict\n\nfine" || resp.CostUSD != 0.012 || resp.Cached || resp.Model != "sonnet" || !resp.CreatedAt.Equal(now) {
		t.Errorf("resp %+v", resp)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("calls %v", f.Calls)
	}
	argv := strings.Join(f.Calls[0], " ")
	for _, w := range []string{"-p", "--output-format json", "--model sonnet", "--system-prompt sys", "--no-session-persistence"} {
		if !strings.Contains(argv, w) {
			t.Errorf("argv %q missing %q", argv, w)
		}
	}
	if strings.Contains(argv, "payload") {
		t.Error("prompt must go through stdin, not argv")
	}
	opts := f.CallOpts[0]
	if opts.Stdin != "payload" || opts.Timeout != time.Minute {
		t.Errorf("opts %+v", opts)
	}
	if cache.puts != 1 {
		t.Errorf("puts %d", cache.puts)
	}

	again, err := c.Ask(context.Background(), req, false)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Cached || again.Text != resp.Text || len(f.Calls) != 1 {
		t.Errorf("second ask should hit cache: %+v calls=%d", again, len(f.Calls))
	}

	if _, err := c.Ask(context.Background(), req, true); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 2 {
		t.Error("refresh should bypass the cache")
	}
}

func TestAskWithoutCache(t *testing.T) {
	f := &exec.Fake{}
	f.AddOutput(okJSON, "claude")
	c := client(f, nil)
	c.Model = ""
	if _, err := c.Ask(context.Background(), Request{Prompt: "x"}, false); err != nil {
		t.Fatal(err)
	}
	if argv := strings.Join(f.Calls[0], " "); strings.Contains(argv, "--model") || strings.Contains(argv, "--system-prompt") {
		t.Errorf("empty model/system should be omitted: %q", argv)
	}
}

func TestAskErrors(t *testing.T) {
	cases := []struct {
		name string
		res  *exec.Result
		want string
	}{
		{"missing", nil, "claude not found"},
		{"timeout", &exec.Result{Code: exec.ExitTimeout}, "timed out after 1m0s"},
		{"exit with json", &exec.Result{Code: 1, Stdout: `{"is_error":true,"result":"Credit balance is too low"}`}, "failed: Credit balance is too low"},
		{"exit with stderr", &exec.Result{Code: 2, Stderr: "bad flag\nusage"}, "exited 2: bad flag"},
		{"is_error", &exec.Result{Stdout: `{"subtype":"error_max_turns","is_error":true,"result":"stopped"}`}, "returned an error (error_max_turns): stopped"},
		{"garbage", &exec.Result{Stdout: "not json"}, "unexpected claude output"},
		{"empty", &exec.Result{Stdout: `{"subtype":"success","result":"  "}`}, "empty response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &exec.Fake{}
			if tc.res != nil {
				f.Add([]string{"claude"}, *tc.res)
			}
			cache := &memCache{}
			_, err := client(f, cache).Ask(context.Background(), Request{Prompt: "p"}, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
			if cache.puts != 0 {
				t.Error("failures must not be cached")
			}
		})
	}
}

func TestAskCacheReadError(t *testing.T) {
	f := &exec.Fake{}
	c := client(f, &memCache{getErr: errors.New("locked")})
	if _, err := c.Ask(context.Background(), Request{Prompt: "p"}, false); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("err %v", err)
	}
	if len(f.Calls) != 0 {
		t.Error("should not run the CLI after a cache error")
	}
}

func TestHashDependsOnModelAndPrompt(t *testing.T) {
	a := &Client{Model: "a"}
	b := &Client{Model: "b"}
	req := Request{System: "s", Prompt: "p"}
	if a.Hash(req) == b.Hash(req) {
		t.Error("model should change the hash")
	}
	if a.Hash(req) == a.Hash(Request{System: "s", Prompt: "q"}) {
		t.Error("prompt should change the hash")
	}
	// The separator keeps boundaries distinct.
	if a.Hash(Request{System: "ab", Prompt: "c"}) == a.Hash(Request{System: "a", Prompt: "bc"}) {
		t.Error("field boundaries should matter")
	}
}

func TestNormalizeLevel(t *testing.T) {
	for _, c := range []struct{ in, want string }{{"summary", "brief"}, {"Brief", "brief"}, {"short", "brief"},
		{"thorough", "deep"}, {" DEEP ", "deep"}, {"detailed", "deep"}, {"", "standard"}, {"weird", "standard"}} {
		if got := NormalizeLevel(c.in); got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestAnalysisRequest(t *testing.T) {
	details := make([]string, 15)
	for i := range details {
		details[i] = "line"
	}
	r := &run.Run{Command: "system", Host: "box", StartedAt: now, FinishedAt: now, ID: 42,
		Stats: []run.Stat{{Name: "total", Value: "3"}},
		Findings: []finding.Finding{{Command: "system", Check: "logs.oom_kill", Severity: finding.Error,
			Kind: finding.Issue, Subject: "journal", Message: "OOM", Details: details}}}
	req := AnalysisRequest(r, "summary", 0)
	if !strings.Contains(req.System, "audit system") || !strings.Contains(req.System, "under 250 words") {
		t.Errorf("system %q", req.System)
	}
	for _, w := range []string{"analysis level: brief", `"check": "logs.oom_kill"`, `"(5 more)"`, `"total"`} {
		if !strings.Contains(req.Prompt, w) {
			t.Errorf("prompt missing %q:\n%s", w, req.Prompt)
		}
	}
	if strings.Count(req.Prompt, `"line"`) != DefaultMaxDetails {
		t.Errorf("details should be capped at %d", DefaultMaxDetails)
	}
	if strings.Contains(req.Prompt, "box") || strings.Contains(req.Prompt, "2026") {
		t.Error("prompt should not include host or timestamps")
	}

	// A later run with identical findings must produce the same request.
	r2 := *r
	r2.ID, r2.StartedAt, r2.FinishedAt = 43, now.Add(time.Hour), now.Add(time.Hour)
	if AnalysisRequest(&r2, "summary", 0) != req {
		t.Error("request should be stable across runs with identical findings")
	}
	if len(r.Findings[0].Details) != 15 {
		t.Error("input details mutated")
	}
}
