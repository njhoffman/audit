// Package llm asks an AI CLI (claude in print mode, or codex exec) to review
// audit results. Responses are cached by a hash of the provider, model and
// prompt, so re-rendering a report with unchanged findings costs nothing.
package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
)

// Providers.
const (
	Claude = "claude"
	Codex  = "codex"
)

// Cache stores responses by prompt hash. *store.Store implements it.
type Cache interface {
	CacheGet(ctx context.Context, hash string) (*store.CachedResponse, error)
	CachePut(ctx context.Context, hash string, c store.CachedResponse) error
}

// Client runs an AI CLI.
type Client struct {
	Runner exec.Runner
	// Provider is Claude (the default) or Codex.
	Provider string
	Command  string // executable; the provider's name by default
	Model    string // "" uses the CLI's default
	Timeout  time.Duration
	Cache    Cache // optional
	Now      func() time.Time
}

// Request is one prompt.
type Request struct {
	System string
	Prompt string
	// Schema, when set, is a JSON Schema the answer must match; the answer's
	// Text is then that JSON document.
	Schema string
}

// Response is the model's answer.
type Response struct {
	Text      string
	Model     string
	CostUSD   float64
	Cached    bool
	CreatedAt time.Time
}

func (c *Client) provider() string {
	if c.Provider == Codex {
		return Codex
	}
	return Claude
}

func (c *Client) command() string {
	if c.Command != "" {
		return c.Command
	}
	return c.provider()
}

// Label names the provider and model for display ("codex", "claude
// claude-sonnet-5-5").
func (c *Client) Label() string {
	if c.Model == "" {
		return c.provider()
	}
	return c.provider() + " " + c.Model
}

// Hash identifies a request for the cache. Claude requests hash as they did
// before providers existed, so their cache entries stay valid.
func (c *Client) Hash(req Request) string {
	h := sha256.New()
	parts := []string{c.Model, req.System, req.Prompt}
	if c.provider() != Claude {
		parts = append([]string{c.provider()}, parts...)
	}
	if req.Schema != "" {
		parts = append(parts, req.Schema)
	}
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cliResult is the subset of `claude -p --output-format json` we read.
type cliResult struct {
	Type       string          `json:"type"`
	Subtype    string          `json:"subtype"`
	IsError    bool            `json:"is_error"`
	Result     string          `json:"result"`
	Structured json.RawMessage `json:"structured_output"`
	CostUSD    float64         `json:"total_cost_usd"`
}

// Ask returns the cached answer for req unless refresh is set, and otherwise
// runs the CLI: claude with tools disabled, codex in its read-only sandbox
// from an empty directory. The prompt goes on stdin.
func (c *Client) Ask(ctx context.Context, req Request, refresh bool) (*Response, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	hash := c.Hash(req)
	if c.Cache != nil && !refresh {
		hit, err := c.Cache.CacheGet(ctx, hash)
		if err != nil {
			return nil, fmt.Errorf("read ai cache: %w", err)
		}
		if hit != nil {
			return &Response{Text: hit.Text, Model: hit.Model, CostUSD: hit.CostUSD, Cached: true, CreatedAt: hit.CreatedAt}, nil
		}
	}
	var resp *Response
	var err error
	if c.provider() == Codex {
		resp, err = c.askCodex(ctx, req)
	} else {
		resp, err = c.askClaude(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	// Claude answers keep the bare model name they were saved with before
	// providers existed; codex answers name the provider.
	resp.Model, resp.CreatedAt = c.Model, now()
	if c.provider() != Claude {
		resp.Model = c.Label()
	}
	if resp.Text == "" {
		return nil, errors.New("empty response from " + c.command())
	}
	if c.Cache != nil {
		err := c.Cache.CachePut(ctx, hash, store.CachedResponse{Model: resp.Model, Text: resp.Text,
			CostUSD: resp.CostUSD, CreatedAt: resp.CreatedAt})
		if err != nil {
			return resp, fmt.Errorf("write ai cache: %w", err)
		}
	}
	return resp, nil
}

// AskJSON asks req, which must carry a Schema, and decodes the answer into v.
func (c *Client) AskJSON(ctx context.Context, req Request, refresh bool, v any) (*Response, error) {
	if req.Schema == "" {
		return nil, errors.New("AskJSON needs a schema")
	}
	resp, err := c.Ask(ctx, req, refresh)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(stripFence(resp.Text)), v); err != nil {
		return resp, fmt.Errorf("%s did not answer with the expected JSON: %w", c.command(), err)
	}
	return resp, nil
}

// stripFence removes a markdown code fence around a JSON answer.
func stripFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "```"))
}

func (c *Client) runError(res exec.Result, hint string) error {
	command := c.command()
	switch res.Code {
	case exec.ExitNotFound:
		return fmt.Errorf("%s not found; %s", command, hint)
	case exec.ExitTimeout:
		return fmt.Errorf("%s timed out after %s (ai.timeout)", command, c.Timeout)
	}
	return fmt.Errorf("%s exited %d: %s", command, res.Code, firstLine(strings.TrimSpace(res.Stderr)))
}

func (c *Client) askClaude(ctx context.Context, req Request) (*Response, error) {
	command := c.command()
	args := []string{"-p", "--output-format", "json", "--tools", "", "--no-session-persistence"}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	if req.System != "" {
		args = append(args, "--system-prompt", req.System)
	}
	if req.Schema != "" {
		args = append(args, "--json-schema", req.Schema)
	}
	// CLAUDECODE marks a nested session; the review is a separate one-shot run.
	res := c.Runner.Run(ctx, command, args, exec.Options{Timeout: c.Timeout, Stdin: req.Prompt, Unset: []string{"CLAUDECODE"}})
	if res.Code != 0 {
		if out, err := parse(res.Stdout); err == nil && out.Result != "" && res.Code > 0 {
			return nil, fmt.Errorf("%s failed: %s", command, firstLine(out.Result))
		}
		return nil, c.runError(res, "install Claude Code or set ai.claude.command")
	}
	out, err := parse(res.Stdout)
	if err != nil {
		return nil, err
	}
	if out.IsError || out.Subtype != "success" {
		return nil, fmt.Errorf("%s returned an error (%s): %s", command, out.Subtype, firstLine(out.Result))
	}
	text := strings.TrimSpace(out.Result)
	if len(out.Structured) > 0 && string(out.Structured) != "null" {
		text = string(out.Structured)
	}
	return &Response{Text: text, CostUSD: out.CostUSD}, nil
}

// SessionCommand starts the CLI interactively with prompt as the first
// message: claude with its usual permission prompts, codex with its default
// approvals. The caller attaches it to the terminal. CLAUDECODE is removed
// so a session started from inside Claude Code is not taken as nested.
func (c *Client) SessionCommand(ctx context.Context, prompt string) *osexec.Cmd {
	var args []string
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	args = append(args, "--", prompt)
	cmd := osexec.CommandContext(ctx, c.command(), args...) // #nosec G204 -- the configured AI CLI
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLAUDECODE=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

// codexPreamble keeps codex, an agent with a shell, answering from the data
// it is given.
const codexPreamble = "Answer from the data in this message only. Do not run commands, read files or browse."

func (c *Client) askCodex(ctx context.Context, req Request) (*Response, error) {
	dir, err := os.MkdirTemp("", "audit-codex-")
	if err != nil {
		return nil, fmt.Errorf("codex work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	last := filepath.Join(dir, "answer.txt")
	args := []string{"exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral", "--color", "never",
		"--cd", dir, "--output-last-message", last}
	if req.Schema != "" {
		schema := filepath.Join(dir, "schema.json")
		if err := os.WriteFile(schema, []byte(req.Schema), 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--output-schema", schema)
	}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	args = append(args, "-")
	prompt := codexPreamble + "\n\n"
	if req.System != "" {
		prompt += req.System + "\n\n"
	}
	prompt += req.Prompt
	res := c.Runner.Run(ctx, c.command(), args, exec.Options{Timeout: c.Timeout, Stdin: prompt, Dir: dir})
	if res.Code != 0 {
		return nil, c.runError(res, "install Codex or set ai.codex.command")
	}
	text := ""
	if b, err := os.ReadFile(last); err == nil { // #nosec G304 -- our temp file
		text = strings.TrimSpace(string(b))
	}
	if text == "" {
		text = strings.TrimSpace(res.Stdout)
	}
	return &Response{Text: text}, nil
}

func parse(stdout string) (cliResult, error) {
	var out cliResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); err != nil {
		return out, fmt.Errorf("unexpected claude output: %w", err)
	}
	return out, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 300 {
		line = line[:300] + "..."
	}
	return line
}

// Levels are the accepted analysis depths.
var Levels = []string{"brief", "standard", "deep"}

// NormalizeLevel maps level spellings to brief, standard or deep.
func NormalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "brief", "summary", "short":
		return "brief"
	case "deep", "detailed", "thorough":
		return "deep"
	}
	return "standard"
}

func systemPrompt(command, level string) string {
	base := "You review the output of `audit " + command + "`, a tool that audits a single Linux workstation " +
		"for its owner. You receive its findings and summary statistics as JSON. Identify the problems that " +
		"matter, group findings that share a root cause, propose concrete fixes (commands or config edits " +
		"where possible), and point out improvements to structure or redundancy the checks hint at. Ignore " +
		"noise. Answer in markdown with short headings and bullet lists. Do not use emojis."
	switch NormalizeLevel(level) {
	case "brief":
		return base + " Keep it under 250 words: a one-line verdict, then the few items worth acting on."
	case "deep":
		return base + " Be thorough: for each significant finding explain the likely cause, impact and " +
			"remediation steps, and cross-reference related findings."
	}
	return base + " Be balanced: cover what matters without padding, roughly 300 to 600 words."
}

// DefaultMaxDetails bounds detail lines per finding in the prompt.
const DefaultMaxDetails = 10

type promptFinding struct {
	Check    string           `json:"check"`
	Severity finding.Severity `json:"severity"`
	Kind     finding.Kind     `json:"kind"`
	Subject  string           `json:"subject,omitempty"`
	Message  string           `json:"message,omitempty"`
	Hint     string           `json:"hint,omitempty"`
	Details  []string         `json:"details,omitempty"`
}

// AnalysisRequest builds the review prompt for a run. It leaves out
// timestamps and run ids so unchanged results hash to the same cache entry.
// maxDetails caps detail lines per finding; 0 uses DefaultMaxDetails.
func AnalysisRequest(r *run.Run, level string, maxDetails int) Request {
	fs := capFindings(r.Findings, maxDetails)
	payload := struct {
		Command  string          `json:"command"`
		Scope    string          `json:"scope,omitempty"`
		Stats    []run.Stat      `json:"stats,omitempty"`
		Errors   []string        `json:"scan_errors,omitempty"`
		Ignored  int             `json:"ignored_by_user,omitempty"`
		Findings []promptFinding `json:"findings"`
	}{r.Command, r.Scope, r.Stats, r.Errors, r.Ignored, fs}
	b, _ := json.MarshalIndent(payload, "", " ")
	var sb strings.Builder
	fmt.Fprintf(&sb, "Review these `audit %s` results (analysis level: %s).\n\n", r.Command, NormalizeLevel(level))
	sb.WriteString("```json\n")
	sb.Write(b)
	sb.WriteString("\n```\n")
	return Request{System: systemPrompt(r.Command, level), Prompt: sb.String()}
}
