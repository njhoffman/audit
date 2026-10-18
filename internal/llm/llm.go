// Package llm asks the claude CLI (print mode) to review audit results.
// Responses are cached by a hash of the model and prompt, so re-rendering a
// report with unchanged findings costs nothing.
package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
)

// Cache stores responses by prompt hash. *store.Store implements it.
type Cache interface {
	CacheGet(ctx context.Context, hash string) (*store.CachedResponse, error)
	CachePut(ctx context.Context, hash string, c store.CachedResponse) error
}

// Client runs the claude CLI.
type Client struct {
	Runner  exec.Runner
	Command string // executable, "claude" by default
	Model   string
	Timeout time.Duration
	Cache   Cache // optional
	Now     func() time.Time
}

// Request is one prompt.
type Request struct {
	System string
	Prompt string
}

// Response is the model's answer.
type Response struct {
	Text      string
	Model     string
	CostUSD   float64
	Cached    bool
	CreatedAt time.Time
}

// Hash identifies a request for the cache.
func (c *Client) Hash(req Request) string {
	h := sha256.New()
	for _, part := range []string{c.Model, req.System, req.Prompt} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cliResult is the subset of `claude -p --output-format json` we read.
type cliResult struct {
	Type    string  `json:"type"`
	Subtype string  `json:"subtype"`
	IsError bool    `json:"is_error"`
	Result  string  `json:"result"`
	CostUSD float64 `json:"total_cost_usd"`
}

// Ask returns the cached answer for req unless refresh is set, and otherwise
// runs the CLI with tools disabled and the prompt on stdin.
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

	command := c.Command
	if command == "" {
		command = "claude"
	}
	args := []string{"-p", "--output-format", "json", "--tools", "", "--no-session-persistence"}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	if req.System != "" {
		args = append(args, "--system-prompt", req.System)
	}
	// CLAUDECODE marks a nested session; the review is a separate one-shot run.
	res := c.Runner.Run(ctx, command, args, exec.Options{Timeout: c.Timeout, Stdin: req.Prompt, Unset: []string{"CLAUDECODE"}})
	switch res.Code {
	case 0:
	case exec.ExitNotFound:
		return nil, fmt.Errorf("%s not found; install Claude Code or set ai.command", command)
	case exec.ExitTimeout:
		return nil, fmt.Errorf("%s timed out after %s (ai.timeout)", command, c.Timeout)
	default:
		if out, err := parse(res.Stdout); err == nil && out.Result != "" {
			return nil, fmt.Errorf("%s failed: %s", command, firstLine(out.Result))
		}
		return nil, fmt.Errorf("%s exited %d: %s", command, res.Code, firstLine(strings.TrimSpace(res.Stderr)))
	}
	out, err := parse(res.Stdout)
	if err != nil {
		return nil, err
	}
	if out.IsError || out.Subtype != "success" {
		return nil, fmt.Errorf("%s returned an error (%s): %s", command, out.Subtype, firstLine(out.Result))
	}
	resp := &Response{Text: strings.TrimSpace(out.Result), Model: c.Model, CostUSD: out.CostUSD, CreatedAt: now()}
	if resp.Text == "" {
		return nil, errors.New("empty response from " + command)
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
	if maxDetails <= 0 {
		maxDetails = DefaultMaxDetails
	}
	fs := make([]promptFinding, len(r.Findings))
	for i, f := range r.Findings {
		details := f.Details
		if len(details) > maxDetails {
			details = append(append([]string{}, details[:maxDetails]...),
				fmt.Sprintf("(%d more)", len(f.Details)-maxDetails))
		}
		fs[i] = promptFinding{Check: f.Check, Severity: f.Severity, Kind: f.Kind, Subject: f.Subject,
			Message: f.Message, Hint: f.Hint, Details: details}
	}
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
