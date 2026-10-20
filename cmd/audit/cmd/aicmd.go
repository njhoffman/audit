package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/ai"
	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
)

func newAICmd(a *app) *cobra.Command {
	var ping bool
	c, f := scanCommand(a, "ai", "Check AI tools, MCP servers and AI projects",
		`Report the AI tooling of this workstation:

  tools        claude, codex, gh copilot, aichat and ollama: installed,
               version, logged in (claude auth status, codex login status),
               ollama's local server and models
  keys         provider API keys in the environment, by name only
  MCP servers  from ~/.claude.json (user and per project), ~/.codex/config.toml
               and mcphub; ai.mcp_missing when a server's command is not
               installed, so it cannot start
  config       Claude Code hooks whose program or script is missing
               (ai.hook_broken), allow rules that let Claude run anything
               (ai.permissions_broad), CLAUDE.md files over
               ai.instruction_limit_kb (ai.instructions_large), unreadable
               configs (ai.config_syntax)
  projects     repos under repos.roots with CLAUDE.md, .claude, AGENTS.md,
               .mcp.json, .cursor, GEMINI.md or copilot instructions, plus
               every directory Claude Code has sessions for: markers, git
               branch and changes, instruction size, commands, skills,
               agents, MCP servers, session count and last session;
               ai.stale_sessions when the project is gone

Nothing is sent to a provider unless --ping is given: then one tiny request
per logged-in CLI (and ollama's version endpoint) checks that it answers.`,
		func() (core.Scanner, error) { return a.aiScanner(ping), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) {
			var d ai.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				a.log.Warn("read ai data", "err", err)
				return
			}
			a.printAI(p, d)
		})
	c.Flags().BoolVarP(&ping, "ping", "p", false, "send one tiny request to each logged-in provider (implies --rescan)")
	f.jsonExtra = func(_ context.Context, r *run.Run) (any, error) {
		var d ai.Data
		err := json.Unmarshal(r.Data, &d)
		return d, err
	}
	pre := c.PreRunE
	c.PreRunE = func(cmd *cobra.Command, args []string) error {
		if ping {
			f.rescan = true
		}
		if pre != nil {
			return pre(cmd, args)
		}
		return nil
	}
	return c
}

func (a *app) aiScanner(ping bool) *core.AIScanner {
	rc := a.cfg.Repos
	expand := func(ps []string) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = a.env.Expand(p)
		}
		return out
	}
	excl := make([]string, len(rc.Exclude))
	for i, e := range rc.Exclude {
		if strings.HasPrefix(e, "**/") {
			excl[i] = e
		} else {
			excl[i] = a.env.Expand(e)
		}
	}
	o := ai.Options{Env: a.env, Repos: repos.Options{Roots: expand(rc.Roots), Exclude: excl, MaxDepth: rc.MaxDepth},
		InstructionLimit: a.cfg.AI.InstructionLimitKB << 10}
	if ping {
		o.Ping = a.pingProvider
	}
	return &core.AIScanner{Options: o}
}

// pingProvider sends one tiny uncached request and times it.
func (a *app) pingProvider(ctx context.Context, p ai.Provider) (time.Duration, error) {
	start := time.Now()
	switch p.Name {
	case "claude", "codex":
		_, pc := a.cfg.AI.For(p.Name)
		c := &llm.Client{Runner: exec.NewOSRunner(a.env), Provider: p.Name, Command: pc.Command, Model: pc.Model,
			Timeout: 90 * time.Second}
		resp, err := c.Ask(ctx, llm.Request{Prompt: "Reply with the single word OK."}, true)
		if err != nil {
			return 0, err
		}
		if !strings.Contains(strings.ToUpper(resp.Text), "OK") {
			return 0, fmt.Errorf("unexpected answer %q", firstWords(resp.Text))
		}
	case "ollama":
		c := http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ai.OllamaURL+"/api/version", nil)
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	default:
		return 0, errors.New("no test request for " + p.Name)
	}
	return time.Since(start), nil
}

func firstWords(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func (a *app) printAI(p *render.Printer, d ai.Data) {
	home := a.env.Home
	var rows [][]string
	for _, pr := range d.Providers {
		detail := pr.Detail
		if pr.Kind == "key" {
			detail = ""
		}
		if pr.Ping != "" {
			detail = strings.TrimSpace(detail + "  ping: " + pr.Ping)
		}
		rows = append(rows, []string{pr.Name, pr.Kind, pr.Status(), pr.Version, detail})
	}
	p.Table([]string{"TOOL", "KIND", "STATUS", "VERSION", "DETAIL"}, rows)
	rows = nil
	for _, s := range d.MCP {
		target := s.Command
		if target == "" {
			target = s.URL
		}
		state := "ok"
		if !s.Found {
			state = "missing " + s.Command
		}
		rows = append(rows, []string{s.Name, s.Source, state, target})
	}
	if len(rows) > 0 {
		sayln(a.out)
		p.Table([]string{"MCP SERVER", "CONFIGURED IN", "STATE", "RUNS"}, rows)
	}
	rows = nil
	now := timeNow()
	for _, pr := range d.Projects {
		last := "-"
		if !pr.LastSession.IsZero() {
			last = ago(now.Sub(pr.LastSession))
		}
		state := ""
		switch {
		case !pr.Exists:
			state = "gone"
		case pr.Git && pr.Dirty > 0:
			state = fmt.Sprintf("%s, %d changed", pr.Branch, pr.Dirty)
		case pr.Git:
			state = pr.Branch
		default:
			state = "no git"
		}
		extras := []string{}
		if pr.Commands > 0 {
			extras = append(extras, fmt.Sprintf("%d cmd", pr.Commands))
		}
		if pr.Skills > 0 {
			extras = append(extras, fmt.Sprintf("%d skill", pr.Skills))
		}
		if pr.Agents > 0 {
			extras = append(extras, fmt.Sprintf("%d agent", pr.Agents))
		}
		if len(pr.MCP) > 0 {
			extras = append(extras, "mcp: "+strings.Join(pr.MCP, ","))
		}
		instr := "-"
		if pr.InstructionBytes > 0 {
			instr = files.Human(pr.InstructionBytes)
		}
		rows = append(rows, []string{shortPath(pr.Path, home), state, pr.Tools(), instr, fmt.Sprint(pr.Sessions), last, strings.Join(extras, " ")})
	}
	if len(rows) > 0 {
		sayln(a.out)
		p.Table([]string{"PROJECT", "GIT", "MARKERS", "INSTRUCTIONS", "SESSIONS", "LAST", "EXTRAS"}, rows)
	}
}

// ago is "3d ago", or "just now".
func ago(d time.Duration) string {
	if h := run.HumanAge(d); h != "just now" {
		return h + " ago"
	}
	return "just now"
}
