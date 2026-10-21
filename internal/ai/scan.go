package ai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
)

// Options configure Scan.
type Options struct {
	Env *exec.Env
	// Repos are where projects are searched for (repos.roots).
	Repos repos.Options
	// Ping, when set, sends one tiny request to a provider and returns
	// how long it took; nil skips --ping.
	Ping func(ctx context.Context, p Provider) (time.Duration, error)
	// InstructionLimit is the size past which an instruction file is
	// reported as large.
	InstructionLimit int64
}

// Data is what an ai run stores.
type Data struct {
	Providers []Provider  `json:"providers"`
	MCP       []MCPServer `json:"mcp"`
	Hooks     []Hook      `json:"hooks,omitempty"`
	Projects  []Project   `json:"projects"`
}

func mk(check string, sev finding.Severity, subject, msg, hint string) finding.Finding {
	return finding.Finding{Command: Command, Check: "ai." + check, Kind: finding.Issue, Severity: sev, Subject: subject,
		Message: msg, Hint: hint}
}

// Scan gathers the AI tooling state and checks it.
func Scan(ctx context.Context, o Options, rep progress.Reporter) (*Data, []finding.Finding, []run.Stat, []string, error) {
	env := o.Env
	d := &Data{}
	var out []finding.Finding
	var errs []string

	rep.Phase("checking AI tools", 0)
	d.Providers = Providers(ctx, env)
	for i := range d.Providers {
		p := &d.Providers[i]
		if p.Installed && p.LoggedIn != nil && !*p.LoggedIn && p.Kind == "cli" {
			out = append(out, mk("not_logged_in", finding.Notice, p.Name, p.Name+" is installed but not logged in", "Log in with "+p.Name+"'s own login command."))
		}
		if p.Name == "ollama" && p.LoggedIn != nil && !*p.LoggedIn {
			out = append(out, mk("ollama_down", finding.Info, "ollama", "ollama is installed but its server is not running", "systemctl start ollama, or ollama serve"))
		}
		if o.Ping != nil && p.Installed && p.Kind != "key" && (p.LoggedIn == nil || *p.LoggedIn) && p.Name != "gh copilot" && p.Name != "aichat" {
			rep.Phase("pinging "+p.Name, 0)
			dur, err := o.Ping(ctx, *p)
			if err != nil {
				p.Ping = err.Error()
				out = append(out, mk("ping_failed", finding.Warning, p.Name, p.Name+" did not answer a test request: "+err.Error(), ""))
			} else {
				p.Ping, p.PingOK = "ok in "+dur.Round(100*time.Millisecond).String(), true
			}
		}
	}

	rep.Phase("reading MCP servers", 0)
	mcp, merrs := MCPServers(env)
	d.MCP = mcp
	for _, e := range merrs {
		out = append(out, mk("config_syntax", finding.Error, e, e, "Fix the file; the tool cannot read its MCP servers."))
	}
	for _, s := range mcp {
		if !s.Found {
			out = append(out, mk("mcp_missing", finding.Warning, s.Source+": "+s.Name,
				fmt.Sprintf("MCP server %q (%s) runs %s, which is not installed, so it fails to start", s.Name, s.Source, s.Command),
				"Install "+s.Command+" or remove the server from "+s.File+"."))
		}
	}

	st, serrs := ClaudeSettings(env)
	d.Hooks = st.Hooks
	for _, e := range serrs {
		out = append(out, mk("config_syntax", finding.Error, e, e, ""))
	}
	for _, h := range st.Hooks {
		if prob := HookProblem(env, h.Command); prob != "" {
			out = append(out, mk("hook_broken", finding.Warning, h.Event+": "+h.Command,
				fmt.Sprintf("Claude Code %s hook %q fails: %s", h.Event, h.Command, prob), "Fix or remove it in "+h.File+"."))
		}
	}
	if broad := BroadRules(st.Allow); len(broad) > 0 {
		f := mk("permissions_broad", finding.Notice, "permissions",
			fmt.Sprintf("%d Claude Code allow rule(s) let it run any command without asking", len(broad)),
			"Allow specific commands instead, so Claude asks before running arbitrary code.")
		f.Details = broad
		out = append(out, f)
	}
	global := filepath.Join(env.Home, ".claude", "CLAUDE.md")
	if fi, err := os.Stat(global); err == nil && fi.Size() > o.InstructionLimit {
		out = append(out, mk("instructions_large", finding.Notice, global,
			fmt.Sprintf("%s is %s; Claude Code loads it into every session", global, files.Human(fi.Size())),
			"Trim it, or move rarely needed parts into skills or project CLAUDE.md files."))
	}

	rep.Phase("finding AI projects", 0)
	sessions := SessionDirs(env.Home)
	paths := map[string]bool{}
	for _, p := range repos.Discover(o.Repos) {
		if len(Markers(p)) > 0 {
			paths[p] = true
		}
	}
	for p := range sessions {
		paths[p] = true
	}
	list := make([]string, 0, len(paths))
	for p := range paths {
		if p != env.Home {
			list = append(list, p)
		}
	}
	sort.Strings(list)
	rep.Phase("inspecting AI projects", len(list))
	for _, p := range list {
		pr := Inspect(ctx, env, p, sessions[p])
		d.Projects = append(d.Projects, pr)
		rep.Step(filepath.Base(p))
		switch {
		case !pr.Exists && pr.SessionDir != "":
			f := mk("stale_sessions", finding.Info, pr.SessionDir,
				fmt.Sprintf("%d Claude session(s) (%s) belong to %s, which no longer exists", pr.Sessions, files.Human(pr.SessionBytes), pr.Path),
				"rm -r "+pr.SessionDir)
			f.Group = &finding.Group{ID: "stale_sessions", Title: "Remove sessions of deleted projects", Hint: "delete the listed ~/.claude/projects directories"}
			out = append(out, f)
		case pr.InstructionBytes > o.InstructionLimit:
			out = append(out, mk("instructions_large", finding.Notice, pr.Path,
				fmt.Sprintf("%s has %s of CLAUDE.md/AGENTS.md, loaded into every session", pr.Path, files.Human(pr.InstructionBytes)),
				"Trim it or split rarely needed parts into skills."))
		}
		if ctx.Err() != nil {
			return nil, nil, nil, nil, ctx.Err()
		}
	}
	finding.Sort(out)

	installed, keys := 0, 0
	for _, p := range d.Providers {
		switch {
		case p.Kind == "key":
			keys++
		case p.Installed:
			installed++
		}
	}
	missing := 0
	for _, s := range d.MCP {
		if !s.Found {
			missing++
		}
	}
	withSessions := 0
	for _, p := range d.Projects {
		if p.Sessions > 0 {
			withSessions++
		}
	}
	stats := []run.Stat{
		{Name: "AI tools", Value: fmt.Sprint(installed), Note: "installed"},
		{Name: "provider keys", Value: fmt.Sprint(keys), Note: "in the environment"},
		{Name: "MCP servers", Value: fmt.Sprint(len(d.MCP)), Note: fmt.Sprintf("%d cannot start", missing)},
		{Name: "AI projects", Value: fmt.Sprint(len(d.Projects)), Note: fmt.Sprintf("%d with Claude sessions", withSessions)},
	}
	return d, out, stats, errs, nil
}

// Status is the one-word state of a provider for tables.
func (p Provider) Status() string {
	switch {
	case p.Kind == "key":
		if p.Detail != "" {
			return p.Detail
		}
		return "set"
	case !p.Installed:
		return "not installed"
	case p.LoggedIn == nil:
		return "installed"
	case *p.LoggedIn && p.Kind == "local":
		return "running"
	case *p.LoggedIn:
		return "logged in"
	case p.Kind == "local":
		return "stopped"
	}
	return "not logged in"
}

// Tools lists a project's markers as a short string.
func (p Project) Tools() string { return strings.Join(p.Markers, " ") }
