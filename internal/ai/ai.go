// Package ai reports on the AI tooling of the workstation: which AI CLIs
// are installed and logged in, which provider keys the environment holds
// (by name), local model servers, configured MCP servers and whether their
// commands exist, problems in the AI tools' own configuration, and the
// projects set up for AI assistants with their sessions.
package ai

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/njhoffman/audit/internal/exec"
)

// Command is the audit subcommand name.
const Command = "ai"

// Provider is one AI tool or service.
type Provider struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // cli, key, local
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
	// LoggedIn is nil when the tool cannot tell.
	LoggedIn *bool  `json:"logged_in,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// Ping holds the result of --ping: "ok in 1.2s" or the error.
	Ping   string `json:"ping,omitempty"`
	PingOK bool   `json:"ping_ok,omitempty"`
}

// MCPServer is one configured MCP server.
type MCPServer struct {
	Name string `json:"name"`
	// Source is the tool whose config defines it ("claude", "claude project
	// PATH", "codex", "mcphub", ".mcp.json PATH").
	Source  string `json:"source"`
	File    string `json:"file"`
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
	// Found is false when the command is not on PATH.
	Found bool `json:"found"`
}

func yes(b bool) *bool { return &b }

var versionRe = regexp.MustCompile(`\d+\.\d+`)

// versionLine picks the line that carries a version number, skipping the
// warnings some CLIs print first (ollama without a server).
func versionLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); versionRe.MatchString(l) && !strings.HasPrefix(strings.ToLower(l), "warning") {
			return l
		}
	}
	return firstLine(out)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

func runCmd(ctx context.Context, env *exec.Env, name string, args ...string) exec.Result {
	return env.Run(ctx, name, args, exec.Options{Timeout: 20 * time.Second, Unset: []string{"CLAUDECODE"}})
}

// keyRe matches environment variables that hold an AI provider key.
var keyRe = regexp.MustCompile(`^_?(ANTHROPIC|OPENAI|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE_AI|DEEPSEEK|OPENROUTER|MISTRAL|GROQ|XAI|` +
	`PERPLEXITY|TOGETHER|COHERE|HUGGINGFACE|HF|FIREWORKS|REPLICATE|AZURE_OPENAI)_(API_KEY|TOKEN|KEY)$`)

// OllamaURL is ollama's local API; tests point it at a test server.
var OllamaURL = "http://127.0.0.1:11434"

// Providers checks the AI CLIs, the provider keys in the environment and
// a local ollama, without sending any request to a provider.
func Providers(ctx context.Context, env *exec.Env) []Provider {
	var out []Provider
	cli := func(name, binary string, version []string) Provider {
		p := Provider{Name: name, Kind: "cli", Path: env.Which(binary)}
		p.Installed = p.Path != ""
		if p.Installed && version != nil {
			if r := runCmd(ctx, env, binary, version...); r.OK() {
				p.Version = versionLine(r.Stdout + "\n" + r.Stderr)
			}
		}
		return p
	}
	claude := cli("claude", "claude", []string{"--version"})
	if claude.Installed {
		r := runCmd(ctx, env, "claude", "auth", "status")
		var st struct {
			LoggedIn   *bool  `json:"loggedIn"`
			AuthMethod string `json:"authMethod"`
		}
		// Without a loggedIn field the state is unknown, not "logged out".
		if json.Unmarshal([]byte(r.Stdout), &st) == nil {
			claude.LoggedIn, claude.Detail = st.LoggedIn, st.AuthMethod
		}
	}
	out = append(out, claude)
	codex := cli("codex", "codex", []string{"--version"})
	if codex.Installed {
		r := runCmd(ctx, env, "codex", "login", "status")
		line := firstLine(r.Stdout + r.Stderr)
		codex.LoggedIn, codex.Detail = yes(r.OK() && strings.HasPrefix(line, "Logged in")), line
	}
	out = append(out, codex)
	if gh := env.Which("gh"); gh != "" {
		p := Provider{Name: "gh copilot", Kind: "cli", Path: gh}
		if r := runCmd(ctx, env, "gh", "copilot", "--version"); r.OK() {
			p.Installed, p.Version = true, firstLine(r.Stdout)
		}
		out = append(out, p)
	}
	aichat := cli("aichat", "aichat", []string{"--version"})
	if aichat.Installed {
		out = append(out, aichat)
	}
	ollama := cli("ollama", "ollama", []string{"--version"})
	ollama.Kind = "local"
	if ollama.Installed {
		c := http.Client{Timeout: 2 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, OllamaURL+"/api/tags", nil)
		if resp, err := c.Do(req); err == nil {
			var tags struct {
				Models []struct {
					Name string `json:"name"`
				} `json:"models"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&tags)
			_ = resp.Body.Close()
			names := make([]string, 0, len(tags.Models))
			for _, m := range tags.Models {
				names = append(names, m.Name)
			}
			ollama.Detail = fmt.Sprintf("server running, %d model(s): %s", len(names), strings.Join(names, ", "))
			ollama.LoggedIn = yes(true)
		} else {
			ollama.Detail, ollama.LoggedIn = "server not running", yes(false)
		}
		out = append(out, ollama)
	}
	var keys []string
	for k, v := range env.Vars {
		if keyRe.MatchString(k) && v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := Provider{Name: k, Kind: "key", Installed: true}
		if strings.HasPrefix(k, "_") {
			p.Detail = "disabled (leading underscore)"
		}
		out = append(out, p)
	}
	return out
}

// MCPServers reads the MCP servers configured for Claude Code (user and
// per project), Codex and mcphub.
func MCPServers(env *exec.Env) ([]MCPServer, []string) {
	var out []MCPServer
	var errs []string
	add := func(name, source, file string, raw map[string]any) {
		s := MCPServer{Name: name, Source: source, File: file}
		if c, ok := raw["command"].(string); ok {
			s.Command = c
		}
		if u, ok := raw["url"].(string); ok {
			s.URL = u
		}
		s.Found = s.Command == "" || env.Which(s.Command) != ""
		out = append(out, s)
	}
	addAll := func(m map[string]any, source, file string) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if raw, ok := m[n].(map[string]any); ok {
				add(n, source, file, raw)
			}
		}
	}
	readJSON := func(p string) map[string]any {
		b, err := os.ReadFile(p) // #nosec G304 -- the AI tools' own config files
		if err != nil {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		return m
	}
	claudeJSON := filepath.Join(env.Home, ".claude.json")
	if m := readJSON(claudeJSON); m != nil {
		if s, ok := m["mcpServers"].(map[string]any); ok {
			addAll(s, "claude", claudeJSON)
		}
		if projects, ok := m["projects"].(map[string]any); ok {
			keys := make([]string, 0, len(projects))
			for k := range projects {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if p, ok := projects[k].(map[string]any); ok {
					if s, ok := p["mcpServers"].(map[string]any); ok {
						addAll(s, "claude project "+k, claudeJSON)
					}
				}
			}
		}
	}
	codexCfg := filepath.Join(env.Home, ".codex", "config.toml")
	if b, err := os.ReadFile(codexCfg); err == nil { // #nosec G304 -- codex's config
		var m map[string]any
		if err := toml.Unmarshal(b, &m); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", codexCfg, err))
		} else if s, ok := m["mcp_servers"].(map[string]any); ok {
			addAll(s, "codex", codexCfg)
		}
	}
	hub := filepath.Join(env.XDG("XDG_CONFIG_HOME"), "mcphub", "servers.json")
	if m := readJSON(hub); m != nil {
		if s, ok := m["mcpServers"].(map[string]any); ok {
			addAll(s, "mcphub", hub)
		}
	}
	return out, errs
}

// Hook is a command Claude Code runs on an event.
type Hook struct {
	Event   string `json:"event"`
	Matcher string `json:"matcher,omitempty"`
	Command string `json:"command"`
	File    string `json:"file"`
}

// Settings is what the checks read from Claude Code's settings files.
type Settings struct {
	Hooks []Hook   `json:"hooks,omitempty"`
	Allow []string `json:"allow,omitempty"`
	Files []string `json:"files"`
}

// ClaudeSettings reads ~/.claude/settings.json and settings.local.json.
func ClaudeSettings(env *exec.Env) (Settings, []string) {
	var st Settings
	var errs []string
	for _, name := range []string{"settings.json", "settings.local.json"} {
		p := filepath.Join(env.Home, ".claude", name)
		b, err := os.ReadFile(p) // #nosec G304 -- Claude Code's settings
		if err != nil {
			continue
		}
		var raw struct {
			Hooks map[string][]struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"hooks"`
			Permissions struct {
				Allow []string `json:"allow"`
			} `json:"permissions"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			errs = append(errs, fmt.Sprintf("%s does not parse: %v", p, err))
			continue
		}
		st.Files = append(st.Files, p)
		events := make([]string, 0, len(raw.Hooks))
		for e := range raw.Hooks {
			events = append(events, e)
		}
		sort.Strings(events)
		for _, e := range events {
			for _, m := range raw.Hooks[e] {
				for _, h := range m.Hooks {
					if h.Type == "command" && h.Command != "" {
						st.Hooks = append(st.Hooks, Hook{Event: e, Matcher: m.Matcher, Command: h.Command, File: p})
					}
				}
			}
		}
		st.Allow = append(st.Allow, raw.Permissions.Allow...)
	}
	return st, errs
}

// interpreters are commands whose permission allows running anything.
var interpreters = map[string]bool{"bash": true, "sh": true, "zsh": true, "fish": true, "python": true, "python3": true,
	"node": true, "perl": true, "ruby": true, "env": true, "sudo": true, "eval": true, "xargs": true, "npx": true, "uvx": true}

var bashRule = regexp.MustCompile(`^Bash(?:\((.*)\))?$`)

// BroadRules picks allow rules that let Claude run arbitrary commands: Bash
// with no pattern or "*", or an interpreter with any arguments.
func BroadRules(allow []string) []string {
	var out []string
	for _, r := range allow {
		m := bashRule.FindStringSubmatch(strings.TrimSpace(r))
		if m == nil {
			continue
		}
		pat := strings.TrimSpace(m[1])
		cmd, _, _ := strings.Cut(strings.TrimSuffix(strings.TrimSuffix(pat, ":*"), "*"), " ")
		if pat == "" || pat == "*" || interpreters[cmd] && (strings.HasSuffix(pat, ":*") || strings.HasSuffix(pat, "*")) {
			out = append(out, r)
		}
	}
	return out
}

// HookProblem says what is wrong with a hook command: a script path that
// does not exist, or a program not on PATH; "" when both are fine.
func HookProblem(env *exec.Env, command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	prog := fields[0]
	if strings.Contains(prog, "=") {
		return ""
	}
	if env.Which(env.Expand(prog)) == "" {
		if strings.ContainsRune(prog, '/') {
			return env.Expand(prog) + " does not exist or is not executable"
		}
		return prog + " is not installed"
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.HasPrefix(f, "~/") || strings.HasPrefix(f, "/") || strings.HasPrefix(f, "$HOME/") {
			p := env.Expand(strings.Trim(f, `"'`))
			if _, err := os.Stat(p); err != nil {
				return p + " does not exist"
			}
		}
		break
	}
	return ""
}

// Project is a directory set up for an AI assistant.
type Project struct {
	Path string `json:"path"`
	// Markers lists what was found: CLAUDE.md, .claude, AGENTS.md, .mcp.json,
	// .cursor, copilot-instructions.
	Markers []string `json:"markers"`
	Exists  bool     `json:"exists"`
	Git     bool     `json:"git"`
	Branch  string   `json:"branch,omitempty"`
	Dirty   int      `json:"dirty,omitempty"`
	// InstructionBytes is the size of CLAUDE.md and AGENTS.md together.
	InstructionBytes int64     `json:"instruction_bytes,omitempty"`
	Commands         int       `json:"commands,omitempty"`
	Skills           int       `json:"skills,omitempty"`
	Agents           int       `json:"agents,omitempty"`
	MCP              []string  `json:"mcp,omitempty"`
	Sessions         int       `json:"sessions,omitempty"`
	SessionBytes     int64     `json:"session_bytes,omitempty"`
	LastSession      time.Time `json:"last_session,omitzero"`
	// SessionDir is Claude Code's session directory for the project.
	SessionDir string `json:"session_dir,omitempty"`
}

var markers = []struct{ name, rel string }{
	{"CLAUDE.md", "CLAUDE.md"}, {".claude", ".claude"}, {"AGENTS.md", "AGENTS.md"}, {".mcp.json", ".mcp.json"},
	{".cursor", ".cursor"}, {"copilot-instructions", ".github/copilot-instructions.md"}, {"GEMINI.md", "GEMINI.md"},
}

// Markers lists the AI project markers in dir.
func Markers(dir string) []string {
	var out []string
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m.rel)); err == nil {
			out = append(out, m.name)
		}
	}
	return out
}

func count(glob string) int {
	m, _ := filepath.Glob(glob)
	return len(m)
}

var cwdRe = regexp.MustCompile(`"cwd"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// SessionDirs maps each project path Claude Code has sessions for to its
// session directory, reading the working directory recorded in the newest
// session file (the directory name itself is a lossy encoding).
func SessionDirs(home string) map[string]string {
	out := map[string]string{}
	root := filepath.Join(home, ".claude", "projects")
	dirs, _ := os.ReadDir(root)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(root, d.Name())
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		sort.Slice(files, func(i, j int) bool { return mtime(files[i]).After(mtime(files[j])) })
		for _, f := range files {
			if cwd := sessionCwd(f); cwd != "" {
				out[cwd] = dir
				break
			}
		}
	}
	return out
}

func mtime(p string) time.Time {
	if st, err := os.Stat(p); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

func sessionCwd(file string) string {
	f, err := os.Open(file) // #nosec G304 -- Claude Code's session logs
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for i := 0; i < 50 && sc.Scan(); i++ {
		if m := cwdRe.FindSubmatch(sc.Bytes()); m != nil {
			var s string
			if json.Unmarshal([]byte(`"`+string(m[1])+`"`), &s) == nil {
				return s
			}
		}
	}
	return ""
}

// Inspect describes one project directory.
func Inspect(ctx context.Context, env *exec.Env, path, sessionDir string) Project {
	p := Project{Path: path, SessionDir: sessionDir}
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		p.Exists = true
		p.Markers = Markers(path)
		for _, f := range []string{"CLAUDE.md", "AGENTS.md"} {
			if st, err := os.Stat(filepath.Join(path, f)); err == nil {
				p.InstructionBytes += st.Size()
			}
		}
		p.Commands = count(filepath.Join(path, ".claude", "commands", "*.md"))
		p.Skills = count(filepath.Join(path, ".claude", "skills", "*", "SKILL.md"))
		p.Agents = count(filepath.Join(path, ".claude", "agents", "*.md"))
		if b, err := os.ReadFile(filepath.Join(path, ".mcp.json")); err == nil { // #nosec G304 -- project MCP config
			var m struct {
				Servers map[string]any `json:"mcpServers"`
			}
			if json.Unmarshal(b, &m) == nil {
				for n := range m.Servers {
					p.MCP = append(p.MCP, n)
				}
				sort.Strings(p.MCP)
			}
		}
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			p.Git = true
			if r := runCmd(ctx, env, "git", "-C", path, "status", "--porcelain=v2", "--branch"); r.OK() {
				for line := range strings.SplitSeq(r.Stdout, "\n") {
					switch {
					case strings.HasPrefix(line, "# branch.head "):
						p.Branch = strings.TrimPrefix(line, "# branch.head ")
					case line != "" && !strings.HasPrefix(line, "#"):
						p.Dirty++
					}
				}
			}
		}
	}
	if sessionDir != "" {
		files, _ := filepath.Glob(filepath.Join(sessionDir, "*.jsonl"))
		p.Sessions = len(files)
		for _, f := range files {
			if st, err := os.Stat(f); err == nil {
				p.SessionBytes += st.Size()
				if st.ModTime().After(p.LastSession) {
					p.LastSession = st.ModTime()
				}
			}
		}
	}
	return p
}
