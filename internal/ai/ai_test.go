package ai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/repos"
)

var ctx = context.Background()

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exe(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
}

func TestBroadRulesAndHooks(t *testing.T) {
	got := BroadRules([]string{"Bash", "Bash(*)", "Bash(bash:*)", "Bash(python3 *)", "Bash(git status:*)", "Bash(cargo:*)", "Read(*)"})
	if !reflect.DeepEqual(got, []string{"Bash", "Bash(*)", "Bash(bash:*)", "Bash(python3 *)"}) {
		t.Errorf("broad: %v", got)
	}
	home := t.TempDir()
	bin := t.TempDir()
	exe(t, bin, "bash", "python")
	write(t, filepath.Join(home, ".config/claude/hooks/ok.sh"), "")
	env := &exec.Env{Vars: map[string]string{"PATH": bin + ":/bin", "HOME": home}, Home: home}
	for cmd, want := range map[string]string{
		"/bin/bash ~/.config/claude/hooks/ok.sh": "",
		"bash ~/.config/claude/hooks/gone.sh":    filepath.Join(home, ".config/claude/hooks/gone.sh") + " does not exist",
		"~/.config/claude/hooks/auto.sh":         filepath.Join(home, ".config/claude/hooks/auto.sh") + " does not exist or is not executable",
		"black --quiet $file":                    "black is not installed",
		"python -m black $file":                  "",
		"FOO=1 anything":                         "",
	} {
		if got := HookProblem(env, cmd); got != want {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}
}

func TestProviders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3:8b"}]}`))
	}))
	defer srv.Close()
	old := OllamaURL
	OllamaURL = srv.URL
	t.Cleanup(func() { OllamaURL = old })
	bin := t.TempDir()
	exe(t, bin, "claude", "codex", "ollama")
	fake := &exec.Fake{}
	fake.AddOutput("2.1.0 (Claude Code)\n", "claude", "--version")
	fake.AddOutput(`{"loggedIn": false, "authMethod": "none"}`, "claude", "auth", "status")
	fake.AddOutput("codex-cli 0.1\n", "codex", "--version")
	fake.Add([]string{"codex", "login", "status"}, exec.Result{Code: 1, Stdout: "Not logged in"})
	fake.AddOutput("Warning: could not connect\nollama version is 0.9.0\n", "ollama", "--version")
	env := &exec.Env{Vars: map[string]string{"PATH": bin, "OPENAI_API_KEY": "sk-x", "_ANTHROPIC_API_KEY": "y", "EDITOR": "vim"}, Runner: fake}
	by := map[string]Provider{}
	for _, p := range Providers(ctx, env) {
		by[p.Name] = p
	}
	if c := by["claude"]; c.Status() != "not logged in" || c.Version != "2.1.0 (Claude Code)" {
		t.Errorf("claude: %+v", c)
	}
	if c := by["codex"]; c.Status() != "not logged in" {
		t.Errorf("codex: %+v", c)
	}
	if o := by["ollama"]; o.Status() != "running" || !strings.Contains(o.Detail, "llama3:8b") || o.Version != "ollama version is 0.9.0" {
		t.Errorf("ollama: %+v", o)
	}
	if by["OPENAI_API_KEY"].Status() != "set" || by["_ANTHROPIC_API_KEY"].Status() != "disabled (leading underscore)" {
		t.Errorf("keys: %+v", by)
	}
	if _, ok := by["EDITOR"]; ok {
		t.Error("only provider keys are listed")
	}
}

func TestMCPServers(t *testing.T) {
	home := t.TempDir()
	bin := t.TempDir()
	exe(t, bin, "uvx")
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"a":{"command":"npx","args":["x"]},"web":{"type":"http","url":"https://x/mcp"}},
		"projects":{"/p":{"mcpServers":{"b":{"command":"uvx"}}}}}`)
	write(t, filepath.Join(home, ".codex/config.toml"), "[mcp_servers.c]\ncommand = \"uvx\"\n")
	write(t, filepath.Join(home, ".config/mcphub/servers.json"), "{broken")
	env := &exec.Env{Vars: map[string]string{"PATH": bin, "XDG_CONFIG_HOME": filepath.Join(home, ".config")}, Home: home}
	ms, errs := MCPServers(env)
	got := map[string]bool{}
	for _, m := range ms {
		got[m.Source+"/"+m.Name] = m.Found
	}
	want := map[string]bool{"claude/a": false, "claude/web": true, "claude project /p/b": true, "codex/c": true}
	if !reflect.DeepEqual(got, want) || len(errs) != 1 || !strings.Contains(errs[0], "servers.json") {
		t.Errorf("servers %v errs %v", got, errs)
	}
}

func TestScan(t *testing.T) {
	home := t.TempDir()
	bin := t.TempDir()
	exe(t, bin, "git")
	proj := filepath.Join(home, "src", "proj")
	write(t, filepath.Join(proj, ".git", "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(proj, "CLAUDE.md"), strings.Repeat("x", 2000))
	write(t, filepath.Join(proj, ".claude", "commands", "go.md"), "")
	write(t, filepath.Join(proj, ".mcp.json"), `{"mcpServers":{"rg":{"command":"rg"}}}`)
	write(t, filepath.Join(home, "src", "plain", ".git", "HEAD"), "")
	// Claude sessions: one for proj, one for a deleted project.
	write(t, filepath.Join(home, ".claude/projects/-src-proj/a.jsonl"), `{"type":"user","cwd":"`+proj+`"}`+"\n")
	write(t, filepath.Join(home, ".claude/projects/-gone/b.jsonl"), `{"cwd":"`+filepath.Join(home, "gone")+`"}`+"\n")
	write(t, filepath.Join(home, ".claude/settings.json"), `{"hooks":{"Stop":[{"matcher":"*","hooks":[{"type":"command","command":"missing-tool --x"}]}]},
		"permissions":{"allow":["Bash(*)","Bash(git status:*)"]}}`)
	fake := &exec.Fake{}
	fake.AddOutput("# branch.head main\n1 .M N... x\n", "git", "-C", proj, "status")
	env := &exec.Env{Vars: map[string]string{"PATH": bin, "HOME": home, "XDG_CONFIG_HOME": filepath.Join(home, ".config")}, Home: home, Runner: fake}
	pinged := 0
	o := Options{Env: env, Repos: repos.Options{Roots: []string{filepath.Join(home, "src")}, MaxDepth: 3}, InstructionLimit: 1000,
		Ping: func(context.Context, Provider) (time.Duration, error) { pinged++; return 0, errors.New("boom") }}
	d, fs, stats, _, err := Scan(ctx, o, progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]int{}
	for _, f := range fs {
		checks[f.Check]++
	}
	for _, c := range []string{"ai.hook_broken", "ai.permissions_broad", "ai.instructions_large", "ai.stale_sessions"} {
		if checks[c] != 1 {
			t.Errorf("%s: %v", c, checks)
		}
	}
	if len(d.Projects) != 2 {
		t.Fatalf("projects (plain repo without markers left out): %+v", d.Projects)
	}
	var p Project
	for _, x := range d.Projects {
		if x.Path == proj {
			p = x
		}
	}
	if !p.Exists || p.Branch != "main" || p.Dirty != 1 || p.Commands != 1 || p.Sessions != 1 || !reflect.DeepEqual(p.MCP, []string{"rg"}) ||
		p.Tools() != "CLAUDE.md .claude .mcp.json" {
		t.Errorf("project: %+v", p)
	}
	if pinged != 0 || len(stats) != 3 {
		t.Errorf("no CLI installed, nothing to ping: %d; stats %v", pinged, stats)
	}
}
