package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAICommand(t *testing.T) {
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OPENAI_API_KEY", "sk-test")
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"web":{"command":"npx"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	claude, _, _ := fakeAI(t, "claude", claudeJSON(t, map[string]any{"subtype": "success", "result": "OK"}))
	if err := os.Symlink(claude, filepath.Join(bin, "claude")); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, cfgHome, "repos: {roots: ["+home+"]}\nai: {claude: {command: "+claude+"}}\n")
	r := runArgs(t, "ai", "-r", "-l")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"ai.mcp_missing", "OPENAI_API_KEY", "MCP SERVER", "missing npx"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q:\n%s", want, r.out)
		}
	}
	r = runArgs(t, "ai", "-p", "-l")
	if r.e != nil || !strings.Contains(r.out, "ping: ok in") {
		t.Errorf("--ping: %v\n%s\n%s", r.e, r.out, r.err)
	}
}
