package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	return dir
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := isolate(t)
	cfg, used, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if used != "" {
		t.Errorf("no file should be reported, got %q", used)
	}
	if cfg.System.Journal != DefaultJournalFlags || cfg.AI.Claude.Model != DefaultModel || cfg.AI.Provider != ProviderClaude || cfg.History != DefaultHistory {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.DataDir != filepath.Join(dir, "data", "audit") || !strings.HasSuffix(cfg.DBPath(), "audit/audit.db") {
		t.Errorf("data dir: %q", cfg.DataDir)
	}
	if got := cfg.Stale.For("packages"); got.Warn != 24*time.Hour || got.Old != 168*time.Hour {
		t.Errorf("default thresholds: %+v", got)
	}
	if got := cfg.Stale.For("files"); got.Warn != 168*time.Hour || got.Old != 720*time.Hour {
		t.Errorf("files thresholds: %+v", got)
	}
	if !cfg.Export.Enabled || cfg.ExportDir() != filepath.Join(dir, "data", "audit", "export") {
		t.Errorf("export: %+v %q", cfg.Export, cfg.ExportDir())
	}
	home, _ := os.UserHomeDir()
	cfg.Export.Dir = "~/dash/audit"
	if got := cfg.ExportDir(); got != filepath.Join(home, "dash", "audit") {
		t.Errorf("export dir with ~: %q", got)
	}
	if len(cfg.Packages.Managers) != 10 || cfg.Environment.StartupTimeout != 15*time.Second {
		t.Errorf("command defaults: %+v %+v", cfg.Packages, cfg.Environment)
	}
}

func TestLoadFile(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "config", "audit.yaml")
	write(t, path, `
history: 5
stale:
  warn: 2h
  old: 10h
  commands:
    repos: {old: 48h}
ignore: [path.missing]
ai: {provider: codex, codex: {model: gpt-test}, claude: {model: claude-haiku-5-5}}
packages: {managers: [cargo]}
`)
	cfg, used, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if used != path || cfg.History != 5 || cfg.AI.Claude.Model != "claude-haiku-5-5" || cfg.Ignore[0] != "path.missing" {
		t.Errorf("file not applied: %+v", cfg)
	}
	if name, pc := cfg.AI.For(""); name != ProviderCodex || pc.Model != "gpt-test" || pc.Command != "codex" {
		t.Errorf("ai.provider codex: %s %+v", name, pc)
	}
	if name, pc := cfg.AI.For(ProviderClaude); name != ProviderClaude || pc.Model != "claude-haiku-5-5" {
		t.Errorf("explicit provider: %s %+v", name, pc)
	}
	if got := cfg.Stale.For("repos"); got.Warn != 2*time.Hour || got.Old != 48*time.Hour {
		t.Errorf("partial override: %+v", got)
	}
	if len(cfg.Packages.Managers) != 1 || cfg.System.Journal != DefaultJournalFlags {
		t.Errorf("merge with defaults: %+v", cfg)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	isolate(t)
	t.Setenv("AUDIT_AI_CLAUDE_MODEL", "from-env")
	cfg, _, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AI.Claude.Model != "from-env" {
		t.Errorf("env override: %q", cfg.AI.Claude.Model)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := isolate(t)
	if _, _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("explicit missing file must error")
	}
	bad := filepath.Join(dir, "bad.yaml")
	write(t, bad, "history: [")
	if _, _, err := Load(bad); err == nil {
		t.Error("invalid YAML must error")
	}
	for _, body := range []string{
		"history: 0", "stale: {warn: 5h, old: 1h}", "environment: {shells: [fish]}", "ai: {provider: gemini}",
		"display: {details: 0}", "ai: {max_details: -1}", "system: {log_max_lines: 0}",
		"shell_history: {max_lines: 0}", "shell_history: {max_mb: 0}", "shell_history: {max_mb: 1025}", `shell_history: {patterns: [""]}`,
		"system: {procs: {high_cpu: 0}}", "system: {services: {high_restarts: -1}}",
		"environment: {shellcheck: {severity: loud}}", "packages: {env: shell}",
		"packages: {registry: {max_age: 0s}}", "packages: {registry: {metadata_max_age: -1h}}",
		"packages: {registry: {concurrency: 0}}", "packages: {registry: {timeout: 0s}}",
		"packages: {registry: {unmaintained_after: -1h}}", "packages: {tags: [Has Space]}", "packages: {tags: [UPPER]}",
		"packages: {update: {timeout: 0s}}", `packages: {update: {exclude: [""]}}`,
		"tui: {keys: {qiut: [x]}}", "tui: {keys: {rescan: [ctrl+c]}}", "tui: {keys: {quit: [d]}}",
		"tui: {interface: dmenu}", "tui: {fzf_keys: {status_done: [d]}}", "tui: {fzf_keys: {up: [alt-k]}}",
	} {
		write(t, bad, body)
		if _, _, err := Load(bad); err == nil {
			t.Errorf("invalid config %q must error", body)
		}
	}
}

func TestLoadKeys(t *testing.T) {
	dir := isolate(t)
	path := filepath.Join(dir, "k.yaml")
	write(t, path, "tui: {keys: {quit: [Q, z], status_done: [D], editor: []}}")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	k := cfg.TUI.Keys
	if !reflect.DeepEqual(k["quit"], []string{"Q", "z"}) || !reflect.DeepEqual(k["status_done"], []string{"D"}) {
		t.Errorf("overrides keep their case and replace the default list: %v %v", k["quit"], k["status_done"])
	}
	if len(k["editor"]) != 0 {
		t.Errorf("[] unbinds: %v", k["editor"])
	}
	if !reflect.DeepEqual(k["bottom"], []string{"end", "G"}) || !reflect.DeepEqual(k["page_down"], []string{"pgdown", "f", " "}) {
		t.Errorf("other actions keep their defaults: %v %v", k["bottom"], k["page_down"])
	}
}

// The template documents every default, so loading it must give exactly the
// config that no file gives.
func TestTemplateMatchesDefaults(t *testing.T) {
	dir := isolate(t)
	want, _, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "t.yaml")
	write(t, path, Template)
	got, _, err := Load(path)
	if err != nil {
		t.Fatalf("template does not load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("template disagrees with defaults:\n got %+v\nwant %+v", got, want)
	}
	if got.Packages.Registry.MaxAge != 24*time.Hour || got.Packages.Registry.Concurrency != 8 || len(got.Packages.Tags) != len(DefaultTags) {
		t.Errorf("registry defaults: %+v tags=%d", got.Packages.Registry, len(got.Packages.Tags))
	}
	write(t, path, "packages: {registry: {unmaintained_after: 0s}, tags: [my-tag]}")
	if c, _, err := Load(path); err != nil || c.Packages.Registry.UnmaintainedAfter != 0 || c.Packages.Tags[0] != "my-tag" {
		t.Errorf("unmaintained_after 0 disables the check and custom tags load: %v %+v", err, c)
	}
	if got.System.Procs.HighCPU != 80 || got.Environment.Shellcheck.Exclude[0] != "SC2034" || got.Display.Details != 5 {
		t.Errorf("new keys: %+v %+v", got.System.Procs, got.Environment.Shellcheck)
	}
}

func TestEnsureDefault(t *testing.T) {
	dir := isolate(t)
	want := filepath.Join(dir, "config", "audit.yaml")
	path, created, err := EnsureDefault()
	if err != nil || path != want || !created {
		t.Fatalf("first call: %q %v %v", path, created, err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != Template {
		t.Fatalf("written file is not the template: %v", err)
	}
	write(t, path, "history: 3\n")
	if _, created, err := EnsureDefault(); err != nil || created {
		t.Fatalf("existing file must be left alone: %v %v", created, err)
	}
	if cfg, used, err := Load(""); err != nil || used != want || cfg.History != 3 {
		t.Errorf("load after ensure: %q %v", used, err)
	}
}

func TestEnsureDefaultUnwritable(t *testing.T) {
	dir := isolate(t)
	ro := filepath.Join(dir, "config")
	if err := os.MkdirAll(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if _, _, err := EnsureDefault(); err == nil {
		t.Error("unwritable config dir must error")
	}
}
