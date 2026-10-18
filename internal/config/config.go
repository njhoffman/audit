// Package config loads audit's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the merged view of defaults, the YAML file and AUDIT_* variables.
// Command-line flags are applied on top by the cmd package.
type Config struct {
	DataDir string `mapstructure:"data_dir" yaml:"data_dir"`
	History int    `mapstructure:"history" yaml:"history"`
	NoColor bool   `mapstructure:"no_color" yaml:"no_color"`
	// GitHubUser is the login whose repositories are tagged "mine"; empty
	// means ask gh once and remember the answer.
	GitHubUser  string            `mapstructure:"github_user" yaml:"github_user"`
	Stale       StaleConfig       `mapstructure:"stale" yaml:"stale"`
	Ignore      []string          `mapstructure:"ignore" yaml:"ignore"`
	Display     DisplayConfig     `mapstructure:"display" yaml:"display"`
	AI          AIConfig          `mapstructure:"ai" yaml:"ai"`
	System      SystemConfig      `mapstructure:"system" yaml:"system"`
	Packages    PackagesConfig    `mapstructure:"packages" yaml:"packages"`
	Environment EnvironmentConfig `mapstructure:"environment" yaml:"environment"`
}

// Thresholds says when saved results count as stale (Warn) and old (Old).
type Thresholds struct {
	Warn time.Duration `mapstructure:"warn" yaml:"warn"`
	Old  time.Duration `mapstructure:"old" yaml:"old"`
}

// StaleConfig holds the default thresholds and per-command overrides.
type StaleConfig struct {
	Thresholds `mapstructure:",squash" yaml:",inline"`
	Commands   map[string]Thresholds `mapstructure:"commands" yaml:"commands"`
}

// For returns the thresholds that apply to command.
func (s StaleConfig) For(command string) Thresholds {
	t := s.Thresholds
	if o, ok := s.Commands[command]; ok {
		if o.Warn > 0 {
			t.Warn = o.Warn
		}
		if o.Old > 0 {
			t.Old = o.Old
		}
	}
	return t
}

// AIConfig configures the opt-in LLM review (the claude CLI in print mode).
type AIConfig struct {
	Command       string        `mapstructure:"command" yaml:"command"`
	Model         string        `mapstructure:"model" yaml:"model"`
	AnalysisLevel string        `mapstructure:"analysis_level" yaml:"analysis_level"`
	Timeout       time.Duration `mapstructure:"timeout" yaml:"timeout"`
	MaxDetails    int           `mapstructure:"max_details" yaml:"max_details"`
}

// DisplayConfig configures terminal output.
type DisplayConfig struct {
	// Details is how many detail lines a finding shows without --verbose.
	Details int `mapstructure:"details" yaml:"details"`
}

// SystemConfig configures `audit system`.
type SystemConfig struct {
	Journal     string         `mapstructure:"journal" yaml:"journal"`
	Logs        []string       `mapstructure:"logs" yaml:"logs"`
	LogMaxLines int            `mapstructure:"log_max_lines" yaml:"log_max_lines"`
	LogPatterns int            `mapstructure:"log_patterns" yaml:"log_patterns"`
	Programs    []string       `mapstructure:"programs" yaml:"programs"`
	Procs       ProcsConfig    `mapstructure:"procs" yaml:"procs"`
	Services    ServicesConfig `mapstructure:"services" yaml:"services"`
}

// ProcsConfig sets the process thresholds of `audit system`.
type ProcsConfig struct {
	Top         int     `mapstructure:"top" yaml:"top"`
	HighCPU     float64 `mapstructure:"high_cpu" yaml:"high_cpu"`
	HighMem     float64 `mapstructure:"high_mem" yaml:"high_mem"`
	HighThreads int     `mapstructure:"high_threads" yaml:"high_threads"`
}

// ServicesConfig configures the systemd unit checks of `audit system`.
type ServicesConfig struct {
	UserUnits     bool `mapstructure:"user_units" yaml:"user_units"`
	HighRestarts  int  `mapstructure:"high_restarts" yaml:"high_restarts"`
	UnitFilePerms bool `mapstructure:"unit_file_perms" yaml:"unit_file_perms"`
}

// Sources of the packages scan environment.
const (
	EnvLogin   = "login"
	EnvProcess = "process"
)

// PackagesConfig configures `audit packages`.
type PackagesConfig struct {
	// Env is where the scan's PATH and variables come from: "login" (a fresh
	// login shell, the first of environment.shells) or "process" (audit's own).
	Env      string         `mapstructure:"env" yaml:"env"`
	Managers []string       `mapstructure:"managers" yaml:"managers"`
	ScanDirs []string       `mapstructure:"scan_dirs" yaml:"scan_dirs"`
	Registry RegistryConfig `mapstructure:"registry" yaml:"registry"`
	Update   UpdateConfig   `mapstructure:"update" yaml:"update"`
	// Tags is the vocabulary AI tagging chooses from.
	Tags []string `mapstructure:"tags" yaml:"tags"`
}

// RegistryConfig configures `audit packages registry`.
type RegistryConfig struct {
	// MaxAge is how old cached versions may be before they are fetched again.
	MaxAge time.Duration `mapstructure:"max_age" yaml:"max_age"`
	// MetadataMaxAge is the same for descriptions, where they cost extra
	// requests (crates.io API, GitHub).
	MetadataMaxAge time.Duration `mapstructure:"metadata_max_age" yaml:"metadata_max_age"`
	Concurrency    int           `mapstructure:"concurrency" yaml:"concurrency"`
	Timeout        time.Duration `mapstructure:"timeout" yaml:"timeout"`
	// UnmaintainedAfter flags packages with no release for this long; 0
	// disables the check.
	UnmaintainedAfter time.Duration `mapstructure:"unmaintained_after" yaml:"unmaintained_after"`
}

// UpdateConfig configures `audit packages update`.
type UpdateConfig struct {
	// Timeout bounds one package's update command.
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
	// Exclude lists packages (name or manager:name) never updated.
	Exclude []string `mapstructure:"exclude" yaml:"exclude"`
}

// EnvironmentConfig configures `audit environment`.
type EnvironmentConfig struct {
	Shells         []string         `mapstructure:"shells" yaml:"shells"`
	StartupFiles   []string         `mapstructure:"startup_files" yaml:"startup_files"`
	StartupDirs    []string         `mapstructure:"startup_dirs" yaml:"startup_dirs"`
	KnownOutput    []string         `mapstructure:"known_output" yaml:"known_output"`
	StartupTimeout time.Duration    `mapstructure:"startup_timeout" yaml:"startup_timeout"`
	SlowStartup    time.Duration    `mapstructure:"slow_startup" yaml:"slow_startup"`
	Shellcheck     ShellcheckConfig `mapstructure:"shellcheck" yaml:"shellcheck"`
}

// ShellcheckConfig configures the shellcheck pass over startup scripts.
type ShellcheckConfig struct {
	Severity string   `mapstructure:"severity" yaml:"severity"`
	Exclude  []string `mapstructure:"exclude" yaml:"exclude"`
}

// Defaults.
const (
	DefaultJournalFlags  = "-p 4 -b -n 500 --no-pager"
	DefaultModel         = "claude-sonnet-5-5"
	DefaultAnalysisLevel = "standard"
	DefaultHistory       = 20
)

var (
	DefaultLogs     = []string{"boot", "dmesg", "journal"}
	DefaultPrograms = []string{"sshd", "nginx", "postgres", "apache", "docker", "cron"}
	DefaultManagers = []string{"uv", "pnpm", "cargo", "go", "gem", "gh"}
	DefaultScanDirs = []string{"~/.local/bin"}
	DefaultTags     = []string{
		"cli", "tui", "gui", "library", "lsp", "formatter", "linter", "compiler", "build", "testing", "debugging",
		"profiling", "docs", "git", "github", "http", "network", "database", "cloud", "container", "kubernetes",
		"security", "crypto", "shell", "terminal", "editor", "files", "search", "text", "json", "yaml", "markdown",
		"monitoring", "system", "package-manager", "version-manager", "ai", "media", "image", "audio", "video",
		"productivity",
	}
	DefaultShells       = []string{"zsh", "bash"}
	DefaultStartupFiles = []string{
		"~/.profile", "~/.bash_profile", "~/.bash_login", "~/.bashrc", "~/.bash_aliases",
		"~/.zshenv", "~/.zprofile", "~/.zshrc", "~/.zlogin",
	}
	DefaultStartupDirs = []string{"~/.shell"}
	// DefaultKnownOutput matches startup output that is intentional, such as
	// a timing banner. Lines matching any of these are not reported.
	DefaultKnownOutput = []string{`^\s*--\s+[0-9.]+s\s+::`}
)

func defaults(v *viper.Viper) {
	v.SetDefault("data_dir", "")
	v.SetDefault("history", DefaultHistory)
	v.SetDefault("no_color", false)
	v.SetDefault("github_user", "")
	v.SetDefault("stale.warn", 24*time.Hour)
	v.SetDefault("stale.old", 7*24*time.Hour)
	v.SetDefault("stale.commands", map[string]any{
		"files": map[string]any{"warn": "168h", "old": "720h"},
	})
	v.SetDefault("ignore", []string{})
	v.SetDefault("display.details", 5)
	v.SetDefault("ai.command", "claude")
	v.SetDefault("ai.model", DefaultModel)
	v.SetDefault("ai.analysis_level", DefaultAnalysisLevel)
	v.SetDefault("ai.timeout", 5*time.Minute)
	v.SetDefault("ai.max_details", 10)
	v.SetDefault("system.journal", DefaultJournalFlags)
	v.SetDefault("system.logs", DefaultLogs)
	v.SetDefault("system.log_max_lines", 5000)
	v.SetDefault("system.log_patterns", 10)
	v.SetDefault("system.programs", DefaultPrograms)
	v.SetDefault("system.procs.top", 10)
	v.SetDefault("system.procs.high_cpu", 80.0)
	v.SetDefault("system.procs.high_mem", 25.0)
	v.SetDefault("system.procs.high_threads", 1000)
	v.SetDefault("system.services.user_units", true)
	v.SetDefault("system.services.high_restarts", 5)
	v.SetDefault("system.services.unit_file_perms", true)
	v.SetDefault("packages.env", EnvLogin)
	v.SetDefault("packages.managers", DefaultManagers)
	v.SetDefault("packages.scan_dirs", DefaultScanDirs)
	v.SetDefault("packages.registry.max_age", 24*time.Hour)
	v.SetDefault("packages.registry.metadata_max_age", 7*24*time.Hour)
	v.SetDefault("packages.registry.concurrency", 8)
	v.SetDefault("packages.registry.timeout", 10*time.Second)
	v.SetDefault("packages.registry.unmaintained_after", 3*365*24*time.Hour)
	v.SetDefault("packages.update.timeout", 15*time.Minute)
	v.SetDefault("packages.update.exclude", []string{})
	v.SetDefault("packages.tags", DefaultTags)
	v.SetDefault("environment.shells", DefaultShells)
	v.SetDefault("environment.startup_files", DefaultStartupFiles)
	v.SetDefault("environment.startup_dirs", DefaultStartupDirs)
	v.SetDefault("environment.known_output", DefaultKnownOutput)
	v.SetDefault("environment.startup_timeout", 15*time.Second)
	v.SetDefault("environment.slow_startup", 500*time.Millisecond)
	v.SetDefault("environment.shellcheck.severity", "warning")
	v.SetDefault("environment.shellcheck.exclude", []string{"SC2034"})
}

// Load reads the config. explicit, when non-empty, must exist; otherwise the
// default path is used if present. It returns the config and the path it read
// ("" when no file was found). Load never writes; see EnsureDefault.
func Load(explicit string) (*Config, string, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("AUDIT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	defaults(v)

	path := explicit
	if path == "" {
		p, err := Path()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	used := ""
	if _, err := os.Stat(path); err == nil {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, "", fmt.Errorf("read config %s: %w", path, err)
		}
		used = path
	} else if explicit != "" || !errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, "", fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, "", fmt.Errorf("config %s: %w", path, err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir()
	}
	return cfg, used, nil
}

func (c *Config) validate() error {
	if c.History < 1 {
		return fmt.Errorf("history must be at least 1, got %d", c.History)
	}
	if c.Stale.Warn <= 0 || c.Stale.Old < c.Stale.Warn {
		return fmt.Errorf("stale thresholds must satisfy 0 < warn <= old (got warn=%s old=%s)", c.Stale.Warn, c.Stale.Old)
	}
	positive := []struct {
		key string
		n   float64
	}{
		{"display.details", float64(c.Display.Details)},
		{"ai.max_details", float64(c.AI.MaxDetails)},
		{"system.log_max_lines", float64(c.System.LogMaxLines)},
		{"system.log_patterns", float64(c.System.LogPatterns)},
		{"system.procs.top", float64(c.System.Procs.Top)},
		{"system.procs.high_cpu", c.System.Procs.HighCPU},
		{"system.procs.high_mem", c.System.Procs.HighMem},
		{"system.procs.high_threads", float64(c.System.Procs.HighThreads)},
		{"packages.registry.max_age", float64(c.Packages.Registry.MaxAge)},
		{"packages.registry.metadata_max_age", float64(c.Packages.Registry.MetadataMaxAge)},
		{"packages.registry.concurrency", float64(c.Packages.Registry.Concurrency)},
		{"packages.registry.timeout", float64(c.Packages.Registry.Timeout)},
		{"packages.update.timeout", float64(c.Packages.Update.Timeout)},
	}
	for _, p := range positive {
		if p.n <= 0 {
			return fmt.Errorf("%s must be greater than 0, got %v", p.key, p.n)
		}
	}
	if c.System.Services.HighRestarts < 0 {
		return fmt.Errorf("system.services.high_restarts must be 0 (off) or more, got %d", c.System.Services.HighRestarts)
	}
	if c.Packages.Registry.UnmaintainedAfter < 0 {
		return fmt.Errorf("packages.registry.unmaintained_after must be 0 (off) or more, got %s", c.Packages.Registry.UnmaintainedAfter)
	}
	for _, e := range c.Packages.Update.Exclude {
		if strings.TrimSpace(e) == "" {
			return errors.New("packages.update.exclude: entries must name a package")
		}
	}
	for _, t := range c.Packages.Tags {
		if t == "" || strings.Join(strings.Fields(strings.ToLower(t)), "-") != t {
			return fmt.Errorf("packages.tags: %q must be lowercase words joined by dashes", t)
		}
	}
	if c.Packages.Env != EnvLogin && c.Packages.Env != EnvProcess {
		return fmt.Errorf("packages.env: %q is not %s or %s", c.Packages.Env, EnvLogin, EnvProcess)
	}
	switch c.Environment.Shellcheck.Severity {
	case "error", "warning", "info", "style":
	default:
		return fmt.Errorf("environment.shellcheck.severity: %q is not error, warning, info or style", c.Environment.Shellcheck.Severity)
	}
	for _, s := range c.Environment.Shells {
		if s != "zsh" && s != "bash" {
			return fmt.Errorf("environment.shells: unsupported shell %q (want zsh or bash)", s)
		}
	}
	return nil
}

// Path returns the default config file path.
func Path() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "audit.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "audit.yaml"), nil
}

// EnsureDefault writes Template to the default path when no file exists
// there. It reports the path and whether it created the file.
func EnsureDefault() (string, bool, error) {
	path, err := Path()
	if err != nil {
		return "", false, err
	}
	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return path, false, err
	}
	if err := WriteTemplate(path); err != nil {
		return path, false, err
	}
	return path, true, nil
}

// WriteTemplate writes Template to path, creating its directory.
func WriteTemplate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(Template), 0o600)
}

func defaultDataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "audit")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "audit")
}

// DBPath is the SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "audit.db") }

// ReportDir is where HTML reports are written.
func (c *Config) ReportDir() string { return filepath.Join(c.DataDir, "reports") }

// Template is the commented file written on first run and by
// `audit config --init`. TestTemplateMatchesDefaults keeps it in step with
// defaults().
const Template = `# audit configuration. Every value shown is the default; edit or delete any
# key. Keys can also be set as AUDIT_<KEY> environment variables, with dots
# as underscores (AUDIT_STALE_WARN=12h).

# Where the results database and HTML reports live. Empty means
# $XDG_DATA_HOME/audit (~/.local/share/audit).
data_dir: ""

# Saved runs kept per command.
history: 20

# Disable colors (also off when NO_COLOR is set or output is not a terminal).
no_color: false

# GitHub login whose repositories are tagged "mine". Empty means ask
# gh (gh api user) once and remember the answer.
github_user: ""

# Saved results older than warn are shown with a yellow notice and, when a
# command runs without --report/--list/--summary/--json, trigger a rescan.
# Results older than old are flagged in red. commands overrides per command.
stale:
  warn: 24h
  old: 168h
  commands:
    files: {warn: 168h, old: 720h}

# Findings to hide. Each entry is a full key (command:check:subject), a
# command-qualified check (packages:pnpm.legacy_shim) or a bare check id.
ignore: []

display:
  # Detail lines shown per finding; --verbose shows all of them.
  details: 5

# Opt-in review of findings with --ai, through the claude CLI in print mode.
ai:
  command: claude
  model: claude-sonnet-5-5
  analysis_level: standard   # brief | standard | deep
  timeout: 5m
  # Detail lines per finding sent in the prompt.
  max_details: 10

system:
  # Extra journalctl flags for the journal source.
  journal: "-p 4 -b -n 500 --no-pager"
  # Log sources: boot, dmesg, journal, auth, kern, misc.
  logs: [boot, dmesg, journal]
  # Lines read per log source, and normalized patterns reported per source.
  log_max_lines: 5000
  log_patterns: 10
  # Program configurations to check.
  programs: [sshd, nginx, postgres, apache, docker, cron]
  procs:
    top: 10              # processes listed by CPU and by memory
    high_cpu: 80         # percent
    high_mem: 25         # percent
    high_threads: 1000
  services:
    user_units: true     # also scan the user systemd manager
    high_restarts: 5     # flag units restarted this often; 0 disables
    unit_file_perms: true

packages:
  # Where PATH and the other variables come from: login (a fresh login shell,
  # the first of environment.shells, so a stale terminal session does not
  # cause false findings) or process (the environment audit was started in).
  env: login
  managers: [uv, pnpm, cargo, go, gem, gh]
  # Directories of loose executables checked for broken interpreters.
  scan_dirs: [~/.local/bin]
  # audit packages registry looks packages up in their registries (PyPI,
  # npm, crates.io, the Go proxy, rubygems.org, GitHub) and caches the answer;
  # other scans and the inventory read the cache without network access.
  registry:
    max_age: 24h             # refetch versions older than this
    metadata_max_age: 168h   # refetch descriptions where that costs extra requests
    concurrency: 8
    timeout: 10s             # per package
    unmaintained_after: 26280h   # 3 years without a release; 0 disables
  # audit packages update runs each manager's own update command per package.
  update:
    timeout: 15m             # per package; cargo builds from source
    # Packages never updated, as name or manager:name (e.g. cargo:ripgrep).
    exclude: []
  # Vocabulary that audit packages registry --ai-tags chooses from.
  tags: [cli, tui, gui, library, lsp, formatter, linter, compiler, build, testing, debugging,
         profiling, docs, git, github, http, network, database, cloud, container, kubernetes,
         security, crypto, shell, terminal, editor, files, search, text, json, yaml, markdown,
         monitoring, system, package-manager, version-manager, ai, media, image, audio, video,
         productivity]

environment:
  shells: [zsh, bash]
  startup_files: [~/.profile, ~/.bash_profile, ~/.bash_login, ~/.bashrc, ~/.bash_aliases,
                  ~/.zshenv, ~/.zprofile, ~/.zshrc, ~/.zlogin]
  startup_dirs: [~/.shell]
  # Regular expressions for intentional startup output (e.g. a timing banner).
  known_output: ['^\s*--\s+[0-9.]+s\s+::']
  startup_timeout: 15s
  slow_startup: 500ms
  shellcheck:
    severity: warning    # error | warning | info | style
    exclude: [SC2034]
`
