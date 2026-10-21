package core

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	osexec "os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/ai"
	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/configs"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scripts"
	"github.com/njhoffman/audit/internal/todo"
)

func defaultConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg, _, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// osEnv runs real programs from the system PATH with home as $HOME, so no
// user config (git, shells) leaks in.
func osEnv(home string) *exec.Env {
	env := &exec.Env{Vars: map[string]string{"HOME": home, "PATH": "/usr/local/bin:/usr/bin:/bin"}, Home: home}
	env.Runner = exec.NewOSRunner(env)
	return env
}

func TestSystemScannerScopeAndOwns(t *testing.T) {
	cfg := defaultConfig(t)
	env := &exec.Env{Vars: map[string]string{}}
	logs, err := NewSystem(cfg, env, []string{"logs"})
	if err != nil {
		t.Fatal(err)
	}
	if logs.Command() != "system" || logs.Scope() != "logs" {
		t.Errorf("command %q scope %q", logs.Command(), logs.Scope())
	}
	for check, want := range map[string]bool{"logs.oom_kill": true, "services.failed": false, "logsx.y": false} {
		if got := logs.Owns(check); got != want {
			t.Errorf("logs scope owns %s = %v", check, got)
		}
	}
	full, err := NewSystem(cfg, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if full.Scope() != "" || !full.Owns("services.failed") || !full.Owns("logs.oom_kill") {
		t.Errorf("an unscoped system scanner owns every part: scope %q", full.Scope())
	}
}

// A narrowed system rescan resolves the tasks of its own parts only.
func TestScopedSystemRunResolvesItsParts(t *testing.T) {
	e, c := engine(t)
	ctx := context.Background()
	full := &fakeScanner{command: "system", findings: []finding.Finding{
		fnd("logs.oom_kill", "journal", finding.Error), fnd("services.failed", "x.service", finding.Error)}}
	if _, err := e.Execute(ctx, full, nil); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	sys, err := NewSystem(defaultConfig(t), &exec.Env{Vars: map[string]string{}}, []string{"logs"})
	if err != nil {
		t.Fatal(err)
	}
	// The fake's run is scoped like sys, and sys decides what it owns.
	scoped := struct {
		Scanner
		Owner
	}{&fakeScanner{command: "system", scope: sys.Scope()}, sys}
	if _, err := e.Execute(ctx, scoped, nil); err != nil {
		t.Fatal(err)
	}
	if st := statuses(t, e); st["system:logs.oom_kill:journal"] != todo.Resolved || st["system:services.failed:x.service"] != todo.Open {
		t.Errorf("logs-only rescan: %v", st)
	}
}

func TestNewPackagesScope(t *testing.T) {
	cfg := defaultConfig(t)
	env := &exec.Env{Vars: map[string]string{}, Home: t.TempDir()}
	all := slices.Clone(cfg.Packages.Managers)
	slices.Reverse(all)
	s, err := NewPackages(cfg, env, all)
	if err != nil {
		t.Fatal(err)
	}
	if s.Command() != "packages" || s.Scope() != "" {
		t.Errorf("naming every manager, in any order, is unscoped: %q", s.Scope())
	}
	if s, _ = NewPackages(cfg, env, []string{"uv", "cargo"}); s.Scope() != "uv,cargo" || len(s.Managers) != 2 {
		t.Errorf("a subset is the scope: %q %d", s.Scope(), len(s.Managers))
	}
	if _, err := NewPackages(cfg, env, []string{"bogus"}); err == nil {
		t.Error("an unknown manager is an error")
	}
}

// pnpmManager is installed with fakepm and reports node as its runtime.
type pnpmManager struct {
	envManager
	node string
}

func (pnpmManager) Name() string { return "pnpm" }
func (m pnpmManager) Runtime(context.Context, *exec.Env) *packages.Runtime {
	return &packages.Runtime{Name: packages.RuntimeNode, Version: m.node}
}
func (pnpmManager) Collect(context.Context, *exec.Env) ([]packages.Package, error) { return nil, nil }

type memRuntimes struct {
	m        map[string]packages.RuntimeMeta
	saved    []packages.RuntimeMeta
	settings map[string]string
	err      error
}

func (s *memRuntimes) RuntimeMeta(context.Context) (map[string]packages.RuntimeMeta, error) {
	return maps.Clone(s.m), s.err
}

func (s *memRuntimes) SaveRuntimeMeta(_ context.Context, ms []packages.RuntimeMeta) error {
	s.saved = append(s.saved, ms...)
	return nil
}

func (s *memRuntimes) Setting(_ context.Context, k string) (string, error) { return s.settings[k], nil }

func (s *memRuntimes) SetSetting(_ context.Context, k, v string) error {
	s.settings[k] = v
	return nil
}

type runtimeTable map[string]packages.RuntimeMeta

// LookupRuntime names the meta even on failure, as registry.Client does.
func (l runtimeTable) LookupRuntime(_ context.Context, name string) (packages.RuntimeMeta, error) {
	m, ok := l[name]
	if !ok {
		return packages.RuntimeMeta{Name: name}, errors.New("unreachable")
	}
	return m, nil
}

func fakepmPath(t *testing.T) *exec.Env {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "fakepm"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	return &exec.Env{Vars: map[string]string{"PATH": bin}, Home: t.TempDir()}
}

func TestPackagesRuntimeStatuses(t *testing.T) {
	env := fakepmPath(t)
	rts := &memRuntimes{m: map[string]packages.RuntimeMeta{}, settings: map[string]string{}}
	node := packages.RuntimeMeta{Name: packages.RuntimeNode, Newest: "24.1.0", Lines: map[string]string{"22": "22.9.0", "24": "24.1.0"}}
	s := &PackagesScanner{Env: env, Managers: []packages.Manager{pnpmManager{node: "22.3.0"}}, Runtimes: rts,
		RuntimeRefresh: &RuntimeRefresh{Names: []string{packages.RuntimeNode, packages.RuntimeGo}, Looker: runtimeTable{"node": node}},
		Now:            time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	out, data := scanPackages(t, s)

	major := packages.VersionLine(packages.RuntimeNode, "22.3.0")
	if rts.settings[NodeMajorSetting] != major || data.NodeMajor != major {
		t.Errorf("the node major of the pnpm globals is remembered: setting %q data %q", rts.settings[NodeMajorSetting], data.NodeMajor)
	}
	if len(rts.saved) != 2 || !slices.Contains(out.Errors, "go release lookup: unreachable") {
		t.Errorf("both lookups are saved and the failed one reported: saved %v errors %q", rts.saved, out.Errors)
	}
	if len(data.Runtimes) == 0 {
		t.Error("runtime statuses are described")
	}

	// A later pnpm under another node keeps the remembered major, and no
	// refresh means no lookups.
	rts.saved = nil
	s.Managers, s.RuntimeRefresh = []packages.Manager{pnpmManager{node: "24.0.0"}}, nil
	if _, data = scanPackages(t, s); data.NodeMajor != major || len(rts.saved) != 0 {
		t.Errorf("node major %q, saved %v", data.NodeMajor, rts.saved)
	}

	rts.err = errors.New("disk")
	if _, err := s.Scan(context.Background(), progress.Nop); err == nil || !strings.Contains(err.Error(), "load runtime cache") {
		t.Errorf("a runtime cache failure fails the scan: %v", err)
	}
}

func TestRepoStats(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	gh := func(owner, name string) repos.Repo {
		return repos.Repo{Host: "github.com", Owner: owner, Name: name, Remote: "git@github.com:" + owner + "/" + name}
	}
	a, b, c := gh("me", "a"), gh("other", "b"), repos.Repo{Path: "/local"}
	a.Modified, a.Ahead = 1, 2
	b.Behind = 3
	c.Untracked = 1
	metas := map[string]repos.Meta{a.Key(): {CheckedAt: now.Add(-48 * time.Hour)}, b.Key(): {CheckedAt: now.Add(-time.Hour)}}
	got := map[string]string{}
	for _, s := range repoStats([]repos.Repo{a, b, c}, metas, "ME", now) {
		got[s.Name] = s.Value + "|" + s.Note
	}
	want := map[string]string{"repos": "3|1 mine", "local changes": "2|", "unpushed": "1|", "behind": "1|",
		"checked": "oldest " + run.HumanAge(48*time.Hour) + " ago|"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	for _, tc := range []struct {
		metas map[string]repos.Meta
		want  string
	}{
		{nil, "never; run audit repos refresh"},
		{map[string]repos.Meta{a.Key(): {CheckedAt: now}}, "just now"},
	} {
		if st := repoStats([]repos.Repo{a}, tc.metas, "", now); st[4].Value != tc.want {
			t.Errorf("checked = %q, want %q", st[4].Value, tc.want)
		}
	}
}

func git(t *testing.T, env *exec.Env, dir string, args ...string) {
	t.Helper()
	cmd := osexec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+env.Home, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// A repos scan with Fetch fetches every repo first, so one that fell
// behind its remote shows as behind.
func TestReposScanFetches(t *testing.T) {
	if _, err := osexec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	env := osEnv(home)
	remote, work, root := filepath.Join(home, "remote.git"), filepath.Join(home, "work"), filepath.Join(home, "src")
	git(t, env, home, "init", "-q", "--bare", "-b", "main", remote)
	git(t, env, home, "clone", "-q", remote, work)
	git(t, env, work, "commit", "-q", "--allow-empty", "-m", "one")
	git(t, env, work, "push", "-q", "origin", "HEAD:main")
	git(t, env, home, "clone", "-q", remote, filepath.Join(root, "repo"))
	git(t, env, work, "commit", "-q", "--allow-empty", "-m", "two")
	git(t, env, work, "push", "-q", "origin", "HEAD:main")

	cfg := defaultConfig(t)
	cfg.Repos.Roots, cfg.Repos.LinkDirs = []string{"~/src"}, nil
	s := NewRepos(cfg, env, "me")
	if s.Command() != "repos" || s.Scope() != "" || s.GhqRoot != "" || !slices.Equal(s.Options.Roots, []string{root}) {
		t.Errorf("roots %v ghq root %q", s.Options.Roots, s.GhqRoot)
	}
	// Fetches and sync steps run in this environment: it never prompts and
	// still finds git and the user's config.
	if fe := s.FetchEnv(); fe.Get("GIT_TERMINAL_PROMPT") != "0" || fe.Get("GIT_SSH_COMMAND") == "" ||
		fe.Get("PATH") != env.Get("PATH") || fe.Get("HOME") != home || fe.Which("git") == "" {
		t.Errorf("fetch env: %v", fe.Vars)
	}
	env.Vars["GIT_SSH_COMMAND"] = "ssh -i key"
	if fe := s.FetchEnv(); fe.Get("GIT_SSH_COMMAND") != "ssh -i key" || env.Get("GIT_TERMINAL_PROMPT") != "" {
		t.Error("a set GIT_SSH_COMMAND is kept, and the scan's own environment is not changed")
	}
	delete(env.Vars, "GIT_SSH_COMMAND")
	stat := func(out *Outcome, name string) string {
		for _, st := range out.Stats {
			if st.Name == name {
				return st.Value
			}
		}
		return ""
	}
	out, err := s.Scan(context.Background(), progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	if stat(out, "repos") != "1" || stat(out, "behind") != "0" {
		t.Errorf("without a fetch the clone does not know it is behind: %v", out.Stats)
	}
	s.Fetch = true
	if out, err = s.Scan(context.Background(), progress.Nop); err != nil {
		t.Fatal(err)
	}
	var d repos.Data
	if err := json.Unmarshal(out.Data, &d); err != nil || len(d.Repos) != 1 || d.Repos[0].Behind != 1 {
		t.Errorf("after a fetch the clone is 1 behind: %v %+v; errors %q", err, d.Repos, out.Errors)
	}

	errs := FetchAll(context.Background(), env, []string{filepath.Join(root, "repo"), home}, 2, 10*time.Second, nil)
	if len(errs) != 1 || !strings.HasPrefix(errs[0], "fetch "+home+": ") {
		t.Errorf("a failed fetch is one error line: %q", errs)
	}
}

// The thin adapters map the config onto their package's options and wrap
// its scan.
func TestScannerAdapters(t *testing.T) {
	cfg := defaultConfig(t)
	home := t.TempDir()
	env := osEnv(home)
	for _, d := range []string{"cfg", "data", "bin/one", "bin/two"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "bin/one/hello"), []byte("#!/bin/sh\n# Say hello.\necho hi\n"), 0o700); err != nil { // #nosec G306 -- test script
		t.Fatal(err)
	}
	cfg.Configs.Roots, cfg.Configs.MaxKB = []string{"~/cfg"}, 3
	cfg.Files.Roots, cfg.Files.Exclude, cfg.Files.Downloads, cfg.Files.HashLimitGB = []string{"~/data"}, nil, "~/dl", 2
	cfg.Scripts.Roots = []string{"~/bin/*"}
	cfg.Repos.Roots = nil

	cs := NewConfigs(cfg, env, nil)
	if !slices.Equal(cs.Options.Roots, []string{filepath.Join(home, "cfg")}) || cs.Options.MaxBytes != 3<<10 {
		t.Errorf("configs options: %+v", cs.Options)
	}
	fs := NewFiles(cfg, env)
	if !slices.Equal(fs.Options.Roots, []string{filepath.Join(home, "data")}) || fs.Options.HashLimit != 2<<30 ||
		fs.Options.Downloads != filepath.Join(home, "dl") {
		t.Errorf("files options: %+v", fs.Options)
	}
	ss := NewScripts(cfg, env)
	if !slices.Equal(ss.Options.Roots, []string{filepath.Join(home, "bin/one"), filepath.Join(home, "bin/two")}) {
		t.Errorf("script root globs are expanded: %v", ss.Options.Roots)
	}
	as := &AIScanner{Options: ai.Options{Env: env}}

	for _, tc := range []struct {
		s    Scanner
		cmd  string
		data any
	}{
		{cs, configs.Command, &configs.Data{}},
		{fs, files.Command, &files.Data{}},
		{ss, scripts.Command, &scripts.Data{}},
		{as, ai.Command, &ai.Data{}},
	} {
		if tc.s.Command() != tc.cmd || tc.s.Scope() != "" {
			t.Errorf("%T: command %q scope %q", tc.s, tc.s.Command(), tc.s.Scope())
		}
		out, err := tc.s.Scan(context.Background(), progress.Nop)
		if err != nil {
			t.Fatalf("%s: %v", tc.cmd, err)
		}
		if err := json.Unmarshal(out.Data, tc.data); err != nil || len(out.Stats) == 0 {
			t.Errorf("%s: data %v, %d stats", tc.cmd, err, len(out.Stats))
		}
	}
}

func TestEnvironmentScanner(t *testing.T) {
	if _, err := osexec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	cfg := defaultConfig(t)
	cfg.Environment.Shells = []string{"bash"}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".bash_profile"), []byte("export X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewEnvironment(cfg, osEnv(home))
	if err != nil {
		t.Fatal(err)
	}
	if s.Command() != "environment" || s.Scope() != "" {
		t.Errorf("command %q scope %q", s.Command(), s.Scope())
	}
	if s.LintedElsewhere(filepath.Join(home, ".bash_profile")) {
		t.Error("a startup file outside the script roots is linted here")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, progress.Nop); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled scan is an error: %v", err)
	}
	out, err := s.Scan(context.Background(), progress.Nop)
	if err != nil || len(out.Stats) == 0 || len(out.Data) == 0 {
		t.Errorf("scan: %v, %d stats", err, len(out.Stats))
	}
}

// With the store gone, nothing is scanned into the void: loading fails
// before a scan and saving fails after one.
func TestEngineStoreFailures(t *testing.T) {
	e, _ := engine(t)
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s := &fakeScanner{command: "system"}
	if _, err := e.Resolve(context.Background(), s, Auto, nil); err == nil || s.scans != 0 {
		t.Errorf("auto with an unreadable store: %v after %d scans", err, s.scans)
	}
	if _, err := e.Execute(context.Background(), s, nil); err == nil || !strings.Contains(err.Error(), "save run") {
		t.Errorf("execute with an unwritable store: %v", err)
	}
}
