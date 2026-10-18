package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/registry"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scan/procs"
	"github.com/njhoffman/audit/internal/scan/services"
	"github.com/njhoffman/audit/internal/system"
)

// Commands lists the audit commands in dashboard order.
var Commands = []string{system.Command, environment.Command, packages.Command}

// ScopeFlags names the flag that selects each command's scope.
var ScopeFlags = map[string]string{system.Command: "--only", packages.Command: "--manager"}

// RescanHint is the command line that refreshes saved results of command.
func RescanHint(command, scope string) string {
	hint := "audit " + command + " --rescan"
	if f, ok := ScopeFlags[command]; ok && scope != "" {
		hint += " " + f + " " + scope
	}
	return hint
}

// prefixOwner owns every check under one of its prefixes.
type prefixOwner []string

func (p prefixOwner) Owns(check string) bool {
	for _, pre := range p {
		if strings.HasPrefix(check, pre) {
			return true
		}
	}
	return false
}

// SystemScanner adapts system.Scanner.
type SystemScanner struct {
	*system.Scanner
}

// NewSystem builds the system scanner; only restricts it to some parts.
func NewSystem(cfg *config.Config, only []string) (*SystemScanner, error) {
	sc := cfg.System
	s, err := system.NewScanner(system.Options{
		Only: only, LogSources: sc.Logs, JournalArgs: sc.Journal, Programs: sc.Programs,
		LogMaxLines: sc.LogMaxLines, LogPatterns: sc.LogPatterns,
		Procs: procs.Options{
			TopN: sc.Procs.Top, HighCPUPct: sc.Procs.HighCPU,
			HighMemPct: float32(sc.Procs.HighMem), HighThreadCount: int32(min(sc.Procs.HighThreads, math.MaxInt32)), // #nosec G115 -- clamped
		},
		Services: services.Options{
			SkipUserScope: !sc.Services.UserUnits,
			Findings: services.FindingOptions{
				CheckUnitFilePerms: sc.Services.UnitFilePerms, HighRestartCount: sc.Services.HighRestarts,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &SystemScanner{s}, nil
}

// Command implements Scanner.
func (*SystemScanner) Command() string { return system.Command }

// Owns implements Owner: a scoped run owns the checks of its parts.
func (s *SystemScanner) Owns(check string) bool {
	pre := make(prefixOwner, len(s.Parts))
	for i, p := range s.Parts {
		pre[i] = p.Kind + "."
	}
	return pre.Owns(check)
}

// Scan implements Scanner.
func (s *SystemScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	s.Progress = rep
	res, err := s.Scanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &Outcome{Findings: res.Findings, Stats: res.Stats, Errors: res.Errors, Data: res.RawData()}, nil
}

// EnvironmentScanner adapts environment.Scanner.
type EnvironmentScanner struct {
	*environment.Scanner
}

// NewEnvironment builds the environment scanner over the process environment.
func NewEnvironment(cfg *config.Config, env *exec.Env) (*EnvironmentScanner, error) {
	ec := cfg.Environment
	s, err := environment.NewScanner(env, ec.Shells, ec.StartupFiles, ec.StartupDirs, ec.KnownOutput,
		ec.StartupTimeout, ec.SlowStartup)
	if err != nil {
		return nil, err
	}
	s.ShellcheckSeverity, s.ShellcheckExclude = ec.Shellcheck.Severity, ec.Shellcheck.Exclude
	return &EnvironmentScanner{s}, nil
}

// Command implements Scanner.
func (*EnvironmentScanner) Command() string { return environment.Command }

// Scope implements Scanner; environment runs are never partial.
func (*EnvironmentScanner) Scope() string { return "" }

// Scan implements Scanner.
func (s *EnvironmentScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	s.Progress = rep
	res := s.Scanner.Scan(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rep.Phase("checking environment", 0)
	fs := environment.Analyze(res.State)
	rep.Done()
	return &Outcome{Findings: fs, Stats: res.Stats, Data: res.RawData()}, nil
}

// PackagesScanner inventories package managers and runs the package checks.
type PackagesScanner struct {
	Env      *exec.Env
	Managers []packages.Manager
	ScanDirs []string
	// LoginShell, when set, is started as a fresh login shell and the scan
	// runs over its environment instead of Env's, so a terminal opened before
	// a PATH change does not report stale problems.
	LoginShell string
	Capturer   ShellCapturer
	// Meta is the registry cache. When set, the registry checks run over it;
	// nil skips them.
	Meta MetaStore
	// Refresh, when set, updates the cache from the registries before the
	// checks run.
	Refresh           *RegistryRefresh
	UnmaintainedAfter time.Duration
	// Now is the scan's clock; zero means time.Now.
	Now   time.Time
	scope string
}

// MetaStore holds cached registry data (implemented by *store.Store).
type MetaStore interface {
	PackageMeta(ctx context.Context) (map[string]packages.Meta, error)
	SavePackageMeta(ctx context.Context, ms []packages.Meta) error
}

// RegistryRefresh says what a scan refreshes from the registries.
type RegistryRefresh struct {
	Options   registry.Options
	UserAgent string
	// Only limits the refresh to these packages, which are looked up whatever
	// the age of their cache entry. Empty means every package.
	Only []packages.Ref
	// Looker answers the lookups; nil uses a registry.Client over the scan's
	// environment, so GOPROXY and gh come from the login shell.
	Looker registry.Looker
	// Updated receives the entries the refresh wrote, for follow-up work
	// such as tagging.
	Updated func([]packages.Meta)
}

// ShellCapturer starts a shell and reports the environment it ends up with.
type ShellCapturer interface {
	Capture(ctx context.Context, shell, mode string) environment.Capture
}

// CheckLoginEnv is the finding raised when the login shell cannot be used.
const CheckLoginEnv = "packages.login_env"

// NewPackages builds the packages scanner. only restricts it to some of the
// configured managers.
func NewPackages(cfg *config.Config, env *exec.Env, only []string) (*PackagesScanner, error) {
	names := cfg.Packages.Managers
	scope := ""
	if len(only) > 0 {
		if !sameSet(only, names) {
			scope = strings.Join(only, ",")
		}
		names = only
	}
	ms, err := packages.Resolve(names)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, len(cfg.Packages.ScanDirs))
	for i, d := range cfg.Packages.ScanDirs {
		dirs[i] = env.Expand(d)
	}
	s := &PackagesScanner{Env: env, Managers: ms, ScanDirs: dirs, scope: scope, UnmaintainedAfter: cfg.Packages.Registry.UnmaintainedAfter}
	if cfg.Packages.Env == config.EnvLogin && len(cfg.Environment.Shells) > 0 {
		s.LoginShell = cfg.Environment.Shells[0]
		s.Capturer = &environment.OSCapturer{Env: env, Timeout: cfg.Environment.StartupTimeout}
	}
	return s, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Command implements Scanner.
func (*PackagesScanner) Command() string { return packages.Command }

// Scope implements Scanner.
func (s *PackagesScanner) Scope() string { return s.scope }

// Scan implements Scanner.
func (s *PackagesScanner) Scan(ctx context.Context, rep progress.Reporter) (*Outcome, error) {
	defer rep.Done()
	env, source, envFinding := s.Env, "process", (*finding.Finding)(nil)
	if s.LoginShell != "" {
		rep.Phase("starting a login "+s.LoginShell, 0)
		le, err := loginEnv(ctx, s.Env, s.Capturer, s.LoginShell)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err != nil {
			source = "process (login " + s.LoginShell + " failed)"
			envFinding = &finding.Finding{
				Command: packages.Command, Check: CheckLoginEnv, Kind: finding.Issue, Severity: finding.Warning,
				Subject: s.LoginShell,
				Message: fmt.Sprintf("could not read the environment of a login %s (%v); checked against audit's own environment instead", s.LoginShell, err),
				Hint:    "Run `audit environment -r` to see why the shell fails to start, or set packages.env: process.",
			}
		} else {
			env, source = le, "login "+s.LoginShell
		}
	}
	rep.Phase("collecting packages", len(s.Managers))
	invs := packages.CollectAll(ctx, env, s.Managers, func(inv packages.Inventory) { rep.Step(inv.Manager) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.Now
	if now.IsZero() {
		now = time.Now()
	}
	var metas map[string]packages.Meta
	var errs []string
	var regStats []run.Stat
	if s.Meta != nil {
		var err error
		if metas, err = s.Meta.PackageMeta(ctx); err != nil {
			return nil, fmt.Errorf("load registry cache: %w", err)
		}
		if s.Refresh != nil {
			st, rerrs, err := s.refresh(ctx, rep, env, invs, metas, now)
			if err != nil {
				return nil, err
			}
			errs = append(errs, rerrs...)
			regStats = append(regStats, run.Stat{Group: "registry", Name: "looked up",
				Value: fmt.Sprintf("%d (%d failed, %d already fresh)", st.Checked, st.Failed, st.Fresh)})
		}
		regStats = append(regStats, registryAge(invs, metas, now))
	}
	rep.Phase("checking packages", 0)
	state := &packages.State{Ctx: ctx, Env: env, Inventories: invs, ScanDirs: s.ScanDirs,
		Meta: metas, UnmaintainedAfter: s.UnmaintainedAfter, Now: now}
	fs := packages.Analyze(state)
	if envFinding != nil {
		fs = append(fs, *envFinding)
		finding.Sort(fs)
	}
	data, err := json.Marshal(packages.Data{Inventories: invs})
	if err != nil {
		return nil, err
	}
	stats := append([]run.Stat{{Name: "environment", Value: source}}, packageStats(invs)...)
	stats = append(stats, regStats...)
	return &Outcome{Findings: fs, Stats: stats, Data: data, Errors: errs}, nil
}

// refresh looks the inventory up in the registries, saves what changed and
// merges it into metas.
func (s *PackagesScanner) refresh(ctx context.Context, rep progress.Reporter, env *exec.Env, invs []packages.Inventory,
	metas map[string]packages.Meta, now time.Time) (registry.Stats, []string, error) {
	r := s.Refresh
	opts := r.Options
	opts.Now = now
	var pkgs []packages.Package
	var errs []string
	if len(r.Only) == 0 {
		for _, inv := range invs {
			pkgs = append(pkgs, inv.Packages...)
		}
	} else {
		opts.Force = true
		for _, ref := range r.Only {
			found := ref.Find(invs)
			if len(found) == 0 {
				errs = append(errs, fmt.Sprintf("no installed package matches %q", ref))
			}
			for _, p := range found {
				if p.Registry() == "" {
					errs = append(errs, fmt.Sprintf("%s was installed from %s, not a registry", p.Key(), p.Source))
				}
			}
			pkgs = append(pkgs, found...)
		}
	}
	n := 0
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.Registry() != "" && !seen[p.Key()] {
			seen[p.Key()] = true
			n++
		}
	}
	looker := r.Looker
	if looker == nil {
		looker = registry.NewClient(env, r.UserAgent, opts.Timeout)
	}
	rep.Phase("checking registries", n)
	opts.OnDone = func(p packages.Package, _ error) { rep.Step(p.Name) }
	updated, st := registry.Refresh(ctx, looker, pkgs, metas, opts)
	if err := ctx.Err(); err != nil {
		return st, nil, err
	}
	if err := s.Meta.SavePackageMeta(ctx, updated); err != nil {
		return st, nil, fmt.Errorf("save registry cache: %w", err)
	}
	for _, m := range updated {
		metas[m.Key()] = m
	}
	if r.Updated != nil {
		r.Updated(updated)
	}
	return st, errs, nil
}

// registryAge reports how old the oldest cached registry answer is.
func registryAge(invs []packages.Inventory, metas map[string]packages.Meta, now time.Time) run.Stat {
	st := run.Stat{Group: "registry", Name: "checked"}
	var oldest time.Time
	total, unchecked := 0, 0
	for _, a := range packages.Annotate(invs, metas, nil, "") {
		total += len(a.Items) - countNoRegistry(a.Items)
		unchecked += a.Unchecked
		if !a.CheckedAt.IsZero() && (oldest.IsZero() || a.CheckedAt.Before(oldest)) {
			oldest = a.CheckedAt
		}
	}
	switch {
	case total == 0:
		st.Value = "no packages from a registry"
	case oldest.IsZero():
		st.Value = "never; run audit packages registry"
	default:
		st.Value = "oldest " + packages.Age(now.Sub(oldest)) + " ago"
		if unchecked > 0 {
			st.Value += fmt.Sprintf(", %d never checked", unchecked)
		}
	}
	return st
}

func countNoRegistry(items []packages.Item) int {
	n := 0
	for _, it := range items {
		if it.Registry() == "" {
			n++
		}
	}
	return n
}

// loginEnv starts shell as a fresh login shell and returns env over the
// variables it ends up with. A startup file that exits non-zero still counts
// as long as the shell got far enough to report its environment.
func loginEnv(ctx context.Context, env *exec.Env, c ShellCapturer, shell string) (*exec.Env, error) {
	cp := c.Capture(ctx, shell, environment.ModeNoTTY)
	switch {
	case cp.TimedOut:
		return nil, fmt.Errorf("it did not finish starting in time")
	case cp.Err != "":
		return nil, errors.New(cp.Err)
	case len(cp.Env) == 0 || cp.Env["PATH"] == "":
		return nil, fmt.Errorf("it exited with status %d before reporting its environment", cp.Code)
	}
	vars := maps.Clone(cp.Env)
	delete(vars, "AUDIT_ENV_OUT")
	return env.WithVars(vars), nil
}

func packageStats(invs []packages.Inventory) []run.Stat {
	var out []run.Stat
	total := 0
	for _, inv := range invs {
		v := "not installed"
		switch {
		case inv.Available && inv.Error != "":
			v = "error"
		case inv.Available:
			v = fmt.Sprintf("%d package(s)", len(inv.Packages))
			total += len(inv.Packages)
		}
		out = append(out, run.Stat{Group: "managers", Name: inv.Manager, Value: v})
	}
	return append([]run.Stat{{Name: "packages", Value: fmt.Sprint(total)}}, out...)
}
