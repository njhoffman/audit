package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// Scanner collects everything the environment checks need.
type Scanner struct {
	Env          *exec.Env // the audit process's own environment
	Capturer     Capturer
	Shells       []string
	StartupFiles []string
	StartupDirs  []string
	SlowStartup  time.Duration
	// ShellcheckSeverity is the lowest shellcheck level reported and
	// ShellcheckExclude the codes skipped; empty uses the defaults.
	ShellcheckSeverity string
	ShellcheckExclude  []string
	Workers            int
	Progress           progress.Reporter
	// LintedElsewhere reports whether another command (audit scripts)
	// already lints a file, by its resolved path. Such files are never
	// parsed or shellchecked here, even when a shell sources them.
	LintedElsewhere func(path string) bool
	// RunnerFor builds the runner for the analyzed environment; it defaults
	// to an OS runner resolving commands on that environment's PATH.
	RunnerFor func(*exec.Env) exec.Runner
}

// NewScanner returns a Scanner that captures real login shells.
func NewScanner(env *exec.Env, shells, files, dirs, known []string, timeout, slow time.Duration) (*Scanner, error) {
	res := make([]*regexp.Regexp, 0, len(known))
	for _, k := range known {
		re, err := regexp.Compile(k)
		if err != nil {
			return nil, fmt.Errorf("environment.known_output %q: %w", k, err)
		}
		res = append(res, re)
	}
	return &Scanner{
		Env: env, Capturer: &OSCapturer{Env: env, Timeout: timeout, Known: res},
		Shells: shells, StartupFiles: files, StartupDirs: dirs, SlowStartup: slow,
	}, nil
}

// Data is the persisted payload of an environment run.
type Data struct {
	EnvSource string         `json:"env_source"`
	Captures  []Capture      `json:"captures"`
	Scripts   []Script       `json:"scripts"`
	Syntax    []SyntaxResult `json:"syntax,omitempty"`
	Traced    []string       `json:"traced,omitempty"`
}

// Result is a finished scan: the state to analyze plus what to persist.
type Result struct {
	State *State
	Data  Data
	Stats []run.Stat
}

// RawData encodes the payload for run.Run.Data.
func (r *Result) RawData() json.RawMessage {
	b, _ := json.Marshal(r.Data)
	return b
}

// Scan starts each shell with and without a terminal, discovers startup
// scripts, and parses and lints them.
func (s *Scanner) Scan(ctx context.Context) *Result {
	rep := s.Progress
	if rep == nil {
		rep = progress.Nop
	}
	defer rep.Done()

	rep.Phase("starting login shells", 2*len(s.Shells))
	var captures []Capture
	for _, sh := range s.Shells {
		for _, mode := range []string{ModeTTY, ModeNoTTY} {
			rep.Step(sh + " " + mode)
			captures = append(captures, s.Capturer.Capture(ctx, sh, mode))
		}
	}

	rep.Phase("tracing sourced files", len(s.Shells))
	traced := map[string]bool{}
	loadedBy := map[string][]string{}
	for _, sh := range s.Shells {
		rep.Step(sh)
		files, ok := s.Capturer.Trace(ctx, sh)
		if !ok {
			continue
		}
		traced[sh] = true
		for _, f := range files {
			loadedBy[f] = append(loadedBy[f], sh)
		}
	}

	env, source := s.analyzedEnv(captures)

	expand := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, p := range in {
			out = append(out, s.Env.Expand(p))
		}
		return out
	}
	scripts := discover(expand(s.StartupFiles), expand(s.StartupDirs))
	for i := range scripts {
		real := scripts[i].Path
		if r, err := filepath.EvalSymlinks(real); err == nil {
			real = r
		}
		scripts[i].LoadedBy = loadedBy[real]
	}

	lint := scripts
	if s.LintedElsewhere != nil {
		lint = make([]Script, 0, len(scripts))
		for _, sc := range scripts {
			real := sc.Path
			if r, err := filepath.EvalSymlinks(real); err == nil {
				real = r
			}
			if s.LintedElsewhere(real) {
				continue
			}
			lint = append(lint, sc)
		}
	}
	syntax := s.parseAll(ctx, lint, traced, rep)

	rep.Phase("running shellcheck", 0)
	sc := s.shellcheck(ctx, lint)

	state := &State{
		Ctx: ctx, Env: env, Captures: captures, Scripts: scripts,
		Syntax: syntax, Shellcheck: sc, SlowStartup: s.SlowStartup, Traced: traced,
	}
	res := &Result{
		State: state,
		Data: Data{EnvSource: source, Captures: captures, Scripts: scripts, Syntax: failedOnly(syntax),
			Traced: sortedKeys(traced)},
	}
	res.Stats = stats(res.Data, env, sc)
	return res
}

// analyzedEnv prefers the environment of a zsh login shell under a terminal
// (what an interactive session sees), then any other capture, and falls back
// to the audit process's own environment.
func (s *Scanner) analyzedEnv(captures []Capture) (*exec.Env, string) {
	pick := func() *Capture {
		for i := range captures {
			if captures[i].Shell == "zsh" && captures[i].Mode == ModeTTY && len(captures[i].Env) > 0 {
				return &captures[i]
			}
		}
		for i := range captures {
			if len(captures[i].Env) > 0 {
				return &captures[i]
			}
		}
		return nil
	}
	c := pick()
	if c == nil {
		return s.Env, "audit process"
	}
	env := &exec.Env{Vars: c.Env, Home: s.Env.Home}
	if s.RunnerFor != nil {
		env.Runner = s.RunnerFor(env)
	} else {
		env.Runner = exec.NewOSRunner(env)
	}
	return env, c.Shell + " login shell (" + c.Mode + ")"
}

// parseAll runs `<shell> -n` on every script with each installed shell that
// loads it. Scripts nothing sources are parsed by the shells of their dialect.
func (s *Scanner) parseAll(ctx context.Context, scripts []Script, traced map[string]bool, rep progress.Reporter) []SyntaxResult {
	type job struct {
		path, shell string
		loaded      bool
	}
	var jobs []job
	for _, sc := range scripts {
		shells := sc.LoadShells(traced)
		loaded := len(shells) > 0
		if !loaded {
			shells = sc.Dialect.Shells()
		}
		for _, sh := range shells {
			if s.Env.Which(sh) != "" {
				jobs = append(jobs, job{sc.Path, sh, loaded})
			}
		}
	}
	rep.Phase("parsing startup scripts", len(jobs))
	results := make([]SyntaxResult, len(jobs))
	workers := s.Workers
	if workers <= 0 {
		workers = 8
	}
	ch := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				j := jobs[i]
				r := s.Env.Run(ctx, j.shell, []string{"-n", j.path}, exec.Options{Timeout: 10 * time.Second})
				results[i] = SyntaxResult{Path: j.path, Shell: j.shell, Loaded: j.loaded}
				switch {
				case r.Code == exec.ExitNotFound:
					results[i].Skipped = true
				case !r.OK():
					results[i].Errors = nonEmptyLines(r.Stderr + r.Stdout)
					if len(results[i].Errors) == 0 {
						results[i].Errors = []string{fmt.Sprintf("exit status %d", r.Code)}
					}
				}
				rep.Step(filepath.Base(j.path) + " (" + j.shell + ")")
			}
		}()
	}
	for i := range jobs {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return results
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, "\r "); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func failedOnly(rs []SyntaxResult) []SyntaxResult {
	var out []SyntaxResult
	for _, r := range rs {
		if len(r.Errors) > 0 {
			out = append(out, r)
		}
	}
	return out
}

type scComment struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// shellcheckExcludes are the default codes that are noise for sourced startup files:
// SC2034 flags variables set for code in other files.
const shellcheckExcludes = "SC2034"

// shellcheck lints the sh and bash scripts. Files with a shebang keep their
// declared shell; the rest are sourced and must parse under bash.
func (s *Scanner) shellcheck(ctx context.Context, scripts []Script) *ShellcheckResult {
	if s.Env.Which("shellcheck") == "" {
		return &ShellcheckResult{}
	}
	res := &ShellcheckResult{Installed: true, Comments: map[string][]string{}, Levels: map[string]string{}}
	var withShebang, sourced []string
	for _, sc := range scripts {
		if sc.Dialect == DialectZsh {
			continue
		}
		if shebangShell(sc.Path) != "" {
			withShebang = append(withShebang, sc.Path)
		} else {
			sourced = append(sourced, sc.Path)
		}
	}
	run := func(extra []string, files []string) {
		if len(files) == 0 {
			return
		}
		severity, excludes := s.ShellcheckSeverity, shellcheckExcludes
		if severity == "" {
			severity = "warning"
		}
		if len(s.ShellcheckExclude) > 0 {
			excludes = strings.Join(s.ShellcheckExclude, ",")
		}
		args := append([]string{"-f", "json1", "-S", severity, "-e", excludes}, extra...)
		args = append(args, files...)
		r := s.Env.Run(ctx, "shellcheck", args, exec.Options{Timeout: 60 * time.Second})
		var out struct {
			Comments []scComment `json:"comments"`
		}
		if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
			return
		}
		for _, c := range out.Comments {
			res.Comments[c.File] = append(res.Comments[c.File],
				fmt.Sprintf("line %d: SC%d (%s) %s", c.Line, c.Code, c.Level, c.Message))
			if c.Level == "error" || res.Levels[c.File] == "" {
				res.Levels[c.File] = c.Level
			}
		}
	}
	run(nil, withShebang)
	run([]string{"-s", "bash"}, sourced)
	return res
}

func stats(d Data, env *exec.Env, sc *ShellcheckResult) []run.Stat {
	out := []run.Stat{
		{Group: "environment", Name: "analyzed env", Value: d.EnvSource},
		{Group: "environment", Name: "variables", Value: fmt.Sprint(len(env.Vars))},
		{Group: "environment", Name: "PATH entries", Value: fmt.Sprint(len(pathEntries(env)))},
	}
	byDialect := map[Dialect]int{}
	for _, s := range d.Scripts {
		byDialect[s.Dialect]++
	}
	var dialects []string
	for dl, n := range byDialect {
		dialects = append(dialects, fmt.Sprintf("%s %d", dl, n))
	}
	sort.Strings(dialects)
	out = append(out, run.Stat{Group: "scripts", Name: "startup scripts", Value: fmt.Sprint(len(d.Scripts)),
		Note: strings.Join(dialects, ", ")})
	out = append(out, run.Stat{Group: "scripts", Name: "syntax failures", Value: fmt.Sprint(len(d.Syntax))})
	if sc != nil && sc.Installed {
		out = append(out, run.Stat{Group: "scripts", Name: "shellcheck files flagged", Value: fmt.Sprint(len(sc.Comments))})
	}
	current := filepath.Base(env.Get("SHELL"))
	for _, c := range d.Captures {
		st := run.Stat{Group: "startup", Name: c.Shell + " " + c.Mode, Value: "not installed", Extra: otherShell(c.Shell, current)}
		switch {
		case c.Path == "":
		case c.TimedOut:
			st.Value = "timed out"
		default:
			st.Value = fmt.Sprintf("%.2fs", c.Duration.Seconds())
			var notes []string
			if c.Code != 0 {
				notes = append(notes, fmt.Sprintf("exit %d", c.Code))
			}
			if len(c.Output) > 0 {
				notes = append(notes, fmt.Sprintf("%d unexpected line(s)", len(c.Output)))
			}
			st.Note = strings.Join(notes, ", ")
		}
		out = append(out, st)
	}
	return append(out, shellStats(d.Captures, current)...)
}

// otherShell reports whether shell is not the user's current one; with no
// known current shell, every shell is shown.
func otherShell(shell, current string) bool {
	return current != "" && current != "." && current != shell
}
