// Package exec runs external commands for scanners with closed stdin, captured
// output and a timeout, behind an interface that tests can replace.
package exec

import (
	"bytes"
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Exit codes reported when the command could not produce its own.
const (
	ExitNotFound = 127
	ExitTimeout  = 124
)

// DefaultTimeout bounds a command when Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Options tunes one command invocation.
type Options struct {
	Timeout time.Duration
	Dir     string   // working directory; defaults to the environment's home
	Unset   []string // environment variables removed for this call
	Stdin   string
}

// Result is the outcome of one invocation.
type Result struct {
	Code   int
	Stdout string
	Stderr string
}

// OK reports a zero exit status.
func (r Result) OK() bool { return r.Code == 0 }

// Runner executes commands.
type Runner interface {
	Run(ctx context.Context, name string, args []string, opts Options) Result
}

// Env is the process context a scanner sees: environment variables, home and
// a command runner. Scanners read Env instead of the real process state so
// tests can describe a machine in a temp dir.
type Env struct {
	Vars   map[string]string
	Home   string
	Runner Runner
}

// FromOS captures the current process environment.
func FromOS() *Env {
	vars := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	home, _ := os.UserHomeDir()
	e := &Env{Vars: vars, Home: home}
	e.Runner = &OSRunner{env: e}
	return e
}

// WithVars returns a copy of e over vars. An OSRunner is rebound so commands
// see the new variables; other runners (test fakes) are shared.
func (e *Env) WithVars(vars map[string]string) *Env {
	n := &Env{Vars: vars, Home: e.Home, Runner: e.Runner}
	if _, ok := e.Runner.(*OSRunner); ok {
		n.Runner = NewOSRunner(n)
	}
	return n
}

// Get returns an environment variable ("" when unset).
func (e *Env) Get(k string) string { return e.Vars[k] }

// Lookup returns an environment variable and whether it is set.
func (e *Env) Lookup(k string) (string, bool) {
	v, ok := e.Vars[k]
	return v, ok
}

// Path returns PATH split into entries (empty entries kept as "").
func (e *Env) Path() []string {
	p := e.Vars["PATH"]
	if p == "" {
		return nil
	}
	return strings.Split(p, string(os.PathListSeparator))
}

// XDG returns an XDG base directory, falling back to its spec default under home.
func (e *Env) XDG(kind string) string {
	defaults := map[string]string{
		"XDG_CONFIG_HOME": ".config",
		"XDG_DATA_HOME":   ".local/share",
		"XDG_CACHE_HOME":  ".cache",
		"XDG_STATE_HOME":  ".local/state",
	}
	if v := e.Vars[kind]; v != "" {
		return v
	}
	return filepath.Join(e.Home, defaults[kind])
}

// Expand replaces a leading ~ and $VAR / ${VAR} references using Vars.
func (e *Env) Expand(s string) string {
	if s == "~" {
		return e.Home
	}
	if strings.HasPrefix(s, "~/") {
		s = filepath.Join(e.Home, s[2:])
	}
	return os.Expand(s, func(k string) string {
		if k == "HOME" && e.Vars[k] == "" {
			return e.Home
		}
		return e.Vars[k]
	})
}

// Run executes name with args through the Runner.
func (e *Env) Run(ctx context.Context, name string, args []string, opts Options) Result {
	return e.Runner.Run(ctx, name, args, opts)
}

// Which resolves name on PATH, returning "" when absent.
func (e *Env) Which(name string) string {
	all := e.WhichAll(name)
	if len(all) == 0 {
		return ""
	}
	return all[0]
}

// WhichAll returns every executable called name on PATH, in PATH order, with
// repeated directories collapsed.
func (e *Env) WhichAll(name string) []string {
	if strings.ContainsRune(name, '/') {
		if IsExecutable(name) {
			return []string{name}
		}
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, dir := range e.Path() {
		if dir == "" {
			continue
		}
		dir = filepath.Clean(dir)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		cand := filepath.Join(dir, name)
		if IsExecutable(cand) {
			out = append(out, cand)
		}
	}
	return out
}

// IsExecutable reports whether path is a regular file (after symlinks) with
// an execute bit.
func IsExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// OSRunner runs real processes using the Env's variables.
type OSRunner struct {
	env *Env
}

// NewOSRunner returns a runner bound to env's variables and home.
func NewOSRunner(env *Env) *OSRunner { return &OSRunner{env: env} }

// Run implements Runner.
func (r *OSRunner) Run(ctx context.Context, name string, args []string, opts Options) Result {
	path := r.env.Which(name)
	if path == "" {
		return Result{Code: ExitNotFound, Stderr: name + ": command not found"}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := osexec.CommandContext(ctx, path, args...) // #nosec G204 -- scanners run fixed tool names
	cmd.Dir = opts.Dir
	if cmd.Dir == "" {
		cmd.Dir = r.env.Home
	}
	cmd.Env = r.environ(opts.Unset)
	if opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(opts.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second

	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *osexec.ExitError
	switch {
	case err == nil:
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.Code = ExitTimeout
	case errors.As(err, &exitErr):
		res.Code = exitErr.ExitCode()
		if res.Code < 0 {
			res.Code = ExitTimeout
		}
	default:
		res.Code = ExitNotFound
		if res.Stderr == "" {
			res.Stderr = err.Error()
		}
	}
	return res
}

func (r *OSRunner) environ(unset []string) []string {
	drop := map[string]bool{}
	for _, k := range unset {
		drop[k] = true
	}
	out := make([]string, 0, len(r.env.Vars))
	for k, v := range r.env.Vars {
		if !drop[k] {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// Fake is a Runner for tests. Responses match on the command name followed by
// a prefix of its arguments; the longest matching prefix wins.
type Fake struct {
	mu        sync.Mutex
	responses []fakeResponse
	Calls     [][]string
	CallOpts  []Options // options of each call, parallel to Calls
}

type fakeResponse struct {
	prefix []string
	result Result
}

// Add registers a response for commands starting with prefix.
func (f *Fake) Add(prefix []string, res Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses = append(f.responses, fakeResponse{prefix: prefix, result: res})
}

// AddOutput registers a successful response with the given stdout.
func (f *Fake) AddOutput(stdout string, prefix ...string) {
	f.Add(prefix, Result{Stdout: stdout})
}

// Run implements Runner. Unmatched commands report not-found.
func (f *Fake) Run(_ context.Context, name string, args []string, opts Options) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	argv := append([]string{name}, args...)
	f.Calls = append(f.Calls, argv)
	f.CallOpts = append(f.CallOpts, opts)
	best, bestLen := Result{Code: ExitNotFound, Stderr: name + ": command not found"}, -1
	for _, r := range f.responses {
		if len(r.prefix) > len(argv) || len(r.prefix) <= bestLen {
			continue
		}
		match := true
		for i, p := range r.prefix {
			if argv[i] != p {
				match = false
				break
			}
		}
		if match {
			best, bestLen = r.result, len(r.prefix)
		}
	}
	return best
}
