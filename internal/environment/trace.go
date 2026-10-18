package environment

import (
	"context"
	"errors"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Tracing reports the files a login shell sources. zsh prints them with the
// SOURCE_TRACE option; bash runs with xtrace on a private descriptor and a
// PS4 that tags every line with its source file. Xtrace also echoes
// variable values, so only the file paths are kept.
const bashTraceMarker = "\x01AUDIT\x01"

var (
	zshTraceLine  = regexp.MustCompile(`(?m)^\++(/[^\n]+?):\d+> <sourcetrace>$`)
	bashTraceLine = regexp.MustCompile(`(?m)^\x01+AUDIT\x01([^\x01\n]+)\x01`)
)

// Tracer reports which files a shell sources during login startup.
type Tracer interface {
	// Trace returns the sourced files, resolved through symlinks, in first
	// load order. ok is false when the shell cannot be traced.
	Trace(ctx context.Context, shell string) (files []string, ok bool)
}

// Trace implements Tracer for zsh and bash. Startup runs without a terminal;
// work deferred past the first prompt (zinit turbo, autoloaded functions) is
// not seen.
func (c *OSCapturer) Trace(ctx context.Context, shell string) ([]string, bool) {
	path := c.Env.Which(shell)
	isZsh := filepath.Base(shell) == "zsh"
	var args []string
	var re *regexp.Regexp
	switch {
	case isZsh:
		args, re = []string{"-o", "sourcetrace", "-lic", "exit"}, zshTraceLine
	case filepath.Base(shell) == "bash":
		args, re = []string{"-lixc", "exit"}, bashTraceLine
	}
	if path == "" || args == nil {
		return nil, false
	}
	trace, err := os.CreateTemp("", "audit-trace-*")
	if err != nil {
		return nil, false
	}
	defer func() { _ = os.Remove(trace.Name()) }()
	defer func() { _ = trace.Close() }()

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := osexec.CommandContext(ctx, path, args...) // #nosec G204 -- configured shell
	cmd.Dir = c.Env.Home
	cmd.Env = c.cleanEnv(path, ModeNoTTY, os.DevNull)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	if isZsh {
		cmd.Stderr = trace
	} else {
		cmd.Env = append(cmd.Env, "BASH_XTRACEFD=3", "PS4="+bashTraceMarker+"${BASH_SOURCE[0]}\x01")
		cmd.ExtraFiles = []*os.File{trace}
	}
	err = cmd.Run()
	var exitErr *osexec.ExitError
	if ctx.Err() != nil || (err != nil && !errors.As(err, &exitErr)) {
		return nil, false
	}
	data, err := os.ReadFile(trace.Name()) // #nosec G304 -- our temp file
	if err != nil {
		return nil, false
	}
	return parseTrace(string(data), re), true
}

func parseTrace(out string, re *regexp.Regexp) []string {
	seen := map[string]bool{}
	var files []string
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		p := strings.TrimSpace(m[1])
		if !filepath.IsAbs(p) {
			continue
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	return files
}
