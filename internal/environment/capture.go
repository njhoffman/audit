// Package environment audits the shell environment: PATH and variables as a
// fresh login shell sets them, what startup prints, how long it takes, and
// static problems in the startup scripts.
package environment

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	osexec "os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/njhoffman/audit/internal/exec"
)

// Startup capture modes.
const (
	ModeTTY   = "tty"
	ModeNoTTY = "notty"
)

// Capture is one observed shell startup.
type Capture struct {
	Shell    string            `json:"shell"`
	Mode     string            `json:"mode"`
	Path     string            `json:"path"`
	Output   []string          `json:"output,omitempty"` // unexpected lines, ANSI stripped
	Filtered int               `json:"filtered"`         // lines dropped as known output
	Duration time.Duration     `json:"duration"`
	Code     int               `json:"code"`
	TimedOut bool              `json:"timed_out,omitempty"`
	Err      string            `json:"error,omitempty"`
	Env      map[string]string `json:"-"`
	// Stats is nil when the shell exited before collecting them.
	Stats *ShellStats `json:"stats,omitempty"`
}

// Capturer starts a shell the way a terminal or a tool would.
type Capturer interface {
	Capture(ctx context.Context, shell string, mode string) Capture
	Tracer
}

// OSCapturer runs `<shell> -lic` with a clean environment, under a pty for
// ModeTTY and in a new session without a terminal for ModeNoTTY (how IDEs and
// other tools start login shells).
type OSCapturer struct {
	Env     *exec.Env
	Timeout time.Duration
	Known   []*regexp.Regexp
}

// builtinKnown is output every shell prints on these code paths.
var builtinKnown = []*regexp.Regexp{
	regexp.MustCompile(`^logout$`),
	regexp.MustCompile(`^bash: cannot set terminal process group`),
	regexp.MustCompile(`^bash: no job control in this shell$`),
}

// captureScript runs once startup is done. It stamps the time first, so the
// measured start-up excludes the dump, exit, and background jobs that keep
// the output open afterwards. captureScriptFor adds the shell's stats.
const captureScript = `date +%s%N >"$AUDIT_ENV_OUT.t"; env -0 >"$AUDIT_ENV_OUT"; exit`

// Capture implements Capturer.
func (c *OSCapturer) Capture(ctx context.Context, shell, mode string) Capture {
	res := Capture{Shell: shell, Mode: mode, Path: c.Env.Which(shell)}
	if res.Path == "" {
		res.Code, res.Err = exec.ExitNotFound, shell+" is not installed"
		return res
	}
	envFile, err := os.CreateTemp("", "audit-env-*")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	envPath := envFile.Name()
	_ = envFile.Close()
	stampPath, statsPath := envPath+".t", envPath+".s"
	defer func() { _ = os.Remove(envPath); _ = os.Remove(stampPath); _ = os.Remove(statsPath) }()

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := osexec.CommandContext(ctx, res.Path, "-lic", captureScriptFor(shell)) // #nosec G204 -- configured shell
	cmd.Dir = c.Env.Home
	cmd.Env = c.cleanEnv(res.Path, mode, envPath)
	cmd.WaitDelay = time.Second
	// Both modes start the shell as a session leader, so its pid is the
	// process group: kill the group so background jobs it started go too.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }

	start := time.Now()
	var out bytes.Buffer
	if mode == ModeTTY {
		err = runPTY(cmd, &out)
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout, cmd.Stderr = &out, &out
		err = cmd.Run()
	}
	res.Duration = time.Since(start)
	if d, ok := readStamp(stampPath, start); ok {
		res.Duration = d
	}
	var exitErr *osexec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.TimedOut, res.Code = true, exec.ExitTimeout
	case errors.As(err, &exitErr):
		res.Code = exitErr.ExitCode()
	case errors.Is(err, osexec.ErrWaitDelay):
		// The shell exited cleanly but a background job it started still
		// holds the output open; that is not a startup failure.
	case err != nil:
		res.Code, res.Err = exec.ExitNotFound, err.Error()
	}
	res.Output, res.Filtered = filterOutput(out.String(), append(builtinKnown, c.Known...))
	if data, err := os.ReadFile(envPath); err == nil && len(data) > 0 { // #nosec G304 -- our temp file
		res.Env = parseEnv0(data)
	}
	if data, err := os.ReadFile(statsPath); err == nil { // #nosec G304 -- our temp file
		res.Stats = parseStats(data)
	}
	if res.Stats != nil && res.Env != nil {
		res.Stats.Counts["bins"] = countBins(res.Env["PATH"])
	}
	return res
}

// readStamp parses the nanosecond timestamp captureScript wrote and returns
// how long after start it was taken.
func readStamp(path string, start time.Time) (time.Duration, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- our temp file
	if err != nil {
		return 0, false
	}
	ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	d := time.Unix(0, ns).Sub(start)
	return d, d > 0
}

// ptyDrain is how long output may keep arriving after the shell exits.
const ptyDrain = time.Second

func runPTY(cmd *osexec.Cmd, out io.Writer) error {
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		return err
	}
	// Reading ends with EIO once every holder of the slave side is gone. A
	// background job can hold it indefinitely, so after the shell exits the
	// reader gets ptyDrain and then the master is closed under it.
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, f)
		close(copied)
	}()
	err = cmd.Wait()
	select {
	case <-copied:
	case <-time.After(ptyDrain):
	}
	_ = f.Close()
	<-copied
	return err
}

// cleanEnv is what a display manager or terminal hands a new login shell:
// identity, locale, display and a minimal PATH. Everything else must come
// from the startup files.
func (c *OSCapturer) cleanEnv(shellPath, mode, envPath string) []string {
	term := "xterm-256color"
	if mode != ModeTTY {
		term = "dumb"
	}
	env := []string{
		"HOME=" + c.Env.Home,
		"SHELL=" + shellPath,
		"TERM=" + term,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"AUDIT_ENV_OUT=" + envPath,
	}
	for _, k := range []string{"USER", "LOGNAME", "LANG", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v := c.Env.Get(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

var (
	ansiCSI = regexp.MustCompile(`\x1b\[[0-9;?<=>]*[ -/]*[@-~]`)
	ansiOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)
	ansiESC = regexp.MustCompile(`\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMNOZc]`)
)

// stripANSI removes terminal escape sequences and carriage returns.
func stripANSI(s string) string {
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	s = ansiESC.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "")
}

// filterOutput returns the non-blank lines of out that match no known
// pattern, and how many lines were dropped as known.
func filterOutput(out string, known []*regexp.Regexp) (lines []string, filtered int) {
	for _, line := range strings.Split(stripANSI(out), "\n") {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if matchesAny(line, known) {
			filtered++
			continue
		}
		lines = append(lines, line)
	}
	return lines, filtered
}

func matchesAny(s string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// parseEnv0 parses `env -0` output.
func parseEnv0(data []byte) map[string]string {
	vars := map[string]string{}
	for _, kv := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok && k != "" {
			vars[k] = v
		}
	}
	return vars
}
