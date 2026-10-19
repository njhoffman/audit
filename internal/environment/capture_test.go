package environment

import (
	"os"
	osexec "os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/exec"
)

func TestStripANSI(t *testing.T) {
	in := "\x1b[38;5;242m  -- 0.228s ::main\x1b[39m\r\n\x1b]0;title\x07x\x1b(By\x1b=z"
	if got := stripANSI(in); got != "  -- 0.228s ::main\nxyz" {
		t.Errorf("stripANSI = %q", got)
	}
}

func TestFilterOutput(t *testing.T) {
	var known []*regexp.Regexp
	for _, k := range config.DefaultKnownOutput {
		known = append(known, regexp.MustCompile(k))
	}
	known = append(known, builtinKnown...)
	out := "\r\n\n\x1b[38;5;242m  -- 0.228s ::main <> /pts/13\x1b[39m\r\nlogout\nreal problem  \n\t\n"
	lines, filtered := filterOutput(out, known)
	if !reflect.DeepEqual(lines, []string{"real problem"}) || filtered != 2 {
		t.Errorf("filterOutput = %q, %d", lines, filtered)
	}
}

func TestParseEnv0(t *testing.T) {
	got := parseEnv0([]byte("A=1\x00B=x=y\x00MULTI=a\nb\x00=bad\x00noeq\x00"))
	want := map[string]string{"A": "1", "B": "x=y", "MULTI": "a\nb"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnv0 = %v", got)
	}
}

func TestCaptureMissingShell(t *testing.T) {
	env, _, _ := testEnv(t)
	c := (&OSCapturer{Env: env}).Capture(ctx, "nosuchshell", ModeTTY)
	if c.Code != exec.ExitNotFound || c.Path != "" || !strings.Contains(c.Err, "not installed") {
		t.Errorf("capture = %+v", c)
	}
}

// TestCaptureRealBash starts a real bash login shell in a scratch home in
// both modes, checking output capture, known-output filtering, the captured
// environment and timeouts.
func TestCaptureRealBash(t *testing.T) {
	bash, err := osexec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	if _, err := osexec.LookPath("env"); err != nil {
		t.Skip("env not installed")
	}
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".bash_profile"),
		"export AUDIT_TEST_VAR=from-profile\necho banner-ok\necho 'unexpected line'\n")
	env := &exec.Env{Vars: map[string]string{"HOME": home, "PATH": filepath.Dir(bash) + ":/usr/bin:/bin"}, Home: home}
	env.Runner = exec.NewOSRunner(env)
	c := &OSCapturer{Env: env, Timeout: 10 * time.Second, Known: []*regexp.Regexp{regexp.MustCompile(`^banner-ok$`)}}

	for _, mode := range []string{ModeTTY, ModeNoTTY} {
		got := c.Capture(ctx, "bash", mode)
		if got.Code != 0 || got.TimedOut || got.Err != "" {
			t.Fatalf("%s: capture failed: %+v", mode, got)
		}
		if !reflect.DeepEqual(got.Output, []string{"unexpected line"}) {
			t.Errorf("%s: output = %q", mode, got.Output)
		}
		if got.Filtered < 1 {
			t.Errorf("%s: filtered = %d", mode, got.Filtered)
		}
		if got.Env["AUDIT_TEST_VAR"] != "from-profile" || got.Env["HOME"] != home {
			t.Errorf("%s: env not captured: %v", mode, got.Env["AUDIT_TEST_VAR"])
		}
		if _, leaked := got.Env["AUDIT_ENV_OUT"]; !leaked {
			t.Errorf("%s: env file variable should be visible to the shell", mode)
		}
	}

	writeFile(t, filepath.Join(home, ".bash_profile"), "sleep 30\n")
	c.Timeout = 300 * time.Millisecond
	start := time.Now()
	got := c.Capture(ctx, "bash", ModeNoTTY)
	if !got.TimedOut || got.Code != exec.ExitTimeout {
		t.Errorf("expected timeout: %+v", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout took %s; the process group was not killed", time.Since(start))
	}
}

// A background job started at startup keeps stdout open after the shell
// exits. Start-up time must stop at the stamp, not when the output closes,
// and the lingering job is not a failure.
func TestCaptureDurationExcludesBackgroundJobs(t *testing.T) {
	bash, err := osexec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	for _, tool := range []string{"env", "date", "sleep"} {
		if _, err := osexec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	home := t.TempDir()
	// The job outlives any plausible start-up by a wide margin, so a loaded
	// machine (tests run in parallel under -race) cannot blur the two.
	writeFile(t, filepath.Join(home, ".bash_profile"), "sleep 5 &\n")
	env := &exec.Env{Vars: map[string]string{"HOME": home, "PATH": filepath.Dir(bash) + ":/usr/bin:/bin"}, Home: home}
	env.Runner = exec.NewOSRunner(env)
	c := &OSCapturer{Env: env, Timeout: 10 * time.Second}

	for _, mode := range []string{ModeTTY, ModeNoTTY} {
		got := c.Capture(ctx, "bash", mode)
		if got.Code != 0 || got.TimedOut || got.Err != "" {
			t.Fatalf("%s: capture failed: %+v", mode, got)
		}
		if got.Duration <= 0 || got.Duration > 2500*time.Millisecond {
			t.Errorf("%s: duration %s should exclude the background job", mode, got.Duration)
		}
	}
}

func TestReadStamp(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(100, 0)
	cases := []struct {
		name, body string
		want       time.Duration
		ok         bool
	}{
		{"valid", "100250000000\n", 250 * time.Millisecond, true},
		{"garbage", "soon", 0, false},
		{"before start", "99000000000", 0, false},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, tc.name)
		writeFile(t, p, tc.body)
		got, ok := readStamp(p, start)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s: got %s %v, want %s %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := readStamp(filepath.Join(dir, "missing"), start); ok {
		t.Error("missing stamp should not parse")
	}
}

func TestCaptureCleanEnvDropsAmbientVars(t *testing.T) {
	t.Setenv("AUDIT_AMBIENT_SECRET", "x")
	env, _, home := testEnv(t)
	env.Vars["AUDIT_AMBIENT_SECRET"] = "x"
	env.Vars["LANG"] = "C.UTF-8"
	vars := (&OSCapturer{Env: env}).cleanEnv("/bin/zsh", ModeNoTTY, "/tmp/f")
	joined := strings.Join(vars, "\n")
	for _, want := range []string{"HOME=" + home, "SHELL=/bin/zsh", "TERM=dumb", "AUDIT_ENV_OUT=/tmp/f", "LANG=C.UTF-8"} {
		if !strings.Contains(joined, want) {
			t.Errorf("cleanEnv missing %s: %v", want, vars)
		}
	}
	if strings.Contains(joined, "AMBIENT") {
		t.Error("ambient variables must not reach the login shell")
	}
	_ = os.Getenv("AUDIT_AMBIENT_SECRET")
}

func realCapturer(t *testing.T, shell string) (*OSCapturer, string) {
	t.Helper()
	path, err := osexec.LookPath(shell)
	if err != nil {
		t.Skip(shell + " not installed")
	}
	home := t.TempDir()
	env := &exec.Env{Vars: map[string]string{"HOME": home, "PATH": filepath.Dir(path) + ":/usr/bin:/bin"}, Home: home}
	env.Runner = exec.NewOSRunner(env)
	return &OSCapturer{Env: env, Timeout: 10 * time.Second}, home
}

func TestTraceRealBash(t *testing.T) {
	c, home := realCapturer(t, "bash")
	lib := writeFile(t, filepath.Join(home, "lib.sh"), "SECRET_VALUE=hunter2\nf() { :; }\nf\n")
	writeFile(t, filepath.Join(home, ".bash_profile"), "export X=1\n. ~/lib.sh\n")
	if err := os.Symlink(lib, filepath.Join(home, "link.sh")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".bash_profile"), "export X=1\n. ~/lib.sh\n. ~/link.sh\n")
	files, ok := c.Trace(ctx, "bash")
	if !ok {
		t.Fatal("trace failed")
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f] = true
		if strings.Contains(f, "hunter2") {
			t.Error("trace leaked a variable value")
		}
	}
	profile, _ := filepath.EvalSymlinks(filepath.Join(home, ".bash_profile"))
	realLib, _ := filepath.EvalSymlinks(lib)
	if !got[profile] || !got[realLib] {
		t.Errorf("trace = %v", files)
	}
	n := 0
	for _, f := range files {
		if f == realLib {
			n++
		}
	}
	if n != 1 {
		t.Errorf("symlinked source should collapse to one entry: %v", files)
	}
}

func TestTraceRealZsh(t *testing.T) {
	c, home := realCapturer(t, "zsh")
	writeFile(t, filepath.Join(home, ".zshrc"), "source ~/extra.zsh\n")
	extra := writeFile(t, filepath.Join(home, "extra.zsh"), "x=1\n")
	files, ok := c.Trace(ctx, "zsh")
	if !ok {
		t.Fatal("trace failed")
	}
	rc, _ := filepath.EvalSymlinks(filepath.Join(home, ".zshrc"))
	realExtra, _ := filepath.EvalSymlinks(extra)
	idx := map[string]int{}
	for i, f := range files {
		idx[f] = i + 1
	}
	if idx[rc] == 0 || idx[realExtra] != idx[rc]+1 {
		t.Errorf("trace should list .zshrc then the file it sources: %v", files)
	}
}

func TestTraceUnsupportedShell(t *testing.T) {
	c, _ := realCapturer(t, "sh")
	if _, ok := c.Trace(ctx, "sh"); ok {
		t.Error("sh cannot be traced")
	}
}

func TestParseTrace(t *testing.T) {
	zsh := "+/etc/zsh/zshenv:1> <sourcetrace>\n+/h/a b.zsh:1> <sourcetrace>\n++/h/x.zsh:12> <sourcetrace>\n" +
		"+/h/not:1> echo <sourcetrace>\n+/etc/zsh/zshenv:1> <sourcetrace>\n"
	if got := parseTrace(zsh, zshTraceLine); !reflect.DeepEqual(got, []string{"/etc/zsh/zshenv", "/h/a b.zsh", "/h/x.zsh"}) {
		t.Errorf("zsh = %v", got)
	}
	bash := "\x01AUDIT\x01/h/.bash_profile\x01export X=1\n\x01\x01AUDIT\x01/h/lib.sh\x01f\nmultiline\x01AUDIT\x01/no\x01\n" +
		"\x01AUDIT\x01\x01exit\n"
	if got := parseTrace(bash, bashTraceLine); !reflect.DeepEqual(got, []string{"/h/.bash_profile", "/h/lib.sh"}) {
		t.Errorf("bash = %v", got)
	}
}
