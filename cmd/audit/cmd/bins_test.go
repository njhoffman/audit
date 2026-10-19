package cmd

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

// fakeRelease plays gh for one repo whose latest release v2.0 ships
// tool-v2.0-linux-amd64.tar.gz holding tool-v2.0/tool; tar really runs.
type fakeRelease struct {
	mu      sync.Mutex
	tarball []byte
	digest  string
	calls   []string
}

func newFakeRelease(t *testing.T, binary string) *fakeRelease {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name, body string
		mode       int64
	}{{"tool-v2.0/README", "readme", 0o644}, {"tool-v2.0/tool", binary, 0o755}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return &fakeRelease{tarball: buf.Bytes(), digest: "sha256:" + hex.EncodeToString(sum[:])}
}

func (f *fakeRelease) Run(ctx context.Context, name string, args []string, _ exec.Options) exec.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == "gh api repos/o/tool/releases/latest":
		digest := ""
		if f.digest != "" {
			digest = fmt.Sprintf(`,"digest":%q`, f.digest)
		}
		return exec.Result{Stdout: `{"tag_name":"v2.0","assets":[{"name":"tool-v2.0-darwin-amd64.tar.gz"},` +
			`{"name":"tool-v2.0-linux-amd64.tar.gz"` + digest + `}]}`}
	case strings.HasPrefix(cmd, "gh release download v2.0 -R o/tool -p tool-v2.0-linux-amd64.tar.gz -O "):
		if err := os.WriteFile(args[8], f.tarball, 0o600); err != nil {
			return exec.Result{Code: 1, Stderr: err.Error()}
		}
		return exec.Result{}
	case name == "tar":
		out, err := osexec.CommandContext(ctx, "/usr/bin/tar", args...).CombinedOutput() // #nosec G204 -- test
		if err != nil {
			return exec.Result{Code: 1, Stderr: string(out)}
		}
		return exec.Result{}
	case strings.HasSuffix(name, "/tool") && cmd == name+" --version":
		return exec.Result{Stdout: "tool 1.0\n"}
	}
	return exec.Result{Code: exec.ExitNotFound, Stderr: name + ": command not found"}
}

func binsEnv(t *testing.T) (bin string) {
	t.Helper()
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin = filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "tool"), []byte("\x7fELF old"), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	writeConfig(t, cfgHome, "packages: {env: process, managers: [bins], scan_dirs: ["+bin+"]}\n")
	return bin
}

func runBins(t *testing.T, f *fakeRelease, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut)
	a.interactive = func() bool { return false }
	a.runner, a.looker = f, latestLooker{}
	root := newRootCmd(a)
	root.SetArgs(args)
	e := root.ExecuteContext(context.Background())
	a.close()
	return result{out.String(), errOut.String(), e, a}
}

func TestBinsTrackAndInstall(t *testing.T) {
	bin := binsEnv(t)
	f := newFakeRelease(t, "\x7fELF new")
	r := runBins(t, f, "packages", "bins")
	if r.e != nil || !strings.Contains(r.out, "tool") || !strings.Contains(r.out, "elf") {
		t.Fatalf("list: %v\n%s", r.e, r.out)
	}
	if r := runBins(t, f, "packages", "bins", "install", "tool"); r.e == nil || !strings.Contains(r.e.Error(), "is not tracked") {
		t.Errorf("install untracked: %v", r.e)
	}
	r = runBins(t, f, "packages", "bins", "track", "tool", "o/tool")
	if r.e != nil || r.out != "Tracking tool (1.0) from o/tool; latest release v1.1.0.\n" {
		t.Fatalf("track: %v %q", r.e, r.out)
	}
	if r := runBins(t, f, "packages", "bins", "track", "nope", "o/nope"); r.e == nil || !strings.Contains(r.e.Error(), "no loose binary nope") {
		t.Errorf("track missing: %v", r.e)
	}

	r = runBins(t, f, "packages", "bins", "install", "tool")
	if r.e != nil || !strings.Contains(r.out, "Installed tool v2.0 from tool-v2.0-linux-amd64.tar.gz (sha256 checked)") {
		t.Fatalf("install: %v\n%s", r.e, r.out)
	}
	if b, _ := os.ReadFile(filepath.Join(bin, "tool")); string(b) != "\x7fELF new" { // #nosec G304 -- test file
		t.Errorf("binary not replaced: %q", b)
	}
	if st, _ := os.Stat(filepath.Join(bin, "tool")); st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode())
	}
	backup := filepath.Join(os.Getenv("XDG_DATA_HOME"), "audit", "bins", "tool-1.0")
	if b, err := os.ReadFile(backup); err != nil || string(b) != "\x7fELF old" { // #nosec G304 -- test file
		t.Errorf("backup: %q %v", b, err)
	}
	if r := runBins(t, f, "packages", "bins", "install", "tool"); r.e != nil || r.out != "tool is already at v2.0.\n" {
		t.Errorf("again: %v %q", r.e, r.out)
	}
	r = runBins(t, f, "packages", "bins", "-j")
	if r.e != nil || !strings.Contains(r.out, `"version": "v2.0"`) || !strings.Contains(r.out, `"ident": "o/tool"`) {
		t.Errorf("json after install: %v\n%s", r.e, r.out)
	}
}

func TestBinsInstallChecksums(t *testing.T) {
	bin := binsEnv(t)
	f := newFakeRelease(t, "\x7fELF new")
	if r := runBins(t, f, "packages", "bins", "track", "tool", "o/tool", "-s", "v1.0"); r.e != nil {
		t.Fatal(r.e)
	}
	f.digest = "sha256:" + strings.Repeat("0", 64)
	if r := runBins(t, f, "packages", "bins", "install", "tool"); r.e == nil || !strings.Contains(r.e.Error(), "checksum mismatch") {
		t.Errorf("mismatch: %v", r.e)
	}
	if b, _ := os.ReadFile(filepath.Join(bin, "tool")); string(b) != "\x7fELF old" { // #nosec G304 -- test file
		t.Error("a bad download must leave the binary alone")
	}
	f.digest = ""
	if r := runBins(t, f, "packages", "bins", "install", "tool"); r.e == nil || !strings.Contains(r.e.Error(), "--skip-checksum") {
		t.Errorf("no checksum: %v", r.e)
	}
	r := runBins(t, f, "packages", "bins", "install", "tool", "-k")
	if r.e != nil || !strings.Contains(r.out, "(no checksum published)") {
		t.Errorf("-k: %v %s", r.e, r.out)
	}
}

func TestBinsUpdatePlan(t *testing.T) {
	binsEnv(t)
	f := newFakeRelease(t, "\x7fELF new")
	if r := runBins(t, f, "packages", "bins", "track", "tool", "o/tool", "-s", "v1.0.0"); r.e != nil {
		t.Fatal(r.e)
	}
	r := runBins(t, f, "packages", "update", "-N")
	if r.e != nil || !strings.Contains(r.out, "bins:tool") || !strings.Contains(r.out, packages.SelfCommand+" packages bins install tool") {
		t.Errorf("tracked binaries are planned: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if r := runBins(t, f, "packages", "bins", "untrack", "tool"); r.e != nil || !strings.Contains(r.out, "No longer tracking tool") {
		t.Errorf("untrack: %v %q", r.e, r.out)
	}
	if r := runBins(t, f, "packages", "bins", "untrack", "tool"); r.e == nil {
		t.Error("untracking twice must fail")
	}
}

func TestUnpackers(t *testing.T) {
	dir := t.TempDir()
	// A tar member that tries to escape lands inside the target.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range []string{"../../evil", "pkg/tool"} {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: 2, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("hi"))
	}
	_ = tw.Close()
	archive := filepath.Join(dir, "a.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := untar(archive, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "evil")); err != nil {
		t.Errorf("escaping member should land inside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
		t.Error("a member escaped the target directory")
	}

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("dir/tool")
	_, _ = w.Write([]byte("zipped"))
	_ = zw.Close()
	zfile := filepath.Join(dir, "t.zip")
	if err := os.WriteFile(zfile, zbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{env: &exec.Env{Vars: map[string]string{}}}
	got, err := a.unpack(context.Background(), zfile, "tool", filepath.Join(dir, "z"))
	if b, _ := os.ReadFile(got); err != nil || string(b) != "zipped" { // #nosec G304 -- test file
		t.Errorf("zip: %q %v", got, err)
	}

	var gbuf bytes.Buffer
	gw := gzip.NewWriter(&gbuf)
	_, _ = gw.Write([]byte("gunzipped"))
	_ = gw.Close()
	gfile := filepath.Join(dir, "tool.gz")
	if err := os.WriteFile(gfile, gbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = a.unpack(context.Background(), gfile, "tool", filepath.Join(dir, "g"))
	if b, _ := os.ReadFile(got); err != nil || string(b) != "gunzipped" { // #nosec G304 -- test file
		t.Errorf("gz: %q %v", got, err)
	}
	raw := filepath.Join(dir, "tool-linux-amd64")
	if err := os.WriteFile(raw, []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := a.unpack(context.Background(), raw, "tool", filepath.Join(dir, "r")); err != nil || got != raw {
		t.Errorf("a bare asset is the binary: %q %v", got, err)
	}
}
