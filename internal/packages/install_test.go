package packages

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

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
	// A symlink member is skipped, not written out as a file.
	hdr := &zip.FileHeader{Name: "link"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	lw, _ := zw.CreateHeader(hdr)
	_, _ = lw.Write([]byte("/etc/passwd"))
	_ = zw.Close()
	zfile := filepath.Join(dir, "t.zip")
	if err := os.WriteFile(zfile, zbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &exec.Env{Vars: map[string]string{}, Runner: &exec.Fake{}}
	ctx := context.Background()
	got, err := Unpack(ctx, env, zfile, "tool", filepath.Join(dir, "z"))
	if b, _ := os.ReadFile(got); err != nil || string(b) != "zipped" { // #nosec G304 -- test file
		t.Errorf("zip: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "z", "link")); err == nil {
		t.Error("a zip symlink member must be skipped")
	}

	var gbuf bytes.Buffer
	gw := gzip.NewWriter(&gbuf)
	_, _ = gw.Write([]byte("gunzipped"))
	_ = gw.Close()
	gfile := filepath.Join(dir, "tool.gz")
	if err := os.WriteFile(gfile, gbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = Unpack(ctx, env, gfile, "tool", filepath.Join(dir, "g"))
	if b, _ := os.ReadFile(got); err != nil || string(b) != "gunzipped" { // #nosec G304 -- test file
		t.Errorf("gz: %q %v", got, err)
	}
	raw := filepath.Join(dir, "tool-linux-amd64")
	if err := os.WriteFile(raw, []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Unpack(ctx, env, raw, "tool", filepath.Join(dir, "r")); err != nil || got != raw {
		t.Errorf("a bare asset is the binary: %q %v", got, err)
	}

	// Two executables and none named tool is ambiguous.
	var abuf bytes.Buffer
	tw = tar.NewWriter(&abuf)
	for _, n := range []string{"x/a", "x/b"} {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	}
	_ = tw.Close()
	amb := filepath.Join(dir, "amb.tar")
	if err := os.WriteFile(amb, abuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(ctx, env, amb, "tool", filepath.Join(dir, "a")); err == nil || !strings.Contains(err.Error(), "no single tool") {
		t.Errorf("ambiguous archive: %v", err)
	}
}

// releaseRunner plays gh for repo o/tool: download writes body to -O.
type releaseRunner struct {
	body  []byte
	calls []string
}

func (r *releaseRunner) Run(_ context.Context, name string, args []string, _ exec.Options) exec.Result {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "gh" && len(args) > 8 && args[0] == "release" && args[1] == "download" {
		if err := os.WriteFile(args[8], r.body, 0o600); err != nil {
			return exec.Result{Code: 1, Stderr: err.Error()}
		}
		return exec.Result{}
	}
	return exec.Result{Code: exec.ExitNotFound, Stderr: name + ": command not found"}
}

func TestInstallRelease(t *testing.T) {
	var gbuf bytes.Buffer
	gw := gzip.NewWriter(&gbuf)
	_, _ = gw.Write([]byte("\x7fELF new"))
	_ = gw.Close()
	sum := sha256.Sum256(gbuf.Bytes())
	digest := hex.EncodeToString(sum[:])

	setup := func(t *testing.T) (env *exec.Env, dest, backups string) {
		t.Helper()
		dir := t.TempDir()
		dest = filepath.Join(dir, "bin", "tool")
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte("\x7fELF old"), 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
		return &exec.Env{Runner: &releaseRunner{body: gbuf.Bytes()}}, dest, filepath.Join(dir, "backups")
	}
	spec := func(dest, backups, digest string) InstallSpec {
		return InstallSpec{Repo: "o/tool", Name: "tool", GOOS: "linux", GOARCH: "amd64",
			Release: Release{Tag: "v2.0", Assets: []ReleaseAsset{{Name: "tool-linux-amd64.gz", Digest: digest}}},
			Dest:    dest, BackupDir: backups, OldVersion: "v1.0"}
	}
	ctx := context.Background()

	t.Run("verified", func(t *testing.T) {
		env, dest, backups := setup(t)
		got, err := InstallRelease(ctx, env, spec(dest, backups, "sha256:"+digest))
		if err != nil || !got.Verified || got.SHA256 != digest || got.Asset != "tool-linux-amd64.gz" {
			t.Fatalf("%+v %v", got, err)
		}
		if b, _ := os.ReadFile(dest); string(b) != "\x7fELF new" { // #nosec G304 -- test file
			t.Errorf("dest: %q", b)
		}
		if st, _ := os.Stat(dest); st.Mode().Perm() != 0o755 {
			t.Errorf("mode %v", st.Mode())
		}
		if b, _ := os.ReadFile(filepath.Join(backups, "tool-v1.0")); string(b) != "\x7fELF old" { // #nosec G304 -- test file
			t.Errorf("backup: %q", b)
		}
		if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".*")); len(leftovers) != 0 {
			t.Errorf("temporary files left: %v", leftovers)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		env, dest, backups := setup(t)
		_, err := InstallRelease(ctx, env, spec(dest, backups, "sha256:"+strings.Repeat("0", 64)))
		if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("mismatch: %v", err)
		}
		if b, _ := os.ReadFile(dest); string(b) != "\x7fELF old" { // #nosec G304 -- test file
			t.Error("a bad download must leave dest alone")
		}
	})
	t.Run("no checksum", func(t *testing.T) {
		env, dest, backups := setup(t)
		s := spec(dest, backups, "")
		if _, err := InstallRelease(ctx, env, s); !errors.Is(err, ErrNoChecksum) {
			t.Fatalf("no checksum: %v", err)
		}
		s.SkipChecksum, s.OldVersion = true, ""
		got, err := InstallRelease(ctx, env, s)
		if err != nil || got.Verified {
			t.Fatalf("skip: %+v %v", got, err)
		}
		if _, err := os.Stat(filepath.Join(backups, "tool-previous")); err != nil {
			t.Errorf("an unversioned backup is tool-previous: %v", err)
		}
	})
	t.Run("checksum file", func(t *testing.T) {
		env, dest, backups := setup(t)
		r := env.Runner.(*releaseRunner)
		s := spec(dest, backups, "")
		s.Release.Assets = append(s.Release.Assets, ReleaseAsset{Name: "checksums.txt"})
		// The runner serves the same body for every download, so the
		// checksum file holds no sum for the asset.
		if _, err := InstallRelease(ctx, env, s); !errors.Is(err, ErrNoChecksum) {
			t.Fatalf("unmatched checksum file: %v", err)
		}
		if n := len(r.calls); n != 2 {
			t.Errorf("asset and checksum file downloaded: %v", r.calls)
		}
	})
	t.Run("new file", func(t *testing.T) {
		env, dest, backups := setup(t)
		fresh := filepath.Join(filepath.Dir(dest), "sub", "tool")
		if _, err := InstallRelease(ctx, env, spec(fresh, backups, "sha256:"+digest)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(backups); err == nil {
			t.Error("nothing to back up when dest did not exist")
		}
	})
}

func TestFetchRelease(t *testing.T) {
	f := &exec.Fake{}
	f.AddOutput(`{"tag_name":"v3","assets":[{"name":"a"}]}`, "gh", "api", "repos/o/r/releases/tags/v3")
	f.Add([]string{"gh", "api", "repos/o/r/releases/latest"}, exec.Result{Code: 1, Stderr: "HTTP 404: Not Found"})
	env := &exec.Env{Runner: f}
	rel, err := FetchRelease(context.Background(), env, "o/r", "v3")
	if err != nil || rel.Tag != "v3" || len(rel.Assets) != 1 {
		t.Errorf("tagged: %+v %v", rel, err)
	}
	if _, err := FetchRelease(context.Background(), env, "o/r", ""); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("latest: %v", err)
	}
}
