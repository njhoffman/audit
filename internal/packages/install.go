package packages

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// maxBinary bounds what an archive member may unpack to.
const maxBinary = 1 << 30

// FetchRelease reads repo's latest GitHub release, or the one tagged tag,
// through gh api.
func FetchRelease(ctx context.Context, env *exec.Env, repo, tag string) (Release, error) {
	path := "repos/" + repo + "/releases/latest"
	if tag != "" {
		path = "repos/" + repo + "/releases/tags/" + tag
	}
	r := env.Run(ctx, "gh", []string{"api", path}, exec.Options{Timeout: time.Minute})
	var rel Release
	if !r.OK() {
		return rel, fmt.Errorf("gh api %s: %s", path, LastLine(r.Stderr+"\n"+r.Stdout))
	}
	if err := json.Unmarshal([]byte(r.Stdout), &rel); err != nil {
		return rel, fmt.Errorf("unexpected answer from gh api %s: %w", path, err)
	}
	return rel, nil
}

// InstallSpec is one binary to install from a fetched release.
type InstallSpec struct {
	Repo    string
	Name    string
	Release Release
	// AssetGlob picks the asset; empty selects by GOOS and GOARCH.
	AssetGlob    string
	GOOS, GOARCH string
	// Dest is the file to replace (or create).
	Dest string
	// BackupDir receives a copy of an existing Dest as NAME-OldVersion
	// ("previous" when OldVersion is empty).
	BackupDir    string
	OldVersion   string
	SkipChecksum bool
	// Timeout bounds each download.
	Timeout time.Duration
}

// Installed reports what InstallRelease put in place.
type Installed struct {
	Asset  string
	SHA256 string
	// Verified is false when the release published no checksum and the
	// install went ahead under SkipChecksum.
	Verified bool
}

// InstallRelease downloads the release asset for s, checks its sha256
// against GitHub's digest or the release's checksum file, unpacks it and
// swaps it into s.Dest by a rename, backing up the old file first. Dest is
// left alone on any failure before the swap.
func InstallRelease(ctx context.Context, env *exec.Env, s InstallSpec) (Installed, error) {
	var res Installed
	asset, err := SelectAsset(s.Release.Assets, s.AssetGlob, s.GOOS, s.GOARCH)
	if err != nil {
		return res, err
	}
	res.Asset = asset.Name
	tmp, err := os.MkdirTemp("", "audit-bin-")
	if err != nil {
		return res, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	download := func(name, dir string) (string, error) {
		return ghDownload(ctx, env, s.Repo, s.Release.Tag, name, dir, s.Timeout)
	}
	file, err := download(asset.Name, tmp)
	if err != nil {
		return res, err
	}
	want, ok, err := AssetSHA256(asset, s.Release.Assets, func(ra ReleaseAsset) (string, error) {
		p, err := download(ra.Name, filepath.Join(tmp, "sums"))
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- our temp download
		return string(b), err
	})
	if err != nil {
		return res, err
	}
	got, err := FileSHA256(file)
	if err != nil {
		return res, err
	}
	switch {
	case !ok && !s.SkipChecksum:
		return res, fmt.Errorf("%w (%s %s); pass --skip-checksum to install it anyway", ErrNoChecksum, s.Repo, asset.Name)
	case ok && got != want:
		return res, fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset.Name, got, want)
	}
	bin, err := Unpack(ctx, env, file, s.Name, filepath.Join(tmp, "x"))
	if err != nil {
		return res, err
	}
	if err := ReplaceBin(s.Dest, bin, filepath.Join(s.BackupDir, s.Name+"-"+backupVersion(s.OldVersion))); err != nil {
		return res, err
	}
	res.SHA256, res.Verified = got, ok
	return res, nil
}

func backupVersion(v string) string {
	if v == "" {
		return "previous"
	}
	return v
}

func ghDownload(ctx context.Context, env *exec.Env, repo, tag, asset, dir string, timeout time.Duration) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(dir, filepath.Base(asset))
	r := env.Run(ctx, "gh", []string{"release", "download", tag, "-R", repo, "-p", asset, "-O", out, "--clobber"},
		exec.Options{Timeout: timeout})
	if !r.OK() {
		return "", fmt.Errorf("gh release download %s %s: %s", repo, asset, LastLine(r.Stderr+"\n"+r.Stdout))
	}
	if _, err := os.Stat(out); err != nil {
		return "", fmt.Errorf("gh release download left no %s", asset)
	}
	return out, nil
}

// FileSHA256 is the hex sha256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- our temp download
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Unpack extracts file into dir and returns the binary called name in it,
// or the only executable file; a bare asset is the binary itself. Tar
// archives compressed with xz or zstd go through the tar command, since
// the standard library has no decoder for them.
func Unpack(ctx context.Context, env *exec.Env, file, name, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	lower := strings.ToLower(file)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		if err := unzip(file, dir); err != nil {
			return "", err
		}
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar.bz2"),
		strings.HasSuffix(lower, ".tar"):
		if err := untar(file, dir); err != nil {
			return "", fmt.Errorf("unpack %s: %w", filepath.Base(file), err)
		}
	case strings.Contains(lower, ".tar."):
		r := env.Run(ctx, "tar", []string{"-xf", file, "-C", dir, "--no-same-owner"}, exec.Options{Timeout: 5 * time.Minute})
		if !r.OK() {
			return "", fmt.Errorf("tar -xf %s: %s", filepath.Base(file), LastLine(r.Stderr))
		}
	case strings.HasSuffix(lower, ".gz"):
		out := filepath.Join(dir, name)
		if err := gunzip(file, out); err != nil {
			return "", err
		}
		return out, nil
	default:
		return file, nil
	}
	var exact, execs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		if d.Name() == name {
			exact = append(exact, p)
		}
		if st, err := d.Info(); err == nil && st.Mode().Perm()&0o111 != 0 {
			execs = append(execs, p)
		}
		return nil
	})
	switch {
	case err != nil:
		return "", err
	case len(exact) == 1:
		return exact[0], nil
	case len(exact) == 0 && len(execs) == 1:
		return execs[0], nil
	}
	return "", fmt.Errorf("the archive holds no single %s (found %d by name, %d executables)", name, len(exact), len(execs))
}

// untar extracts the regular files of a plain, gzip or bzip2 tar archive,
// keeping every path inside dir.
func untar(file, dir string) error {
	f, err := os.Open(file) // #nosec G304 -- our temp download
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	switch lower := strings.ToLower(file); {
	case strings.HasSuffix(lower, ".bz2"):
		r = bzip2.NewReader(f)
	case strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tgz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		p := filepath.Join(dir, filepath.Clean("/"+h.Name)) // #nosec G305 -- cleaned against a rooted path
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode).Perm()|0o600) // #nosec G115 G304 -- inside our temp dir
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(tr, maxBinary))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}

// unzip extracts the files of a zip archive, keeping every path inside dir.
func unzip(file, dir string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		p := filepath.Join(dir, filepath.Clean("/"+f.Name)) // #nosec G305 -- cleaned against a rooted path
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o600) // #nosec G304 -- inside our temp dir
		if err == nil {
			_, err = io.Copy(out, io.LimitReader(rc, maxBinary))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func gunzip(file, out string) error {
	in, err := os.Open(file) // #nosec G304 -- our temp download
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700) // #nosec G302 G304 -- an executable in our temp dir
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.LimitReader(zr, maxBinary))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ReplaceBin installs src at dest through a temporary file in dest's
// directory, so the swap is a rename, after copying an existing dest to
// backup.
func ReplaceBin(dest, src, backup string) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		if err := copyFile(dest, backup, 0o700); err != nil {
			return fmt.Errorf("back up %s: %w", dest, err)
		}
	}
	tmp := filepath.Join(dir, "."+filepath.Base(dest)+".audit-new")
	if err := copyFile(src, tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- paths audit chose
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G302 G304 -- installing an executable
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
