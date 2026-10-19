package packages

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/finding"
)

func TestParseTrackSpec(t *testing.T) {
	for in, want := range map[string][2]string{
		"sharkdp/bat":                  {"sharkdp/bat", ""},
		"https://github.com/o/r.git":   {"o/r", ""},
		"sharkdp/bat:*musl*.tar.gz":    {"sharkdp/bat", "*musl*.tar.gz"},
		"stashapp/stash:stash-linux\t": {"stashapp/stash", "stash-linux"},
	} {
		repo, asset, err := ParseTrackSpec(in)
		if err != nil || repo != want[0] || asset != want[1] {
			t.Errorf("%q: %q %q %v", in, repo, asset, err)
		}
	}
	for _, bad := range []string{"bat", "a/b/c", "o/r:[", ""} {
		if _, _, err := ParseTrackSpec(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func assets(names ...string) []ReleaseAsset {
	out := make([]ReleaseAsset, len(names))
	for i, n := range names {
		out[i] = ReleaseAsset{Name: n}
	}
	return out
}

func TestSelectAsset(t *testing.T) {
	bat := assets("bat-musl_0.26.1_musl-linux-amd64.deb", "bat-v0.26.1-aarch64-unknown-linux-gnu.tar.gz",
		"bat-v0.26.1-x86_64-apple-darwin.tar.gz", "bat-v0.26.1-x86_64-pc-windows-msvc.zip",
		"bat-v0.26.1-x86_64-unknown-linux-gnu.tar.gz", "bat-v0.26.1-x86_64-unknown-linux-musl.tar.gz", "bat_0.26.1_amd64.deb")
	if a, err := SelectAsset(bat, "", "linux", "amd64"); err != nil || a.Name != "bat-v0.26.1-x86_64-unknown-linux-gnu.tar.gz" {
		t.Errorf("glibc tar.gz: %+v %v", a, err)
	}
	if a, err := SelectAsset(bat, "*linux-musl*", "linux", "amd64"); err != nil || a.Name != "bat-v0.26.1-x86_64-unknown-linux-musl.tar.gz" {
		t.Errorf("glob: %+v %v", a, err)
	}
	if a, err := SelectAsset(bat, "", "linux", "arm64"); err != nil || a.Name != "bat-v0.26.1-aarch64-unknown-linux-gnu.tar.gz" {
		t.Errorf("arm64: %+v %v", a, err)
	}
	stash := assets("stash-linux", "stash-linux-arm64v8", "stash-macos", "stash-win.exe", "CHECKSUMS_SHA1")
	if _, err := SelectAsset(stash, "", "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "no release asset matches linux/amd64") {
		t.Errorf("a bare name without arch needs a glob: %v", err)
	}
	if a, err := SelectAsset(stash, "stash-linux", "linux", "amd64"); err != nil || a.Name != "stash-linux" {
		t.Errorf("exact glob: %+v %v", a, err)
	}
	two := assets("x-linux-amd64.tar.gz", "x-linux-x86_64-v2.tar.gz")
	if _, err := SelectAsset(two, "", "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "2 release assets match") {
		t.Errorf("ambiguous: %v", err)
	}
}

func TestAssetSHA256(t *testing.T) {
	sum := strings.Repeat("a", 64)
	if s, ok, err := AssetSHA256(ReleaseAsset{Name: "x", Digest: "sha256:" + strings.ToUpper(sum)}, nil, nil); !ok || err != nil || s != sum {
		t.Errorf("digest: %q %v %v", s, ok, err)
	}
	all := assets("x.tar.gz", "checksums.txt")
	fetched := 0
	fetch := func(a ReleaseAsset) (string, error) {
		fetched++
		return strings.Repeat("b", 64) + "  other.tar.gz\n" + sum + " *x.tar.gz\n", nil
	}
	if s, ok, err := AssetSHA256(all[0], all, fetch); !ok || err != nil || s != sum || fetched != 1 {
		t.Errorf("checksum file: %q %v %v", s, ok, err)
	}
	single := assets("x", "x.sha256")
	if s, ok, _ := AssetSHA256(single[0], single, func(ReleaseAsset) (string, error) { return sum + "\n", nil }); !ok || s != sum {
		t.Errorf("a bare sum in NAME.sha256: %q %v", s, ok)
	}
	if _, ok, err := AssetSHA256(ReleaseAsset{Name: "x"}, assets("x"), fetch); ok || err != nil {
		t.Errorf("no checksum: %v %v", ok, err)
	}
	if _, _, err := AssetSHA256(all[0], all, func(ReleaseAsset) (string, error) { return "", errors.New("404") }); err == nil {
		t.Error("a failed checksum download is an error")
	}
}

func TestBinsCollect(t *testing.T) {
	_, _, home := testEnv(t)
	dir := filepath.Join(home, ".local/bin")
	writeFile(t, filepath.Join(dir, "elfy"), "\x7fELF....")
	if err := os.Chmod(filepath.Join(dir, "elfy"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeExe(t, filepath.Join(dir, "script"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(dir, "notexec"), "x")
	if err := os.Symlink("/usr/bin/true", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	b := Bins{Dirs: []string{dir, filepath.Join(home, "missing")}, Tracked: func() (map[string]TrackedBin, error) {
		return map[string]TrackedBin{"elfy": {Name: "elfy", Repo: "o/elfy", Version: "v1.0"}}, nil
	}}
	pkgs, err := b.Collect(ctx, nil)
	if err != nil || len(pkgs) != 2 {
		t.Fatalf("regular executables only: %+v %v", pkgs, err)
	}
	if p := pkgs[0]; p.Name != "elfy" || p.Kind != "elf" || p.Ident != "o/elfy" || p.Version != "v1.0" || p.Registry() != RegistryGitHub ||
		strings.Join(UpdateCommand(p), " ") != SelfCommand+" packages bins install elfy" {
		t.Errorf("tracked: %+v", p)
	}
	if p := pkgs[1]; p.Kind != "script" || p.Registry() != "" || UpdateCommand(p) != nil {
		t.Errorf("untracked: %+v", p)
	}
	invs := []Inventory{{Manager: BinsManager, Available: true, Packages: append(pkgs,
		Package{Manager: BinsManager, Name: "loose", Location: "/x/loose", Kind: "elf"})}}
	fs := finding.RunChecks(Command, &State{Inventories: invs}, []finding.Check[*State]{{ID: "bins.untracked", Fn: binsUntracked}})
	if len(fs) != 1 || fs[0].Subject != "/x/loose" || fs[0].Group == nil {
		t.Errorf("only untracked ELF binaries: %+v", fs)
	}
	bad := Bins{Dirs: []string{dir}, Tracked: func() (map[string]TrackedBin, error) { return nil, errors.New("db locked") }}
	if _, err := bad.Collect(ctx, nil); err == nil {
		t.Error("a tracking load failure is an error")
	}
}
