package files

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

var ctx = context.Background()

func put(t *testing.T, p string, size int, mod time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(len(p) + i%7)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if !mod.IsZero() {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	put(t, to, 0, time.Time{})
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func touchDir(t *testing.T, p string, mod time.Time) {
	t.Helper()
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatal(err)
	}
}

// fixture builds a home with one of every candidate.
func fixture(t *testing.T) (string, time.Time) {
	t.Helper()
	home := t.TempDir()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	old := now.Add(-400 * 24 * time.Hour)
	put(t, filepath.Join(home, "proj/package.json"), 10, time.Time{})
	put(t, filepath.Join(home, "proj/node_modules/dep/index.js"), 300_000, time.Time{})
	touchDir(t, filepath.Join(home, "proj/node_modules"), old)
	put(t, filepath.Join(home, ".local/share/nvim/mason/lsp/package.json"), 10, time.Time{})
	put(t, filepath.Join(home, ".local/share/nvim/mason/lsp/node_modules/x.js"), 300_000, time.Time{})
	touchDir(t, filepath.Join(home, ".local/share/nvim/mason/lsp/node_modules"), old)
	put(t, filepath.Join(home, "Downloads/old.iso"), 400_000, old)
	put(t, filepath.Join(home, "Downloads/new.iso"), 10_000, now)
	put(t, filepath.Join(home, "media/movie.mkv"), 500_000, time.Time{})
	copyFile(t, filepath.Join(home, "media/movie.mkv"), filepath.Join(home, "backup/movie-copy.mkv"))
	put(t, filepath.Join(home, "repo/.git/HEAD"), 10, time.Time{})
	put(t, filepath.Join(home, "repo/big.bin"), 500_000, time.Time{})
	copyFile(t, filepath.Join(home, "repo/big.bin"), filepath.Join(home, "repo/big-copy.bin"))
	put(t, filepath.Join(home, ".local/share/goneapp/blob"), 200_000, time.Time{})
	put(t, filepath.Join(home, ".local/share/Trash/files/x"), 10, time.Time{})
	put(t, filepath.Join(home, "crash/core.1234"), 1_200_000, time.Time{})
	if err := os.MkdirAll(filepath.Join(home, "empty/a"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nowhere"), filepath.Join(home, "dangling")); err != nil {
		t.Fatal(err)
	}
	return home, now
}

func TestWalk(t *testing.T) {
	home, _ := fixture(t)
	tr := Walk(ctx, WalkOptions{Roots: []string{home}, Track: func(_ string, d int) bool { return d <= 1 }, BigFiles: 3, DupMin: 100_000})
	if tr.Files < 10 || tr.Bytes < 2_000_000 || tr.Sizes[filepath.Join(home, "media")] < 500_000 {
		t.Errorf("totals: %d files %d bytes, media %d", tr.Files, tr.Bytes, tr.Sizes[filepath.Join(home, "media")])
	}
	if len(tr.Big) != 3 || tr.Big[0].Bytes < tr.Big[2].Bytes || !strings.HasSuffix(tr.Big[0].Path, "core.1234") {
		t.Errorf("big: %+v", tr.Big)
	}
	kinds := map[string]string{}
	for _, b := range tr.Build {
		kinds[strings.TrimPrefix(b.Path, home)] = b.Kind
	}
	if kinds["/proj/node_modules"] != "node" || kinds["/.local/share/nvim/mason/lsp/node_modules"] != "node" {
		t.Errorf("build dirs: %v", kinds)
	}
	if len(tr.Cores) != 1 || !containsSuffix(tr.Empty, "/empty/a") || !containsSuffix(tr.Broken, "/dangling") {
		t.Errorf("cores %v empty %v broken %v", tr.Cores, tr.Empty, tr.Broken)
	}
	dupGroups := 0
	for _, ps := range tr.BySize {
		if len(ps) > 1 {
			dupGroups++
		}
	}
	if dupGroups != 2 {
		t.Errorf("same-size groups: %v", tr.BySize)
	}
}

func containsSuffix(ps []string, suffix string) bool {
	for _, p := range ps {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

func TestScan(t *testing.T) {
	home, now := fixture(t)
	fake := &exec.Fake{}
	fake.AddOutput("Archived and active journals take up 2.5G in the file system.\n", "journalctl", "--disk-usage")
	fake.AddOutput("vim\ncurl\n", "dpkg-query")
	bin := filepath.Join(home, "bin")
	for _, exe := range []string{"journalctl", "nvim"} {
		put(t, filepath.Join(bin, exe), 1, time.Time{})
		if err := os.Chmod(filepath.Join(bin, exe), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := &exec.Env{Vars: map[string]string{"PATH": bin, "HOME": home}, Home: home, Runner: fake}
	o := Options{Env: env, Roots: []string{home}, Downloads: filepath.Join(home, "Downloads"), LargeMB: 0, DupMinMB: 0,
		CacheMinMB: 0, BuildMinMB: 0, OrphanMinMB: 0, StaleAfter: 90 * 24 * time.Hour, OldDownloads: 180 * 24 * time.Hour,
		HashLimit: 1 << 30, Top: 5, Now: now}
	d, fs, stats, errs, err := Scan(ctx, o, progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 || len(stats) < 2 {
		t.Errorf("errs %v stats %v", errs, stats)
	}
	if len(d.Build) != 1 || !strings.HasSuffix(d.Build[0].Path, "/proj/node_modules") {
		t.Errorf("only the project's node_modules is idle build output: %+v", d.Build)
	}
	if len(d.Dups) != 0 {
		t.Errorf("DupMinMB 0 compares nothing: %+v", d.Dups)
	}
	o.DupMinMB = 0
	checks := map[string]int{}
	for _, f := range fs {
		checks[f.Check]++
	}
	for _, c := range []string{"files.build", "files.downloads", "files.orphaned", "files.core_dumps", "files.broken_links", "files.cache"} {
		if checks[c] == 0 {
			t.Errorf("missing %s: %v", c, checks)
		}
	}
	var journal bool
	for _, c := range d.Caches {
		if c.Name == "systemd journal" && c.Bytes == int64(2.5*(1<<30)) && c.Root {
			journal = true
		}
	}
	if !journal {
		t.Errorf("journal size: %+v", d.Caches)
	}
	if len(d.Orphans) != 1 || !strings.HasSuffix(d.Orphans[0].Path, "/.local/share/goneapp") {
		t.Errorf("orphans: %+v", d.Orphans)
	}
	if d.Reclaimable == 0 {
		t.Error("reclaimable")
	}
}

func TestDuplicates(t *testing.T) {
	home, _ := fixture(t)
	tr := Walk(ctx, WalkOptions{Roots: []string{home}, DupMin: 100_000})
	inRepo := repoChecker(home)
	for size, ps := range tr.BySize {
		var keep []string
		for _, p := range ps {
			if UserFile(p) && !inRepo(p) {
				keep = append(keep, p)
			}
		}
		tr.BySize[size] = keep
	}
	dups, stopped := duplicates(ctx, tr.BySize, 1<<30)
	if stopped || len(dups) != 1 || len(dups[0].Paths) != 2 || !strings.HasSuffix(dups[0].Paths[0], "backup/movie-copy.mkv") {
		t.Errorf("dups (repo copies left out): %+v", dups)
	}
	if _, stopped := duplicates(ctx, tr.BySize, 10); !stopped {
		t.Error("the hash limit stops the check")
	}
}

func TestNames(t *testing.T) {
	if Normalize("Google-Chrome_Beta 2") != "googlechromebeta2" {
		t.Error("Normalize")
	}
	known := map[string]bool{"googlechromestable": true, "vim": true}
	for name, want := range map[string]bool{"google-chrome": true, "Vim": true, "thumbnails": true, "goneapp": false, "ab": false} {
		if Installed(name, known) != want {
			t.Errorf("Installed(%q) != %v", name, want)
		}
	}
	if UserFile("/h/repo/.git/objects/pack/p.pack") || UserFile("/h/.cache/uv/x") || !UserFile("/h/Downloads/x.iso") {
		t.Error("UserFile")
	}
	if ProjectDir("/h/.local/share/nvim/mason/x/node_modules", "/h") || ProjectDir("/h/.gradle", "/h") || !ProjectDir("/h/src/p/target", "/h") {
		t.Error("ProjectDir")
	}
	if parseDockerSize("1.2GB (50%)") != 1_200_000_000 || parseDockerSize("0B") != 0 {
		t.Error("docker sizes")
	}
	if Human(3<<30) != "3.0 GB" || Human(5<<20) != "5 MB" {
		t.Error("Human")
	}
}
