package configs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/progress"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		format, body string
		ok           bool
	}{
		{"json", `{"a": 1}`, true},
		{"json", `{"a": 1}{"b": 2}`, true},
		{"json", "{\n // comment\n \"a\": [1, 2,],\n}", true},
		{"json", `{"a": }`, false},
		{"jsonc", "/* x */ {\"a\": \"http://x//y\"}", true},
		{"json", "\xef\xbb\xbf{\"bom\": true}", true},
		{"yaml", "a: 1\n---\nb: 2\n", true},
		{"yaml", "a: b: c\n", false},
		{"toml", "[x]\na = 1\n", true},
		{"toml", "[x\n", false},
		{"ini", "\xef\xbb\xbf[s]\nk = v\n  continued\n; c\n", true},
		{"ini", "[s]\nnot a pair\n", false},
		{"xml", "<a><b/></a>", true},
		{"xml", "<a><b></a>", false},
	} {
		if err := Parse(c.format, []byte(c.body)); (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.format, c.body, err)
		}
	}
}

func TestCredential(t *testing.T) {
	for body, want := range map[string]string{
		"api_key = sk_live_abcdefghijklmnop1234\n":            "api_key",
		"  \"CONTEXT7_API_KEY\": \"ctx7sk-abcdefghijklmnop\"": "CONTEXT7_API_KEY",
		"token_analysis: enabled_for_everything_here\n":       "",
		"password = short\n":                                  "",
		"İİİİ\nsecret: abcdefghijklmnopqrstuv\n":              "secret",
		"nothing here\n":                                      "",
	} {
		if got := Credential([]byte(body)); got != want {
			t.Errorf("%q: %q, want %q", body, got, want)
		}
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{".zshrc": "zsh", ".tmux.conf": "tmux", ".gitconfig": "git", ".wakatime.cfg": "wakatime", ".npmrc": "npm"} {
		if got := dotName(in); got != want {
			t.Errorf("dotName(%s) = %s", in, got)
		}
	}
	own := NewOwners(map[string]string{"rg": "apt:ripgrep", "nvim": "apt:neovim", "googlechromestable": "apt:google-chrome-stable"})
	for name, want := range map[string]string{"nvim": "apt:neovim", "rgignore": "apt:ripgrep", "google-chrome": "apt:google-chrome-stable",
		"unknownthing": "", "ab": ""} {
		if got := own.Owner(name); got != want {
			t.Errorf("Owner(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestDpkgOwners(t *testing.T) {
	info := t.TempDir()
	if err := os.WriteFile(filepath.Join(info, "ripgrep.list"), []byte("/.\n/usr\n/usr/bin/rg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "coreutils:amd64.list"), []byte("/bin/ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := DpkgOwners(info, []string{"/usr/bin/rg", "/usr/bin/ls", "/usr/bin/none"})
	if got["/usr/bin/rg"] != "ripgrep" || got["/usr/bin/ls"] != "coreutils" || got["/usr/bin/none"] != "" {
		t.Errorf("owners: %v", got)
	}
	if DpkgOwners(filepath.Join(info, "missing"), nil) != nil {
		t.Error("no lists, no answer")
	}
}

func TestScan(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".config/good/settings.json", `{"a": 1}`, 0o644)
	write(".config/broken/config.yaml", "a: b: c\n", 0o644)
	write(".config/leaky/creds.toml", "api_key = \"abcdefghijklmnopqrstuv\"\n", 0o644)
	write(".config/private/creds.toml", "api_key = \"abcdefghijklmnopqrstuv\"\n", 0o600)
	write(".config/goneapp/x.conf", "x", 0o644)
	write(".config/node_modules/skip.json", "{", 0o644)
	write(".gitconfig", "[user\n", 0o644)
	write(".zshenv", "", 0o644)
	write(".oldtoolrc", "x", 0o644)
	write(".config/audit.yaml", "history: 5\n", 0o600)
	bin := t.TempDir()
	for _, exe := range []string{"git", "good", "broken", "leaky", "private", "apt-cache"} {
		write(filepath.Join(strings.TrimPrefix(bin, home), exe), "", 0o755)
		if err := os.WriteFile(filepath.Join(bin, exe), nil, 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	fake := &exec.Fake{}
	fake.Add([]string{"git", "config", "--global", "--list"}, exec.Result{Code: 128, Stderr: "fatal: bad config line 1 in file ~/.gitconfig"})
	fake.AddOutput("oldtool - the old tool\n", "apt-cache", "search")
	env := &exec.Env{Vars: map[string]string{"HOME": home, "PATH": bin, "XDG_CONFIG_HOME": cfg}, Home: home, Runner: fake}
	old := DpkgInfo
	DpkgInfo = t.TempDir()
	t.Cleanup(func() { DpkgInfo = old })
	d, fs, stats, _, err := Scan(context.Background(), Options{Env: env, Roots: []string{cfg}, MaxDepth: 4,
		Exclude: []string{"node_modules"}, MaxBytes: 1 << 20}, progress.Nop)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range fs {
		got[f.Check] = append(got[f.Check], strings.TrimPrefix(f.Subject, home))
	}
	if strings.Join(got["config.syntax"], ",") != "/.config/broken/config.yaml" {
		t.Errorf("syntax: %v", got["config.syntax"])
	}
	if strings.Join(got["config.permissions"], ",") != "/.config/leaky/creds.toml" {
		t.Errorf("only readable credentials: %v", got["config.permissions"])
	}
	if strings.Join(got["config.validator"], ",") != "/.gitconfig" {
		t.Errorf("validators: %v", got["config.validator"])
	}
	orphans := strings.Join(got["config.orphaned"], ",")
	if orphans != "/.config/goneapp,/.oldtoolrc" {
		t.Errorf("orphans: %v", orphans)
	}
	for _, e := range d.Entries {
		if strings.HasSuffix(e.Path, ".oldtoolrc") && e.Guess != "apt:oldtool" {
			t.Errorf("guess: %+v", e)
		}
		if strings.HasSuffix(e.Path, "/good") && e.Owner == "" {
			t.Errorf("good is owned by the good executable: %+v", e)
		}
	}
	if d.Parsed != 5 || len(stats) != 2 {
		t.Errorf("parsed %d (node_modules skipped), stats %v", d.Parsed, stats)
	}
}
