// Package configs checks user configuration: syntax of structured config
// files, the read-only checks programs offer for their own configs,
// credentials in files others can read, and configs whose program is no
// longer installed, each associated with the package it most likely
// belongs to.
package configs

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// Command is the audit subcommand name.
const Command = "configs"

// Options configure Scan.
type Options struct {
	Env *exec.Env
	// Roots are walked for structured config files (default ~/.config).
	Roots    []string
	MaxDepth int
	// Exclude are directory names never descended into.
	Exclude []string
	// MaxBytes skips larger files.
	MaxBytes int64
	// Inventories are the saved package inventories, for owners.
	Inventories []packages.Inventory
}

// File is one parsed config file.
type File struct {
	Path   string `json:"path"`
	Format string `json:"format"`
	Error  string `json:"error,omitempty"`
}

// Entry is a config directory or dotfile with the program it belongs to.
type Entry struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	// Owner is "apt:neovim", "flatpak:org.x.App", "uv:ruff", "exe:/usr/bin/x"
	// and so on; "" means no installed program matches (an orphan).
	Owner string `json:"owner,omitempty"`
	// Guess names a package that is not installed but matches the name.
	Guess string `json:"guess,omitempty"`
}

// Data is what a configs run stores.
type Data struct {
	Files   []File  `json:"files"`
	Entries []Entry `json:"entries"`
	Parsed  int     `json:"parsed"`
}

// formats maps extensions to a format name.
var formats = map[string]string{".json": "json", ".jsonc": "jsonc", ".yaml": "yaml", ".yml": "yaml",
	".toml": "toml", ".ini": "ini", ".xml": "xml", ".plist": "xml"}

// jsonStream decodes one or more concatenated JSON values (i3 layouts and
// JSON-lines files hold several).
func jsonStream(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var v any
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Parse checks data in format and returns the first error.
func Parse(format string, data []byte) error {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	switch format {
	case "json":
		if err := jsonStream(data); err != nil {
			// Many tools write JSON with comments (VS Code, waybar): accept it
			// when it parses once they are removed.
			if err2 := jsonStream(StripJSONC(data)); err2 != nil {
				return err
			}
		}
	case "jsonc":
		return jsonStream(StripJSONC(data))
	case "yaml":
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var v any
			err := dec.Decode(&v)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	case "toml":
		return toml.Unmarshal(data, new(map[string]any))
	case "ini":
		return ParseINI(data)
	case "xml":
		dec := xml.NewDecoder(bytes.NewReader(data))
		// Strict, so mismatched tags fail, but HTML entities (&nbsp;) are
		// accepted as many hand-written configs use them.
		dec.Entity = xml.HTMLEntity
		for {
			_, err := dec.Token()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// StripJSONC removes // and /* */ comments outside strings and trailing
// commas before } or ].
func StripJSONC(in []byte) []byte {
	var out []byte
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case inStr:
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return trailingComma.ReplaceAll(out, []byte("$1"))
}

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// ParseINI accepts [sections], key=value or key: value lines, ;/# comments
// and indented continuation lines.
func ParseINI(data []byte) error {
	for n, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "", strings.HasPrefix(t, ";"), strings.HasPrefix(t, "#"):
		case strings.HasPrefix(t, "["):
			if !strings.HasSuffix(t, "]") {
				return fmt.Errorf("line %d: unterminated section %q", n+1, t)
			}
		case line != t && (line[0] == ' ' || line[0] == '\t'):
			// continuation
		case strings.ContainsAny(t, "=:"):
		default:
			return fmt.Errorf("line %d: expected key = value, got %q", n+1, t)
		}
	}
	return nil
}

// credRe finds credential-looking assignments: the key name, then a long
// value. Only the key is ever reported.
var credRe = regexp.MustCompile(`(?im)^\s*["']?([a-z0-9_.-]*(?:api[_-]?key|secret|token|passwd|password))["']?\s*[:=]\s*["']?[A-Za-z0-9_\-./+]{16,}`)

// codeExt are source files, whose "token = ..." lines are code, not
// stored credentials.
var codeExt = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".lua": true, ".py": true, ".sh": true,
	".bash": true, ".zsh": true, ".vim": true, ".go": true, ".rb": true, ".rs": true, ".c": true, ".h": true, ".java": true,
	".kt": true, ".php": true, ".pl": true, ".el": true, ".fish": true, ".md": true, ".html": true, ".css": true, ".scss": true,
	".tsx": true, ".jsx": true, ".vue": true, ".svelte": true, ".txt": true, ".db": true}

var credWords = [][]byte{[]byte("key"), []byte("secret"), []byte("token"), []byte("passw")}

// Credential returns the key of the first credential-looking assignment.
// Only lines holding one of the words are matched against the expression,
// which keeps scanning thousands of files cheap.
func Credential(data []byte) string {
	// ASCII-only lowering keeps offsets aligned with data (bytes.ToLower can
	// change the length of some Unicode text).
	lower := make([]byte, len(data))
	for i, c := range data {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	if !slices.ContainsFunc(credWords, func(w []byte) bool { return bytes.Contains(lower, w) }) {
		return ""
	}
	start := 0
	for start < len(lower) {
		end := bytes.IndexByte(lower[start:], '\n')
		if end < 0 {
			end = len(lower)
		} else {
			end += start
		}
		if line := lower[start:end]; slices.ContainsFunc(credWords, func(w []byte) bool { return bytes.Contains(line, w) }) {
			if m := credRe.FindSubmatch(data[start:end]); m != nil {
				return string(m[1])
			}
		}
		start = end + 1
	}
	return ""
}

func excluded(name string, ex []string) bool {
	for _, e := range ex {
		if name == e {
			return true
		}
	}
	return false
}

// Scan checks the configs and returns the findings.
func Scan(ctx context.Context, o Options, rep progress.Reporter) (*Data, []finding.Finding, []run.Stat, []string, error) {
	home := o.Env.Home
	d := &Data{}
	var out []finding.Finding
	add := func(check string, sev finding.Severity, subject, msg, hint string, g *finding.Group) {
		out = append(out, finding.Finding{Command: Command, Check: "config." + check, Kind: finding.Issue, Severity: sev,
			Subject: subject, Message: msg, Hint: hint, Group: g})
	}
	rep.Phase("parsing config files", 0)
	var creds []string
	for _, root := range o.Roots {
		base := strings.Count(filepath.Clean(root), string(filepath.Separator))
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if e.IsDir() {
				if p != root && (excluded(e.Name(), o.Exclude) || strings.Count(p, string(filepath.Separator))-base > o.MaxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !e.Type().IsRegular() {
				return nil
			}
			info, err := e.Info()
			if err != nil || info.Size() > o.MaxBytes {
				return nil
			}
			format := formats[strings.ToLower(filepath.Ext(p))]
			data, err := os.ReadFile(p) // #nosec G304 G122 -- reads the user's own config files; nothing is written
			if err != nil {
				return nil
			}
			if format != "" && len(bytes.TrimSpace(data)) > 0 {
				d.Parsed++
				f := File{Path: p, Format: format}
				if perr := Parse(format, data); perr != nil {
					f.Error = oneLine(perr.Error())
					add("syntax", finding.Error, p, fmt.Sprintf("%s does not parse as %s: %s", short(p, home), format, f.Error),
						"Fix the file; the program reading it may ignore it or fail to start.",
						&finding.Group{ID: "syntax", Rollup: true, Title: "Fix parse errors in {n} config file{s}",
							Hint: "Fix each file; the program reading it may ignore it or fail to start."})
					out[len(out)-1].Details = []string{format + ": " + f.Error}
				}
				d.Files = append(d.Files, f)
			}
			if info.Mode().Perm()&0o044 != 0 && !codeExt[strings.ToLower(filepath.Ext(p))] {
				if key := Credential(data); key != "" {
					creds = append(creds, p)
					add("permissions", finding.Warning, p, fmt.Sprintf("%s holds what looks like a credential (%s) and other users can read it",
						short(p, home), key), "chmod 600 "+p+", or move the secret to a keyring or pass.", nil)
				}
			}
			return nil
		})
	}
	var errs []string
	rep.Phase("running config validators", len(validators))
	for _, v := range validators {
		for _, vf := range v.run(ctx, o.Env) {
			add("validator", vf.sev, vf.path, fmt.Sprintf("%s: %s", v.name, vf.msg), vf.hint, nil)
		}
		rep.Step(v.name)
	}
	rep.Phase("matching configs to programs", 0)
	d.Entries = entries(ctx, o)
	for _, e := range d.Entries {
		if e.Owner != "" {
			continue
		}
		msg := fmt.Sprintf("%s (%s) belongs to no installed program", short(e.Path, home), files.Human(e.Bytes))
		if e.Guess != "" {
			msg += "; it matches the package " + e.Guess + ", which is not installed"
		}
		add("orphaned", finding.Info, e.Path, msg, "", &finding.Group{ID: "orphaned", Title: "Remove configs of uninstalled programs",
			Hint: "audit configs clean moves them to the trash; ignore configs:config.orphaned:PATH for false matches"})
	}
	finding.Sort(out)
	orphans := 0
	for _, e := range d.Entries {
		if e.Owner == "" {
			orphans++
		}
	}
	stats := []run.Stat{
		{Name: "files parsed", Value: fmt.Sprint(d.Parsed)},
		{Name: "config entries", Value: fmt.Sprint(len(d.Entries)), Note: fmt.Sprintf("%d orphaned", orphans)},
	}
	return d, out, stats, errs, ctx.Err()
}

func short(p, home string) string {
	if rest, ok := strings.CutPrefix(p, home); ok {
		return "~" + rest
	}
	return p
}

func oneLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// validated is one validator complaint.
type validated struct {
	sev       finding.Severity
	path, msg string
	hint      string
}

type validator struct {
	name string
	run  func(ctx context.Context, env *exec.Env) []validated
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func firstExisting(ps ...string) string {
	for _, p := range ps {
		if exists(p) {
			return p
		}
	}
	return ""
}

func quick(ctx context.Context, env *exec.Env, name string, args ...string) exec.Result {
	return env.Run(ctx, name, args, exec.Options{Timeout: 20 * time.Second})
}

// validators are the read-only checks programs offer for their configs.
var validators = []validator{
	{"git", func(ctx context.Context, env *exec.Env) []validated {
		p := firstExisting(filepath.Join(env.Home, ".gitconfig"), filepath.Join(env.XDG("XDG_CONFIG_HOME"), "git", "config"))
		if p == "" || env.Which("git") == "" {
			return nil
		}
		if r := quick(ctx, env, "git", "config", "--global", "--list"); !r.OK() {
			return []validated{{finding.Error, p, oneLine(r.Stderr), "git refuses the file; fix the reported line."}}
		}
		return nil
	}},
	{"ssh", func(ctx context.Context, env *exec.Env) []validated {
		p := filepath.Join(env.Home, ".ssh", "config")
		if !exists(p) || env.Which("ssh") == "" {
			return nil
		}
		if r := quick(ctx, env, "ssh", "-G", "-F", p, "audit-config-check"); !r.OK() {
			return []validated{{finding.Error, p, oneLine(r.Stderr), "ssh stops on this; fix the reported option."}}
		}
		return nil
	}},
	{"systemd", func(ctx context.Context, env *exec.Env) []validated {
		dir := filepath.Join(env.XDG("XDG_CONFIG_HOME"), "systemd", "user")
		var units []string
		for _, ext := range []string{"service", "timer", "socket", "path"} {
			m, _ := filepath.Glob(filepath.Join(dir, "*."+ext))
			units = append(units, m...)
		}
		if len(units) == 0 || env.Which("systemd-analyze") == "" {
			return nil
		}
		r := env.Run(ctx, "systemd-analyze", append([]string{"--user", "verify"}, units...), exec.Options{Timeout: time.Minute})
		var out []validated
		for _, line := range strings.Split(strings.TrimSpace(r.Stderr), "\n") {
			for _, u := range units {
				if strings.Contains(line, filepath.Base(u)) {
					out = append(out, validated{finding.Warning, u, oneLine(line), "systemctl --user cat the unit and fix it."})
					break
				}
			}
		}
		return out
	}},
	{"i3", func(ctx context.Context, env *exec.Env) []validated { return wmCheck(ctx, env, "i3") }},
	{"sway", func(ctx context.Context, env *exec.Env) []validated { return wmCheck(ctx, env, "sway") }},
	{"fish", func(ctx context.Context, env *exec.Env) []validated {
		if env.Which("fish") == "" {
			return nil
		}
		var out []validated
		_ = filepath.WalkDir(filepath.Join(env.XDG("XDG_CONFIG_HOME"), "fish"), func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() && strings.HasSuffix(p, ".fish") {
				if r := quick(ctx, env, "fish", "-n", p); !r.OK() {
					out = append(out, validated{finding.Error, p, oneLine(r.Stderr), "fish cannot parse it."})
				}
			}
			return nil
		})
		return out
	}},
	{"tmux", func(ctx context.Context, env *exec.Env) []validated {
		p := firstExisting(filepath.Join(env.Home, ".tmux.conf"), filepath.Join(env.XDG("XDG_CONFIG_HOME"), "tmux", "tmux.conf"))
		// source-file -n parses without running anything, but needs a server;
		// audit never starts one.
		if p == "" || env.Which("tmux") == "" || !quick(ctx, env, "tmux", "list-sessions").OK() {
			return nil
		}
		if r := quick(ctx, env, "tmux", "source-file", "-n", p); !r.OK() || strings.TrimSpace(r.Stdout+r.Stderr) != "" {
			msg := oneLine(r.Stderr + r.Stdout)
			if msg == "" {
				msg = fmt.Sprintf("exit status %d", r.Code)
			}
			return []validated{{finding.Error, p, msg, "tmux reports this when it loads the file."}}
		}
		return nil
	}},
}

func wmCheck(ctx context.Context, env *exec.Env, wm string) []validated {
	p := filepath.Join(env.XDG("XDG_CONFIG_HOME"), wm, "config")
	if !exists(p) || env.Which(wm) == "" {
		return nil
	}
	r := quick(ctx, env, wm, "-C", "-c", p)
	var out []validated
	for _, line := range strings.Split(r.Stdout+"\n"+r.Stderr, "\n") {
		if strings.Contains(line, "ERROR") {
			out = append(out, validated{finding.Error, p, oneLine(line), wm + " would reject this line on reload."})
		}
	}
	if len(out) == 0 && !r.OK() {
		out = append(out, validated{finding.Error, p, fmt.Sprintf("%s -C exited %d", wm, r.Code), ""})
	}
	return out
}

// standardDot are home dot-entries that belong to the desktop, the shell or
// a user's own setup rather than one program.
var standardDot = map[string]bool{".cache": true, ".config": true, ".local": true, ".ssh": true, ".gnupg": true, ".pki": true,
	".Trash": true, ".profile": true, ".bash_logout": true, ".hushlogin": true, ".sudo_as_admin_successful": true,
	".Xauthority": true, ".ICEauthority": true, ".xsession-errors": true, ".xsession-errors.old": true, ".dbus": true,
	".face": true, ".face.icon": true, ".lesshst": true, ".wget-hsts": true, ".python_history": true, ".viminfo": true,
	".bash_history": true, ".zsh_history": true, ".zcompdump": true, ".themes": true, ".icons": true,
	".fonts": true, ".shell": true, ".dotfiles": true, ".cfg": true, ".xinitrc": true, ".xprofile": true, ".Xresources": true,
	".var": true, ".pam_environment": true, ".selected_editor": true, ".terminfo": true, ".inputrc": true, ".z": true,
	".nix-defexpr": true, ".nix-profile": true, ".nix-channels": true, ".xsessionrc": true, ".Xdefaults": true,
	".gtkrc-2.0": true, ".dmrc": true, ".esd_auth": true, ".bash_aliases": true, ".editorconfig": true,
	// zsh's own files; "z" alone is too short to match the program by name.
	".zshenv": true, ".zprofile": true, ".zlogin": true, ".zlogout": true, ".zcalc_history": true, ".zsh_history_bad": true}

// dotSuffixes are words a dotfile name adds to its program's name.
var dotSuffixes = []string{"env", "profile", "login", "logout", "history", "ignore", "data", "rc", "conf", "config", "cfg", "db", "bdb"}

var numericTail = regexp.MustCompile(`\.[0-9A-Za-z]*[0-9][0-9A-Za-z]*$`)

// dotName turns a dotfile into the program name it is for: ".zshrc" ->
// "zsh", ".tmux.conf" -> "tmux", ".gitconfig" -> "git".
func dotName(name string) string {
	n := strings.TrimPrefix(name, ".")
	for _, suf := range []string{".conf", ".config", "config", ".cfg", ".json", ".yaml", ".yml", ".toml", ".ini", "_history",
		"-history", ".history", "rc", ".d"} {
		if t := strings.TrimSuffix(n, suf); t != n && t != "" {
			n = t
			break
		}
	}
	return n
}

// owners maps normalized program names to an owner label.
func owners(ctx context.Context, o Options) map[string]string {
	env := o.Env
	out := map[string]string{}
	set := func(name, label string) {
		if k := files.Normalize(name); len(k) >= 2 {
			if _, ok := out[k]; !ok {
				out[k] = label
			}
		}
	}
	for _, inv := range o.Inventories {
		for _, p := range inv.Packages {
			set(p.Name, p.Manager+":"+p.Name)
			for _, e := range p.Executables {
				set(e, p.Manager+":"+p.Name)
			}
		}
	}
	r := env.Run(ctx, "dpkg-query", []string{"-W", "-f", "${Package}\n"}, exec.Options{Timeout: time.Minute})
	for _, n := range strings.Fields(r.Stdout) {
		set(strings.SplitN(n, ":", 2)[0], "apt:"+n)
	}
	r = env.Run(ctx, "flatpak", []string{"list", "--columns=application"}, exec.Options{Timeout: time.Minute})
	for _, id := range strings.Fields(r.Stdout) {
		set(id, "flatpak:"+id)
		set(id[strings.LastIndexByte(id, '.')+1:], "flatpak:"+id)
	}
	r = env.Run(ctx, "snap", []string{"list"}, exec.Options{Timeout: time.Minute})
	for i, line := range strings.Split(r.Stdout, "\n") {
		if f := strings.Fields(line); i > 0 && len(f) > 0 {
			set(f[0], "snap:"+f[0])
		}
	}
	// Executables on PATH, traced to their apt package where dpkg knows the
	// file.
	var paths []string
	exes := map[string]string{}
	for _, dir := range env.Path() {
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			p := filepath.Join(dir, e.Name())
			if _, ok := exes[e.Name()]; !ok {
				exes[e.Name()] = p
				if strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/bin/") {
					paths = append(paths, p)
				}
			}
		}
	}
	byPath := DpkgOwners(DpkgInfo, paths)
	if byPath == nil {
		byPath = map[string]string{}
		for start := 0; start < len(paths); start += 500 {
			batch := paths[start:min(start+500, len(paths))]
			r := env.Run(ctx, "dpkg", append([]string{"-S"}, batch...), exec.Options{Timeout: time.Minute})
			for _, line := range strings.Split(r.Stdout, "\n") {
				if pkg, path, ok := strings.Cut(line, ": "); ok {
					byPath[strings.TrimSpace(path)] = strings.SplitN(strings.Split(pkg, ",")[0], ":", 2)[0]
				}
			}
		}
	}
	for name, p := range exes {
		if pkg, ok := byPath[p]; ok {
			set(name, "apt:"+pkg)
		} else {
			set(name, "exe:"+p)
		}
	}
	return out
}

// Owners is the owner table with its names sorted once.
type Owners struct {
	m    map[string]string
	keys []string
}

// NewOwners indexes an owner table by normalized name.
func NewOwners(m map[string]string) Owners {
	keys := make([]string, 0, len(m))
	for k := range m {
		if len(k) >= 4 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return Owners{m: m, keys: keys}
}

// Owner finds the owner label of a config named name: an exact normalized
// match, a program name plus a common word (".zshenv"), else a program
// whose name starts with it or that it starts with (both at least four
// characters).
func (o Owners) Owner(name string) string {
	own := o.m
	n := files.Normalize(name)
	if n == "" {
		return ""
	}
	if l, ok := own[n]; ok {
		return l
	}
	// ".zshenv", ".rgignore", ".wakatime.bdb": a program name plus a common
	// word.
	for _, suf := range dotSuffixes {
		if t := strings.TrimSuffix(n, suf); t != n && len(t) >= 2 {
			if l, ok := own[t]; ok {
				return l
			}
		}
	}
	if len(n) < 4 {
		return ""
	}
	for _, k := range o.keys {
		if strings.HasPrefix(k, n) || strings.HasPrefix(n, k) {
			return own[k]
		}
	}
	return ""
}

// entries lists ~/.config children and home dot-entries with their owners.
func entries(ctx context.Context, o Options) []Entry {
	env := o.Env
	own := NewOwners(owners(ctx, o))
	var out []Entry
	cfg := env.XDG("XDG_CONFIG_HOME")
	consider := func(p, name string) {
		e := Entry{Path: p, Owner: own.Owner(name)}
		if name == "audit" {
			// audit's own config is never an orphan, installed on PATH or
			// not.
			e.Owner = "audit"
		}
		if e.Owner == "" && files.Installed(name, map[string]bool{}) {
			// Desktop-wide entries (mime, fontconfig...) need no owner.
			e.Owner = "desktop"
		}
		if e.Owner == "" {
			// Only orphans are sized: sizing every dot-directory means
			// walking all of home.
			e.Bytes = files.SizeOf(p)
		}
		out = append(out, e)
	}
	if es, err := os.ReadDir(cfg); err == nil {
		for _, e := range es {
			if excluded(e.Name(), o.Exclude) {
				continue
			}
			consider(filepath.Join(cfg, e.Name()), strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))
		}
	}
	if es, err := os.ReadDir(env.Home); err == nil {
		for _, e := range es {
			name := e.Name()
			base := numericTail.ReplaceAllString(name, "")
			if !strings.HasPrefix(name, ".") || standardDot[name] || standardDot[base] || strings.HasPrefix(name, ".zcompdump") {
				continue
			}
			consider(filepath.Join(env.Home, name), dotName(base))
		}
	}
	guessPackages(ctx, env, out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// guessPackages names an uninstalled apt package for each orphan whose name
// is a package name, in one apt-cache query.
func guessPackages(ctx context.Context, env *exec.Env, es []Entry) {
	if env.Which("apt-cache") == "" {
		return
	}
	want := map[string][]int{}
	for i, e := range es {
		if e.Owner != "" {
			continue
		}
		name := strings.ToLower(dotName(numericTail.ReplaceAllString(filepath.Base(e.Path), "")))
		if len(name) >= 3 && regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`).MatchString(name) {
			want[name] = append(want[name], i)
		}
	}
	if len(want) == 0 {
		return
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, regexp.QuoteMeta(n))
	}
	sort.Strings(names)
	r := env.Run(ctx, "apt-cache", []string{"search", "--names-only", "^(" + strings.Join(names, "|") + ")$"},
		exec.Options{Timeout: time.Minute})
	for _, line := range strings.Split(r.Stdout, "\n") {
		pkg, _, _ := strings.Cut(line, " ")
		for _, i := range want[pkg] {
			es[i].Guess = "apt:" + pkg
		}
	}
}

// DpkgInfo is where dpkg keeps each package's file list.
var DpkgInfo = "/var/lib/dpkg/info"

// DpkgOwners maps the wanted paths to their packages by reading dpkg's
// *.list files, which is much faster than dpkg -S for thousands of paths.
// It returns nil when the lists cannot be read. /bin and /usr/bin are the
// same directory on merged-/usr systems, so both spellings match.
func DpkgOwners(info string, paths []string) map[string]string {
	lists, err := filepath.Glob(filepath.Join(info, "*.list"))
	if err != nil || len(lists) == 0 {
		return nil
	}
	want := map[string]string{}
	for _, p := range paths {
		want[p] = p
		if rest, ok := strings.CutPrefix(p, "/usr"); ok {
			want[rest] = p
		} else {
			want["/usr"+p] = p
		}
	}
	out := map[string]string{}
	for _, l := range lists {
		b, err := os.ReadFile(l) // #nosec G304 -- dpkg's own file lists
		if err != nil {
			continue
		}
		pkg := strings.SplitN(strings.TrimSuffix(filepath.Base(l), ".list"), ":", 2)[0]
		for line := range strings.SplitSeq(string(b), "\n") {
			if p, ok := want[line]; ok {
				if _, seen := out[p]; !seen {
					out[p] = pkg
				}
			}
		}
	}
	return out
}
