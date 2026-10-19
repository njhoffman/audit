// Package scripts inventories the user's scripts, describes each one from
// its header comment (or a cached AI description), and checks them without
// running them: language linters, shebang interpreters, permissions, line
// endings, PATH shadowing, commands they call that are not installed, and
// long-untouched scripts that look dead.
package scripts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// Command is the audit subcommand name.
const Command = "scripts"

// Script is one script with what audit learned about it.
type Script struct {
	Path string `json:"path"`
	Name string `json:"name"`
	// Lang is shell, bash, zsh, python, node, lua, ruby, perl, fish or "".
	Lang        string `json:"lang"`
	Interpreter string `json:"interpreter,omitempty"`
	Description string `json:"description,omitempty"`
	// DescSource is "header" or "ai".
	DescSource string    `json:"desc_source,omitempty"`
	Usage      string    `json:"usage,omitempty"`
	SHA256     string    `json:"sha256"`
	Bytes      int64     `json:"bytes"`
	ModTime    time.Time `json:"mod_time"`
	Executable bool      `json:"executable"`
	// Missing lists commands the script calls that are not installed.
	Missing []string `json:"missing,omitempty"`
	// Issues counts the findings about the script.
	Issues int `json:"issues"`
}

// Options control Discover.
type Options struct {
	Roots    []string
	MaxDepth int
	Exclude  []string
	MaxBytes int64
}

var scriptExt = map[string]string{".sh": "shell", ".bash": "bash", ".zsh": "zsh", ".py": "python", ".js": "node",
	".mjs": "node", ".cjs": "node", ".lua": "lua", ".rb": "ruby", ".pl": "perl", ".fish": "fish"}

// interpLang maps interpreter names to a language.
var interpLang = map[string]string{"sh": "shell", "dash": "shell", "ash": "shell", "ksh": "shell", "bash": "bash",
	"zsh": "zsh", "python": "python", "python3": "python", "python2": "python", "node": "node", "nodejs": "node",
	"lua": "lua", "luajit": "lua", "ruby": "ruby", "perl": "perl", "fish": "fish", "uv": "python"}

var shebangRe = regexp.MustCompile(`^#!\s*(\S+)(?:\s+(.*))?`)

// Shebang parses a first line into the interpreter path and the program it
// names ("/usr/bin/env python3" gives "/usr/bin/env", "python3").
func Shebang(line string) (interp, prog string) {
	m := shebangRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
	if m == nil {
		return "", ""
	}
	interp, prog = m[1], filepath.Base(m[1])
	if prog == "env" {
		for _, a := range strings.Fields(m[2]) {
			if strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
				continue
			}
			prog = a
			break
		}
	}
	return interp, prog
}

// LangOf picks the language from the shebang program, else the extension.
func LangOf(prog, name string) string {
	p := strings.TrimRight(prog, "0123456789.")
	if l, ok := interpLang[prog]; ok {
		return l
	}
	if l, ok := interpLang[p]; ok {
		return l
	}
	return scriptExt[strings.ToLower(filepath.Ext(name))]
}

// Discover lists the scripts under the roots: regular files with a shebang
// or a script extension; compiled binaries and symlinks are skipped. Roots
// that are symlinks (~/bin) are followed.
func Discover(o Options) []string {
	var out []string
	seen := map[string]bool{}
	for _, root := range o.Roots {
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		base := strings.Count(real, string(filepath.Separator))
		_ = filepath.WalkDir(real, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if p != real && (slicesContains(o.Exclude, e.Name()) || strings.Count(p, string(filepath.Separator))-base > o.MaxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !e.Type().IsRegular() || seen[p] {
				return nil
			}
			info, err := e.Info()
			if err != nil || info.Size() == 0 || info.Size() > o.MaxBytes {
				return nil
			}
			head := readHead(p, 4)
			if strings.HasPrefix(head, "\x7fELF") {
				return nil
			}
			if strings.HasPrefix(head, "#!") || scriptExt[strings.ToLower(filepath.Ext(p))] != "" {
				seen[p] = true
				out = append(out, p)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func slicesContains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func readHead(p string, n int) string {
	f, err := os.Open(p) // #nosec G304 -- the user's scripts
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, n)
	m, _ := f.Read(b)
	return string(b[:m])
}

// noise are header comment lines that describe nothing.
var noise = regexp.MustCompile(`(?i)^(shellcheck|vim?:|-\*-|ex:|\s*$|author|copyright|license|spdx|created|version|date|todo|fixme|=+$|-+$|#+$|\*+$)`)

// Header pulls a description and usage text from a script's leading
// comments (or a Python module docstring).
func Header(text, lang string) (desc, usage string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var lines []string
	first, inDoc := true, false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first && strings.HasPrefix(line, "#!") {
			first = false
			continue
		}
		first = false
		if lang == "python" && !inDoc && (strings.HasPrefix(line, `"""`) || strings.HasPrefix(line, `'''`)) {
			inDoc = true
			line = strings.Trim(line[3:], ` "'`)
			if line != "" {
				lines = append(lines, line)
			}
			if strings.Count(sc.Text(), `"""`)+strings.Count(sc.Text(), `'''`) >= 2 {
				break
			}
			continue
		}
		if inDoc {
			if strings.Contains(line, `"""`) || strings.Contains(line, `'''`) {
				if t := strings.Trim(strings.Split(strings.Split(line, `"""`)[0], `'''`)[0], " "); t != "" {
					lines = append(lines, t)
				}
				break
			}
			lines = append(lines, line)
			continue
		}
		var c string
		switch {
		case strings.HasPrefix(line, "--"):
			c = strings.TrimPrefix(line, "--")
		case strings.HasPrefix(line, "//"):
			c = strings.TrimPrefix(line, "//")
		case strings.HasPrefix(line, "#"):
			c = strings.TrimLeft(line, "#")
		case line == "" && len(lines) == 0:
			continue
		case lang == "python" && len(lines) == 0 && (strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "from ")):
			continue
		default:
			c = "\x00"
		}
		if c == "\x00" {
			break
		}
		lines = append(lines, strings.TrimSpace(c))
		if len(lines) > 25 {
			break
		}
	}
	var descParts, usageParts []string
	inUsage := false
	for _, l := range lines {
		lower := strings.ToLower(l)
		switch {
		case strings.HasPrefix(lower, "usage"):
			inUsage = true
			if rest := strings.TrimSpace(l[5:]); strings.Trim(rest, ": ") != "" {
				usageParts = append(usageParts, strings.TrimLeft(rest, ": "))
			}
		case inUsage && l != "":
			usageParts = append(usageParts, l)
		case l == "":
			inUsage = false
			if len(descParts) > 0 {
				descParts = append(descParts, "")
			}
		case !noise.MatchString(l):
			descParts = append(descParts, l)
		}
	}
	desc = firstParagraph(descParts)
	if len(desc) > 300 {
		desc = desc[:297] + "..."
	}
	return desc, strings.Join(usageParts, "\n")
}

func firstParagraph(parts []string) string {
	var out []string
	for _, p := range parts {
		if p == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

// shellWords are keywords and builtins never looked up on PATH.
var shellWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`if then else elif fi for while until do done case esac in function select time
		return break continue exit export local declare typeset readonly unset set shift source . eval exec trap wait
		echo printf read cd pwd pushd popd dirs test [ [[ true false alias unalias type command builtin hash getopts
		let shopt enable mapfile readarray caller compgen complete compopt disown jobs fg bg kill ulimit umask history
		fc logout suspend times help bind autoload zmodload zstyle setopt unsetopt emulate print whence where which
		noglob integer float functions zparseopts bindkey vared zle compdef rehash sched zcompile zformat zregexparse
		unfunction unhash zstat zsystem zpty ztcp zsocket strftime sysopen syswrite sysread pcre_compile pcre_match
		then do coproc { } ( ) ! :`) {
		shellWords[w] = true
	}
}

var (
	funcDef = regexp.MustCompile(`(?m)^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_:.-]*)\s*(?:\(\s*\)\s*\{?|\{)`)
	// casePattern is a case branch label line ("a|b)", "*.txt)").
	casePattern = regexp.MustCompile(`^\s*\(?[^()$=]+\)`)
	varUse      = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)|\b([A-Za-z_][A-Za-z0-9_]*)=|\b(?:local|declare|typeset|read|export)\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)`)
	funcDef2    = regexp.MustCompile(`(?m)^\s*function\s+([A-Za-z_][A-Za-z0-9_:.-]*)`)
	cmdStart    = regexp.MustCompile(`(?:^|[|;&]|\$\(|&&|\|\||\bthen\b|\bdo\b|\belse\b)\s*(?:sudo\s+|exec\s+|command\s+|nohup\s+|time\s+)?([a-z][a-z0-9_.+-]*)\b`)
)

var heredocRe = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// Commands lists the external commands a shell script appears to call: the
// first word of each command position, minus keywords, builtins, functions
// it defines, variable assignments, heredoc bodies and words in strings or
// comments. It is a heuristic for spotting commands that are not installed.
func Commands(text string) []string {
	defined := map[string]bool{}
	for _, m := range funcDef.FindAllStringSubmatch(text, -1) {
		defined[m[1]] = true
	}
	for _, m := range funcDef2.FindAllStringSubmatch(text, -1) {
		defined[m[1]] = true
	}
	for _, m := range varUse.FindAllStringSubmatch(text, -1) {
		for _, g := range m[1:] {
			if g != "" {
				defined[g] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	heredoc := ""
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if heredoc != "" {
			if t == heredoc {
				heredoc = ""
			}
			continue
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if casePattern.MatchString(t) && !strings.Contains(t, "$(") {
			// Only what follows the label is a command.
			t = t[strings.IndexByte(t, ')')+1:]
		}
		clean := stripStrings(t)
		for _, m := range cmdStart.FindAllStringSubmatchIndex(clean, -1) {
			w := clean[m[2]:m[3]]
			if m[3] < len(clean) && (clean[m[3]] == '=' || clean[m[3]] == ')') {
				continue // an assignment or a case label, not a command
			}
			if len(w) < 2 || shellWords[w] || defined[w] || seen[w] {
				continue
			}
			seen[w] = true
			out = append(out, w)
		}
		if m := heredocRe.FindStringSubmatch(t); m != nil {
			heredoc = m[1]
		}
	}
	sort.Strings(out)
	return out
}

// stripStrings blanks quoted text and trailing comments so their words are
// not taken for commands; $(...) inside double quotes is kept.
func stripStrings(s string) string {
	var b strings.Builder
	single, double := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case single:
			if c == '\'' {
				single = false
			}
			b.WriteByte(' ')
		case c == '\'' && !double:
			single = true
			b.WriteByte(' ')
		case c == '"':
			double = !double
			b.WriteByte(' ')
		case double && c == '$' && i+1 < len(s) && s[i+1] == '(':
			b.WriteByte(c)
		case double:
			if strings.ContainsRune("|;&()", rune(c)) {
				b.WriteByte(c)
			} else {
				b.WriteByte(' ')
			}
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Inspect reads a script and fills what can be learned without running it.
func Inspect(env *exec.Env, p string) (Script, []byte) {
	s := Script{Path: p, Name: filepath.Base(p)}
	data, err := os.ReadFile(p) // #nosec G304 -- the user's scripts
	if err != nil {
		return s, nil
	}
	sum := sha256.Sum256(data)
	s.SHA256, s.Bytes = hex.EncodeToString(sum[:]), int64(len(data))
	if info, err := os.Stat(p); err == nil {
		s.ModTime, s.Executable = info.ModTime(), info.Mode().Perm()&0o111 != 0
	}
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	interp, prog := Shebang(string(firstLine))
	s.Interpreter = interp
	if prog != "" && filepath.Base(interp) == "env" {
		s.Interpreter = interp + " " + prog
	}
	s.Lang = LangOf(prog, p)
	s.Description, s.Usage = Header(string(data), s.Lang)
	if s.Description != "" {
		s.DescSource = "header"
	}
	if s.Lang == "shell" || s.Lang == "bash" || s.Lang == "zsh" {
		for _, c := range Commands(string(data)) {
			if env.Which(c) == "" && !strings.Contains(c, ".") {
				s.Missing = append(s.Missing, c)
			}
		}
	}
	return s, data
}

// Missing interpreters: the shebang's path (or env's program) is not there.
func missingInterpreter(env *exec.Env, s Script) string {
	if s.Interpreter == "" {
		return ""
	}
	interp, prog, _ := strings.Cut(s.Interpreter, " ")
	if prog != "" {
		if env.Which(prog) == "" {
			return prog + " (via env)"
		}
		return ""
	}
	if _, err := os.Stat(interp); err != nil {
		return interp
	}
	return ""
}

// lintTimeout bounds one linter call.
const lintTimeout = 30 * time.Second

func quiet(ctx context.Context, env *exec.Env, name string, args ...string) exec.Result {
	return env.Run(ctx, name, args, exec.Options{Timeout: lintTimeout})
}
