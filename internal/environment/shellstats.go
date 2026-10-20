package environment

import (
	"bufio"
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// ShellStats is what a login shell defines once startup is done: counts of
// its aliases, functions, variables and so on (the keys of statKeys), its
// fpath, and aliases that run a missing command or hide one on PATH. Only
// names are collected; alias bodies and variable values never leave the
// shell.
type ShellStats struct {
	Counts map[string]int `json:"counts,omitempty"`
	Fpath  []string       `json:"fpath,omitempty"`
	// BrokenAliases maps an alias to the command it runs, which is not an
	// alias, function, builtin or program.
	BrokenAliases map[string]string `json:"broken_aliases,omitempty"`
	// ShadowAliases are aliases named like a program on PATH that run
	// something else.
	ShadowAliases []string `json:"shadow_aliases,omitempty"`
}

// statKeys orders the counts in the summary, with their labels.
var statKeys = []struct{ key, label string }{
	{"aliases", "aliases"},
	{"functions", "functions"},
	{"params", "parameters"},
	{"exports", "exported"},
	{"arrays", "arrays"},
	{"integers", "integers"},
	{"paths", "PATH entries"},
	{"fpaths", "fpath entries"},
	{"bins", "programs on PATH"},
	{"commands", "commands"},
	{"commands_unique", "unique commands"},
	{"completions", "completions"},
	{"bindkeys", "key bindings"},
	{"widgets", "widgets"},
	{"zinit_plugins", "zinit plugins"},
	{"zinit_snippets", "zinit snippets"},
}

// statsScripts print one "count KEY N", "fpath DIR", "alias_broken NAME
// CMD" or "alias_shadow NAME" line each. They run in the startup shell after
// the time stamp and the environment dump, isolated from the user's options
// (emulate -L in zsh, a subshell in bash), with their output going to the
// stats file so none of it reaches the startup output. Only an alias whose
// first word is a plain command name is checked, so env assignments and
// quoting in alias bodies are never printed.
var statsScripts = map[string]string{
	"zsh": `() {
  emulate -L zsh
  setopt extended_glob
  local -a t l
  local a w
  t=(${(v)parameters})
  print -r -- count aliases ${#aliases}
  print -r -- count functions ${#functions}
  print -r -- count params ${#t}
  l=(${(M)t:#*-export*}); print -r -- count exports ${#l}
  l=(${(M)t:#(array|association)*}); print -r -- count arrays ${#l}
  l=(${(M)t:#integer*}); print -r -- count integers ${#l}
  print -r -- count paths ${#path}
  print -r -- count fpaths ${#fpath}
  l=(${(f)"$(bindkey)"}); l=(${l:#* self-insert}); print -r -- count bindkeys ${#l}
  l=(${(f)"$(zle -la)"}); print -r -- count widgets ${#l}
  l=(${(f)"$(whence -ma '*')"}); print -r -- count commands ${#l}
  l=(${(f)"$(whence -m '*')"}); print -r -- count commands_unique ${#l}
  (( ${+_comps} )) && print -r -- count completions ${#_comps}
  (( ${+ZINIT_REGISTERED_PLUGINS} )) && print -r -- count zinit_plugins ${#ZINIT_REGISTERED_PLUGINS}
  (( ${+ZINIT_SNIPPETS} )) && print -r -- count zinit_snippets ${#ZINIT_SNIPPETS}
  print -rl -- "fpath "${^fpath}
  for a in ${(k)aliases}; do
    l=(${(z)aliases[$a]}); w=${l[1]}
    [[ $w == [[:alnum:]_./][[:alnum:]_.+/-]# ]] || continue
    whence -- $w >/dev/null || print -r -- alias_broken $a $w
    [[ $w != $a ]] && whence -p -- $a >/dev/null && print -r -- alias_shadow $a
  done
  return 0
} >"$AUDIT_ENV_OUT.s" 2>/dev/null`,
	"bash": `(
  set +eu
  echo count aliases $(compgen -a | wc -l)
  echo count functions $(compgen -A function | wc -l)
  echo count params $(compgen -v | wc -l)
  echo count exports $(compgen -e | wc -l)
  echo count arrays $(compgen -A arrayvar | wc -l)
  echo count integers $(declare -i | wc -l)
  IFS=: read -ra p <<<"$PATH"; echo count paths ${#p[@]}
  echo count bindkeys $( { bind -p; bind -X; } 2>/dev/null | grep -v '^#' | grep -vc 'self-insert$')
  echo count commands $(compgen -c | wc -l)
  echo count commands_unique $(compgen -c | sort -u | wc -l)
  echo count completions $(complete -p | wc -l)
  for a in $(compgen -a); do
    w=${BASH_ALIASES[$a]%%[[:space:]]*}
    [[ $w =~ ^[[:alnum:]_./][[:alnum:]_.+/-]*$ ]] || continue
    type -- "$w" >/dev/null 2>&1 || echo "alias_broken $a $w"
    [[ $w != "$a" ]] && type -P -- "$a" >/dev/null && echo "alias_shadow $a"
  done
  exit 0
) >"$AUDIT_ENV_OUT.s" 2>/dev/null`,
}

// captureScriptFor is captureScript with shell's stats collection before the
// exit.
func captureScriptFor(shell string) string {
	s, ok := statsScripts[shell]
	if !ok {
		return captureScript
	}
	return strings.TrimSuffix(captureScript, "exit") + s + "; exit"
}

// parseStats reads the stats file; nil when it holds nothing.
func parseStats(data []byte) *ShellStats {
	st := &ShellStats{Counts: map[string]int{}}
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		kind, rest, _ := strings.Cut(sc.Text(), " ")
		switch kind {
		case "count":
			k, v, _ := strings.Cut(rest, " ")
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && k != "" {
				st.Counts[k], found = n, true
			}
		case "fpath":
			if rest != "" {
				st.Fpath, found = append(st.Fpath, rest), true
			}
		case "alias_broken":
			if name, cmd, ok := strings.Cut(rest, " "); ok && name != "" {
				if st.BrokenAliases == nil {
					st.BrokenAliases = map[string]string{}
				}
				st.BrokenAliases[name], found = cmd, true
			}
		case "alias_shadow":
			if rest != "" {
				st.ShadowAliases, found = append(st.ShadowAliases, rest), true
			}
		}
	}
	if !found {
		return nil
	}
	sort.Strings(st.ShadowAliases)
	return st
}

// countBins counts the distinct names of executable files in the directories
// of path.
func countBins(path string) int {
	names := map[string]bool{}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if names[e.Name()] || e.IsDir() {
				continue
			}
			info, err := os.Stat(filepath.Join(dir, e.Name()))
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				names[e.Name()] = true
			}
		}
	}
	return len(names)
}

// shellStats is one summary row per count and shell: the count under a
// terminal, with the count without one when it differs.
func shellStats(captures []Capture) []run.Stat {
	shells, tty, notty := statsByShell(captures)
	var out []run.Stat
	for _, sh := range shells {
		for _, k := range statKeys {
			a, inTTY := countOf(tty[sh], k.key)
			b, inNoTTY := countOf(notty[sh], k.key)
			var v string
			switch {
			case inTTY && (!inNoTTY || a == b):
				v = strconv.Itoa(a)
			case inTTY:
				v = fmt.Sprintf("%d (no terminal: %d)", a, b)
			case inNoTTY:
				v = fmt.Sprintf("%d (no terminal only)", b)
			default:
				continue
			}
			out = append(out, run.Stat{Group: sh, Name: k.label, Value: v})
		}
	}
	return out
}

func countOf(st *ShellStats, key string) (int, bool) {
	if st == nil {
		return 0, false
	}
	n, ok := st.Counts[key]
	return n, ok
}

// statsByShell returns each shell's stats under a terminal and without one.
func statsByShell(captures []Capture) (shells []string, tty, notty map[string]*ShellStats) {
	tty, notty = map[string]*ShellStats{}, map[string]*ShellStats{}
	for _, c := range captures {
		if c.Stats == nil {
			continue
		}
		if tty[c.Shell] == nil && notty[c.Shell] == nil {
			shells = append(shells, c.Shell)
		}
		if c.Mode == ModeTTY {
			tty[c.Shell] = c.Stats
		} else {
			notty[c.Shell] = c.Stats
		}
	}
	return shells, tty, notty
}

// preferTTY is the terminal capture's stats, else the other one's.
func preferTTY(sh string, tty, notty map[string]*ShellStats) *ShellStats {
	if st := tty[sh]; st != nil {
		return st
	}
	return notty[sh]
}

func aliasBroken(s *State) []finding.Finding {
	shells, tty, notty := statsByShell(s.Captures)
	var out []finding.Finding
	for _, sh := range shells {
		names := map[string]string{}
		for _, st := range []*ShellStats{tty[sh], notty[sh]} {
			if st != nil {
				maps.Copy(names, st.BrokenAliases)
			}
		}
		for _, a := range slices.Sorted(maps.Keys(names)) {
			cmd := names[a]
			where := ""
			switch {
			case tty[sh] != nil && tty[sh].BrokenAliases[a] == "":
				where = " without a terminal"
			case notty[sh] != nil && notty[sh].BrokenAliases[a] == "":
				where = " under a terminal"
			}
			msg := fmt.Sprintf("%s alias %s runs %s, which is not a command%s", sh, a, cmd, where)
			var details []string
			for _, d := range s.definitions()["alias:"+a] {
				if slices.Contains(d.shells, sh) {
					details = append(details, fmt.Sprintf("%s: line %d: %s", d.path, d.line, msg))
				}
			}
			out = append(out, finding.Finding{
				Severity: finding.Warning, Subject: sh + " " + a, Message: msg, Details: details,
				Hint: "Install " + cmd + ", or remove the alias (or define it only when `command -v " + cmd + "` succeeds).",
				Group: &finding.Group{ID: "alias_broken", Rollup: true,
					Title: "Fix or remove {n} shell alias definition{s} that run a missing command",
					Hint:  "Install the command, or remove the alias or define it only when `command -v` finds the command."},
			})
		}
	}
	return out
}

func aliasShadows(s *State) []finding.Finding {
	shells, tty, notty := statsByShell(s.Captures)
	var out []finding.Finding
	for _, sh := range shells {
		st := preferTTY(sh, tty, notty)
		if len(st.ShadowAliases) == 0 {
			continue
		}
		n := len(st.ShadowAliases)
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: sh, Details: st.ShadowAliases,
			Message: fmt.Sprintf("%d %s alias%s named like a program on PATH run%s something else",
				n, sh, plural(n, "", "es"), plural(n, "s", "")),
			Hint: "Usually intended (vim=nvim); scripts and `command NAME` still get the program. " +
				"Rename an alias if typing the name should run the program.",
		})
	}
	return out
}

func fpathMissing(s *State) []finding.Finding {
	shells, tty, notty := statsByShell(s.Captures)
	seen := map[string]bool{}
	var out []finding.Finding
	for _, sh := range shells {
		for _, d := range preferTTY(sh, tty, notty).Fpath {
			if seen[d] || !filepath.IsAbs(d) {
				continue
			}
			seen[d] = true
			if !isDir(d) {
				out = append(out, finding.Finding{Severity: finding.Info, Subject: d,
					Message: sh + " fpath entry does not exist: " + d,
					Hint:    "Every missing entry is searched for each autoloaded function; drop it where fpath is set."})
			}
		}
	}
	return out
}

func fpathDuplicate(s *State) []finding.Finding {
	shells, tty, notty := statsByShell(s.Captures)
	var out []finding.Finding
	for _, sh := range shells {
		positions := map[string][]string{}
		var order []string
		for i, d := range preferTTY(sh, tty, notty).Fpath {
			n := filepath.Clean(d)
			if _, ok := positions[n]; !ok {
				order = append(order, n)
			}
			positions[n] = append(positions[n], fmt.Sprint(i))
		}
		for _, d := range order {
			if idx := positions[d]; len(idx) > 1 {
				out = append(out, finding.Finding{
					Severity: finding.Notice, Subject: d,
					Message: fmt.Sprintf("%s appears %d times in %s fpath (positions %s)", d, len(idx), sh, strings.Join(idx, ", ")),
					Hint:    "Something adds it without a guard; use `typeset -U fpath` or check before prepending.",
				})
			}
		}
	}
	return out
}

// nottyDefinitions reports shells that define fewer aliases or functions when started
// without a terminal, which is how IDEs and AI agents start them.
func nottyDefinitions(s *State) []finding.Finding {
	shells, tty, notty := statsByShell(s.Captures)
	var out []finding.Finding
	for _, sh := range shells {
		a, b := tty[sh], notty[sh]
		if a == nil || b == nil {
			continue
		}
		var missing []string
		for _, k := range []string{"aliases", "functions"} {
			if t, n := a.Counts[k], b.Counts[k]; n < t {
				missing = append(missing, fmt.Sprintf("%d of %d %s", n, t, k))
			}
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, finding.Finding{
			Severity: finding.Info, Subject: sh,
			Message: fmt.Sprintf("%s login startup without a terminal defines only %s", sh, strings.Join(missing, " and ")),
			Hint: "Tools that start `" + sh + " -lic` without a terminal (IDEs, AI agents) miss the rest. " +
				"If that is not intended, look for `[[ -t ... ]]` guards or plugins that skip non-terminal shells.",
		})
	}
	return out
}
