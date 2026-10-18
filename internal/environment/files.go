package environment

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/njhoffman/audit/internal/exec"
)

// Dialect says which shells load a file.
type Dialect string

const (
	DialectZsh  Dialect = "zsh"
	DialectBash Dialect = "bash"
	// DialectSh files are sourced by both shells and must parse under each.
	DialectSh Dialect = "sh"
)

// Shells returns the shells that load a file of this dialect.
func (d Dialect) Shells() []string {
	switch d {
	case DialectZsh:
		return []string{"zsh"}
	case DialectBash:
		return []string{"bash"}
	}
	return []string{"bash", "zsh"}
}

// Script is one startup file.
type Script struct {
	Path    string  `json:"path"`
	Dialect Dialect `json:"dialect"`
	// Function is set for autoloadable function files, whose body defines
	// the function named after the file.
	Function string `json:"function,omitempty"`
	// Startup marks a file from the configured startup-file list (as
	// opposed to one found under a startup directory).
	Startup bool `json:"startup,omitempty"`
	// Executable marks a script with a shebang and the execute bit: it is
	// run as a command, not sourced.
	Executable bool `json:"executable,omitempty"`
	// LoadedBy lists the traced shells that sourced the file at startup.
	LoadedBy []string `json:"loaded_by,omitempty"`
}

// LoadShells returns the shells that load the script: the traced shells
// that sourced it, plus the untraced shells its dialect suggests. Autoloaded
// functions are never sourced during startup, so they use their dialect.
func (s Script) LoadShells(traced map[string]bool) []string {
	if s.Function != "" {
		return s.Dialect.Shells()
	}
	if s.Executable {
		return []string{string(s.Dialect)}
	}
	out := append([]string(nil), s.LoadedBy...)
	for _, sh := range s.Dialect.Shells() {
		if !traced[sh] && !slices.Contains(out, sh) {
			out = append(out, sh)
		}
	}
	sort.Strings(out)
	return out
}

// dialectOf guesses the dialect from the path: zsh/ and bash/ directories,
// .zsh/.bash extensions and the dotfile names each shell reads.
func dialectOf(path string) Dialect {
	base := filepath.Base(path)
	slashed := filepath.ToSlash(path)
	switch {
	case strings.HasSuffix(base, ".zsh"), strings.HasPrefix(base, ".z"), strings.Contains(slashed, "/zsh/"):
		return DialectZsh
	case strings.HasSuffix(base, ".bash"), strings.HasPrefix(base, ".bash"), strings.Contains(slashed, "/bash/"):
		return DialectBash
	}
	return DialectSh
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "tests": true, "test": true}

// discover lists the startup files that exist plus the shell scripts under
// dirs, without duplicates and in path order. Files are recognised by
// extension, by a shell shebang, or by living in a functions/ directory.
func discover(files, dirs []string) []Script {
	seen := map[string]bool{}
	var out []Script
	add := func(s Script) {
		if real, err := filepath.EvalSymlinks(s.Path); err == nil {
			if seen[real] {
				return
			}
			seen[real] = true
		}
		out = append(out, s)
	}
	for _, f := range files {
		if isRegular(f) {
			add(Script{Path: f, Dialect: dialectOf(f), Startup: true})
		}
	}
	for _, root := range dirs {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if s, ok := classify(path); ok {
				if sh := shebangShell(path); sh != "" && exec.IsExecutable(path) {
					s.Executable, s.Dialect = true, Dialect(sh)
				}
				add(s)
			}
			return nil
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func classify(path string) (Script, bool) {
	base := filepath.Base(path)
	switch filepath.Ext(base) {
	case ".sh", ".zsh", ".bash":
		return Script{Path: path, Dialect: dialectOf(path)}, true
	case "":
	default:
		return Script{}, false
	}
	if filepath.Base(filepath.Dir(path)) == "functions" {
		return Script{Path: path, Dialect: dialectOf(path), Function: base}, true
	}
	switch shebangShell(path) {
	case "zsh":
		return Script{Path: path, Dialect: DialectZsh}, true
	case "bash":
		return Script{Path: path, Dialect: DialectBash}, true
	case "sh":
		return Script{Path: path, Dialect: DialectSh}, true
	}
	return Script{}, false
}

// shebangShell returns zsh, bash or sh for a script with that interpreter.
func shebangShell(path string) string {
	f, err := os.Open(path) // #nosec G304 -- walking configured startup dirs
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 128)
	n, _ := f.Read(buf)
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return ""
	}
	interp := filepath.Base(fields[0])
	if interp == "env" && len(fields) > 1 {
		interp = fields[1]
	}
	switch interp {
	case "zsh", "bash", "sh", "dash":
		if interp == "dash" {
			return "sh"
		}
		return interp
	}
	return ""
}

func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}
