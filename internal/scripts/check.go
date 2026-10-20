package scripts

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/progress"
	"github.com/njhoffman/audit/internal/run"
)

// ScanOptions configure Scan.
type ScanOptions struct {
	Options
	Env *exec.Env
	// ShellcheckSeverity and ShellcheckExclude follow environment.shellcheck.
	ShellcheckSeverity string
	ShellcheckExclude  []string
	// StaleAfter is how long a script goes unchanged before a broken one
	// counts as dead.
	StaleAfter time.Duration
	// Descriptions are cached AI descriptions by content hash.
	Descriptions map[string]string
	Now          time.Time
}

// Data is what a scripts run stores.
type Data struct {
	Scripts []Script `json:"scripts"`
}

func mk(check string, sev finding.Severity, s Script, msg, hint string) finding.Finding {
	return finding.Finding{Command: Command, Check: "script." + check, Kind: finding.Issue, Severity: sev, Subject: s.Path,
		Message: msg, Hint: hint}
}

// Scan discovers, describes and checks the scripts.
func Scan(ctx context.Context, o ScanOptions, rep progress.Reporter) (*Data, []finding.Finding, []run.Stat, []string, error) {
	paths := Discover(o.Options)
	env := o.Env
	d := &Data{}
	var out []finding.Finding
	var errs []string
	rep.Phase("reading scripts", len(paths))
	for _, p := range paths {
		s, data := Inspect(env, p)
		if s.Description == "" {
			if desc, ok := o.Descriptions[s.SHA256]; ok {
				s.Description, s.DescSource = desc, "ai"
			}
		}
		out = append(out, hygiene(env, s, data, o)...)
		d.Scripts = append(d.Scripts, s)
		rep.Step(s.Name)
		if ctx.Err() != nil {
			return nil, nil, nil, nil, ctx.Err()
		}
	}
	rep.Phase("linting", 0)
	lint, lerrs := Lint(ctx, env, d.Scripts, o)
	out = append(out, lint...)
	errs = append(errs, lerrs...)
	count := map[string]int{}
	for _, f := range out {
		count[f.Subject]++
	}
	described := 0
	for i := range d.Scripts {
		d.Scripts[i].Issues = count[d.Scripts[i].Path]
		if d.Scripts[i].Description != "" {
			described++
		}
	}
	finding.Sort(out)
	linted := "yes"
	if env.Which("shellcheck") == "" {
		linted = "no: shellcheck is not installed"
	}
	stats := []run.Stat{
		{Name: "scripts", Value: fmt.Sprint(len(d.Scripts))},
		{Name: "shell scripts linted", Value: linted},
		{Name: "described", Value: fmt.Sprintf("%d (%d without a description; audit scripts describe fills them)", described, len(d.Scripts)-described)},
	}
	return d, out, stats, errs, ctx.Err()
}

// onPath reports whether the script's directory is on PATH, so its name
// is a command.
func onPath(env *exec.Env, p string) bool {
	dir := filepath.Dir(p)
	for _, d := range env.Path() {
		if real, err := filepath.EvalSymlinks(d); err == nil && real == dir || d == dir {
			return true
		}
	}
	return false
}

func hygiene(env *exec.Env, s Script, data []byte, o ScanOptions) []finding.Finding {
	var out []finding.Finding
	if interp := missingInterpreter(env, s); interp != "" {
		out = append(out, mk("interpreter", finding.Error, s, fmt.Sprintf("%s runs %s, which is not installed", s.Name, interp),
			"Install it or fix the shebang."))
	}
	if strings.HasPrefix(string(data), "#!") && !s.Executable {
		out = append(out, mk("not_executable", finding.Notice, s, s.Name+" has a shebang but is not executable", "chmod +x "+s.Path))
	}
	if strings.Contains(string(data), "\r\n") {
		out = append(out, mk("crlf", finding.Warning, s, s.Name+" has Windows (CRLF) line endings; the shebang line breaks with them",
			"sed -i 's/\\r$//' "+s.Path))
	}
	if onPath(env, s.Path) {
		if all := env.WhichAll(s.Name); len(all) > 0 && all[0] != s.Path {
			if real, err := filepath.EvalSymlinks(all[0]); err != nil || real != s.Path {
				out = append(out, mk("shadowed", finding.Notice, s, fmt.Sprintf("%s is shadowed by %s, earlier on PATH", s.Name, all[0]),
					"Rename one of them, or reorder PATH."))
			}
		}
	}
	if len(s.Missing) > 0 {
		f := mk("missing_commands", finding.Info, s, fmt.Sprintf("%s calls commands that are not installed: %s", s.Name, strings.Join(s.Missing, ", ")),
			"Install them, or remove the script if it is no longer used.")
		f.Group = &finding.Group{ID: "missing_commands", Title: "Install the commands scripts call, or retire the scripts",
			Hint: "the list is a heuristic; ignore scripts:script.missing_commands:PATH for false matches"}
		out = append(out, f)
	}
	broken := len(s.Missing) > 0 || missingInterpreter(env, s) != ""
	if broken && o.StaleAfter > 0 && !s.ModTime.IsZero() && o.Now.Sub(s.ModTime) >= o.StaleAfter {
		f := mk("dead", finding.Info, s, fmt.Sprintf("%s has not changed since %s and calls things that are not installed; it is probably dead",
			s.Name, s.ModTime.Format(time.DateOnly)), "Delete it, or fix it if you still use it.")
		f.Kind = finding.Suggestion
		f.Group = &finding.Group{ID: "dead", Title: "Retire scripts that look dead", Hint: "review and delete them"}
		out = append(out, f)
	}
	return out
}

type shellcheckComment struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Lint runs the language checks that never execute a script: shellcheck
// (one call for all shell scripts), zsh -n, a Python ast parse (ruff when
// installed), node --check, luac -p, ruby -c and fish -n.
func Lint(ctx context.Context, env *exec.Env, ss []Script, o ScanOptions) ([]finding.Finding, []string) {
	var out []finding.Finding
	var errs []string
	byPath := map[string]Script{}
	var shell []string
	for _, s := range ss {
		byPath[s.Path] = s
		if s.Lang == "shell" || s.Lang == "bash" {
			shell = append(shell, s.Path)
		}
	}
	if len(shell) > 0 && env.Which("shellcheck") != "" {
		sev := o.ShellcheckSeverity
		if sev == "" {
			sev = "warning"
		}
		args := []string{"-f", "json1", "-S", sev}
		if len(o.ShellcheckExclude) > 0 {
			args = append(args, "-e", strings.Join(o.ShellcheckExclude, ","))
		}
		for start := 0; start < len(shell); start += 200 {
			batch := shell[start:min(start+200, len(shell))]
			r := env.Run(ctx, "shellcheck", append(args, batch...), exec.Options{Timeout: 5 * time.Minute})
			var res struct {
				Comments []shellcheckComment `json:"comments"`
			}
			if err := json.Unmarshal([]byte(r.Stdout), &res); err != nil {
				errs = append(errs, "shellcheck: "+oneLine(r.Stderr))
				continue
			}
			grouped := map[string][]string{}
			worst := map[string]finding.Severity{}
			for _, c := range res.Comments {
				grouped[c.File] = append(grouped[c.File], fmt.Sprintf("line %d: SC%d %s", c.Line, c.Code, c.Message))
				s := finding.Notice
				switch c.Level {
				case "error":
					s = finding.Error
				case "warning":
					s = finding.Warning
				}
				if w, ok := worst[c.File]; !ok || s.Rank() > w.Rank() {
					worst[c.File] = s
				}
			}
			files := make([]string, 0, len(grouped))
			for f := range grouped {
				files = append(files, f)
			}
			sort.Strings(files)
			for _, f := range files {
				sc := byPath[f]
				fd := mk("shellcheck", worst[f], sc, fmt.Sprintf("shellcheck reports %d problem(s) in %s", len(grouped[f]), sc.Name),
					"shellcheck "+f)
				fd.Details = grouped[f]
				fd.Group = &finding.Group{ID: "shellcheck", Rollup: true, Title: "Fix shellcheck {level} in {n} script{s}",
					Hint: "Run shellcheck FILE for context and fixes."}
				out = append(out, fd)
			}
		}
	}
	for _, s := range ss {
		if ctx.Err() != nil {
			break
		}
		var r exec.Result
		var tool string
		switch {
		case s.Lang == "zsh" && env.Which("zsh") != "":
			tool, r = "zsh -n", quiet(ctx, env, "zsh", "-n", s.Path)
		case s.Lang == "python" && env.Which("python3") != "":
			tool = "python ast"
			r = quiet(ctx, env, "python3", "-I", "-c", "import ast,sys; ast.parse(open(sys.argv[1],'rb').read(), sys.argv[1])", s.Path)
			if r.OK() && env.Which("ruff") != "" {
				if rr := quiet(ctx, env, "ruff", "check", "--no-cache", "--quiet", "--select", "E9,F63,F7,F82", s.Path); !rr.OK() {
					tool, r = "ruff", rr
				}
			}
		case s.Lang == "node" && env.Which("node") != "":
			tool, r = "node --check", quiet(ctx, env, "node", "--check", s.Path)
		case s.Lang == "lua" && env.Which("luac") != "":
			tool, r = "luac -p", quiet(ctx, env, "luac", "-p", s.Path)
		case s.Lang == "ruby" && env.Which("ruby") != "":
			tool, r = "ruby -c", quiet(ctx, env, "ruby", "-c", s.Path)
		case s.Lang == "fish" && env.Which("fish") != "":
			tool, r = "fish -n", quiet(ctx, env, "fish", "-n", s.Path)
		default:
			continue
		}
		if !r.OK() && r.Code != exec.ExitNotFound && r.Code != exec.ExitTimeout {
			msg := oneLine(r.Stderr + "\n" + r.Stdout)
			f := mk("syntax", finding.Error, s, fmt.Sprintf("%s: %s reports %s", s.Name, tool, msg), "Fix the reported line.")
			f.Group = &finding.Group{ID: "syntax", Rollup: true, Title: "Fix parse errors in {n} script{s}"}
			out = append(out, f)
		}
	}
	return out, errs
}

func oneLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > 200 {
				l = l[:200] + "..."
			}
			return l
		}
	}
	return "an error"
}
