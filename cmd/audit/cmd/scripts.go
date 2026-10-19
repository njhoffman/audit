package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/llm"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/scripts"
)

func newScriptsCmd(a *app) *cobra.Command {
	var find string
	c, f := scanCommand(a, "scripts", "Describe and check your scripts",
		`Inventory the scripts under scripts.roots (~/bin, ~/.local/bin and every
~/.config/*/scripts by default): files with a shebang or a script
extension, never compiled binaries or symlinks. Each gets a description
from its header comment or docstring (and usage text), or one audit
scripts describe asked the AI for, cached by content.

Checks never run a script: shellcheck (environment.shellcheck severity and
excludes), zsh -n, a Python ast parse (and ruff's syntax rules when
installed), node --check, luac -p, ruby -c and fish -n; a missing shebang
interpreter, a shebang without the executable bit, CRLF line endings, a
name shadowed earlier on PATH, commands shell scripts call that are not
installed (a heuristic), and broken scripts unchanged for
scripts.stale_after, suggested for removal. perl -c is not used because it
runs BEGIN blocks.

--list shows every script with its language, description and issue count;
--find filters it; audit scripts info NAME shows one.`,
		func() (core.Scanner, error) { return a.scriptsScanner(), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) {
			var d scripts.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				a.log.Warn("read scripts data", "err", err)
				return
			}
			var rows [][]string
			for _, s := range d.Scripts {
				if find != "" && !strings.Contains(strings.ToLower(s.Path+" "+s.Description), strings.ToLower(find)) {
					continue
				}
				issues := "-"
				if s.Issues > 0 {
					issues = fmt.Sprint(s.Issues)
				}
				rows = append(rows, []string{s.Name, s.Lang, issues, s.Description, shortPath(filepath.Dir(s.Path), a.env.Home)})
			}
			p.Table([]string{"SCRIPT", "LANG", "ISSUES", "DESCRIPTION", "DIR"}, rows)
		})
	c.Flags().StringVarP(&find, "find", "f", "", "list only scripts whose path or description contains this text (implies --list)")
	f.impliesList = func() bool { return find != "" }
	f.jsonExtra = func(_ context.Context, r *run.Run) (any, error) {
		var d scripts.Data
		err := json.Unmarshal(r.Data, &d)
		return d, err
	}
	c.AddCommand(newScriptsDescribeCmd(a), newScriptsInfoCmd(a))
	return c
}

func (a *app) scriptsScanner() *core.ScriptsScanner {
	s := core.NewScripts(a.cfg, a.env)
	s.Descs = a.store
	return s
}

// savedScripts loads the saved scripts run, scanning first when there is
// none.
func (a *app) savedScripts(ctx context.Context) (scripts.Data, error) {
	var d scripts.Data
	res, err := a.engine.Resolve(ctx, a.scriptsScanner(), core.Auto, a.progress(true))
	if err != nil {
		return d, err
	}
	err = json.Unmarshal(res.Run.Data, &d)
	return d, err
}

func matchScript(s scripts.Script, arg string) bool {
	return s.Name == arg || s.Path == arg || strings.HasSuffix(s.Path, "/"+arg)
}

func newScriptsDescribeCmd(a *app) *cobra.Command {
	var all, refresh, asJSON bool
	c := &cobra.Command{
		Use:   "describe [script...]",
		Short: "Ask the AI to describe scripts that have no header description",
		Long: `Send scripts without a header description (all with --all, or the named
ones) to the AI CLI (ai.provider, or --ai-provider), ten per request with
each script's first 4000 bytes, and save the one-sentence answers by
content hash, so a script is only described again after it changes. The
script contents leave the machine with this command only. Then the scripts
scan is saved again so the list shows the descriptions.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			return a.describeScripts(c.Context(), args, all, refresh, asJSON)
		},
	}
	fl := c.Flags()
	fl.BoolVarP(&all, "all", "a", false, "describe every script, header description or not")
	fl.BoolVarP(&refresh, "ai-refresh", "A", false, "ask again instead of using cached answers")
	fl.BoolVarP(&asJSON, "json", "j", false, "print the new descriptions as JSON")
	return c
}

func (a *app) describeScripts(ctx context.Context, names []string, all, refresh, asJSON bool) error {
	d, err := a.savedScripts(ctx)
	if err != nil {
		return err
	}
	var todo []scripts.Script
	for _, s := range d.Scripts {
		named := len(names) == 0
		for _, n := range names {
			named = named || matchScript(s, n)
		}
		if named && (all || len(names) > 0 || s.Description == "") {
			todo = append(todo, s)
		}
	}
	if len(todo) == 0 {
		if !asJSON {
			sayln(a.out, "Every script has a description.")
		}
		return nil
	}
	client := a.aiClient("")
	rep := a.progress(!asJSON)
	const batch = 10
	rep.Phase("describing scripts ("+client.Label()+")", (len(todo)+batch-1)/batch)
	got := map[string]string{}
	var failures []string
	for start := 0; start < len(todo); start += batch {
		part := todo[start:min(start+batch, len(todo))]
		in := make([]llm.ScriptInput, 0, len(part))
		byPath := map[string]scripts.Script{}
		for _, s := range part {
			b, err := os.ReadFile(s.Path) // #nosec G304 -- the user's scripts
			if err != nil {
				continue
			}
			in = append(in, llm.ScriptInput{Path: s.Path, Lang: s.Lang, Content: string(b)})
			byPath[s.Path] = s
		}
		var ans llm.ScriptDescriptions
		resp, err := client.AskJSON(ctx, llm.DescribeScriptsRequest(in), refresh, &ans)
		rep.Step(fmt.Sprintf("%d/%d", min(start+batch, len(todo)), len(todo)))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures = append(failures, err.Error())
			continue
		}
		for _, x := range ans.Descriptions {
			s, ok := byPath[x.Path]
			desc := strings.TrimSpace(x.Description)
			if !ok || desc == "" {
				continue
			}
			if err := a.store.SaveScriptDescription(ctx, s.SHA256, desc, resp.Model, timeNow()); err != nil {
				return err
			}
			got[s.Path] = desc
		}
	}
	rep.Done()
	if _, err := a.engine.Execute(ctx, a.scriptsScanner(), a.progress(!asJSON)); err != nil {
		a.log.Warn("rescan after describing", "err", err)
	}
	if asJSON {
		return a.writeJSON(got)
	}
	say(a.out, "Described %d of %d script(s).\n", len(got), len(todo))
	for _, f := range failures {
		say(a.errOut, "AI request failed: %s\n", f)
	}
	if len(got) == 0 && len(failures) > 0 {
		return errors.New("no descriptions; the AI requests failed")
	}
	return nil
}

func newScriptsInfoCmd(a *app) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "info SCRIPT",
		Short: "Show one script's description, usage and issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := a.load(); err != nil {
				return err
			}
			ctx := c.Context()
			r, err := a.engine.Saved(ctx, scripts.Command, "")
			if err != nil {
				return err
			}
			if r == nil {
				return errors.New("no saved scripts results; run `audit scripts -r` first")
			}
			var d scripts.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				return err
			}
			var hits []scripts.Script
			for _, s := range d.Scripts {
				if matchScript(s, args[0]) {
					hits = append(hits, s)
				}
			}
			switch len(hits) {
			case 0:
				return fmt.Errorf("no script matches %q", args[0])
			case 1:
			default:
				paths := make([]string, len(hits))
				for i, h := range hits {
					paths[i] = h.Path
				}
				return fmt.Errorf("%q matches %d scripts: %s", args[0], len(hits), strings.Join(paths, ", "))
			}
			s := hits[0]
			if asJSON {
				return a.writeJSON(s)
			}
			rows := [][]string{{"path", s.Path}, {"language", s.Lang}, {"interpreter", s.Interpreter},
				{"description", s.Description}, {"source", s.DescSource}, {"usage", s.Usage},
				{"changed", s.ModTime.Local().Format("2006-01-02")}, {"missing commands", strings.Join(s.Missing, ", ")}}
			var keep [][]string
			for _, row := range rows {
				if row[1] != "" {
					keep = append(keep, row)
				}
			}
			a.printer().Table([]string{"FIELD", "VALUE"}, keep)
			for _, f := range r.Findings {
				if f.Subject == s.Path {
					say(a.out, "\n%s %s: %s\n", f.Severity, f.Check, f.Message)
					for _, d := range f.Details {
						say(a.out, "  %s\n", d)
					}
				}
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&asJSON, "json", "j", false, "print the script as JSON")
	return c
}
