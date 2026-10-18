// Package htmlreport writes self-contained HTML reports: one page per command
// run and an index summarizing every command.
package htmlreport

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
	"github.com/njhoffman/audit/internal/version"
)

//go:embed style.css
var css string

//go:embed report.html.tmpl
var reportTmpl string

//go:embed index.html.tmpl
var indexTmpl string

var funcs = template.FuncMap{
	"lower": strings.ToLower,
	"stamp": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
	"join":  strings.Join,
}

var (
	reportT = template.Must(template.New("report").Funcs(funcs).Parse(reportTmpl))
	indexT  = template.Must(template.New("index").Funcs(funcs).Parse(indexTmpl))
)

// Options carries what a report shows besides the run itself.
type Options struct {
	Thresholds config.Thresholds
	Todos      []todo.Todo
	Now        time.Time
	// RescanHint is the command line shown in the age banner.
	RescanHint string
	// Packages is the packages inventory joined with cached registry data
	// and tags; nil builds it from the run alone.
	Packages []packages.Annotated
}

// Table is a generic data section.
type Table struct {
	Title   string
	Note    string
	Columns []string
	Rows    [][]string
	// RowTags, when set, holds each row's space-separated tags for the tag
	// filter; RowClass a CSS class per row.
	RowTags  []string
	RowClass []string
}

type tagCount struct {
	Tag string
	N   int
}

type severityCount struct {
	Severity finding.Severity
	N        int
}

type statGroup struct {
	Name  string
	Stats []run.Stat
}

type reportData struct {
	CSS        template.CSS
	Version    string
	Run        *run.Run
	Generated  time.Time
	Age        string // "3h"
	Ago        string // "3h ago" or "just now"
	Freshness  string // fresh, stale or old
	Rescan     string
	Counts     []severityCount
	Total      int
	Groups     []statGroup
	Issues     []finding.Finding
	Suggestion []finding.Finding
	Tables     []Table
	Tags       []tagCount
	Todos      []todo.Todo
	Analysis   template.HTML
}

func freshness(age time.Duration, th config.Thresholds) string {
	switch run.FreshnessOf(age, th.Warn, th.Old) {
	case run.Old:
		return "old"
	case run.Stale:
		return "stale"
	}
	return "fresh"
}

// Write renders the report for r to w.
func Write(w io.Writer, r *run.Run, o Options) error {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	d := reportData{
		CSS: template.CSS(css), Version: version.Version, Run: r, Generated: now, // #nosec G203 -- embedded stylesheet
		Age: run.HumanAge(r.Age(now)), Ago: run.Ago(r.Age(now)), Freshness: freshness(r.Age(now), o.Thresholds),
		Tables: Tables(r), Rescan: o.RescanHint,
	}
	if r.Command == packages.Command && o.Packages != nil {
		d.Tables = packageTables(o.Packages, now)
	}
	d.Tags = tagCounts(d.Tables)
	if d.Rescan == "" {
		d.Rescan = "audit " + r.Command + " --rescan"
	}
	counts := r.Counts()
	for _, s := range finding.Severities {
		if n := counts[s]; n > 0 {
			d.Counts = append(d.Counts, severityCount{s, n})
		}
	}
	d.Total = counts.Total()
	for _, s := range r.Stats {
		if len(d.Groups) == 0 || d.Groups[len(d.Groups)-1].Name != s.Group {
			d.Groups = append(d.Groups, statGroup{Name: s.Group})
		}
		g := &d.Groups[len(d.Groups)-1]
		g.Stats = append(g.Stats, s)
	}
	for _, f := range r.Findings {
		if f.IsSuggestion() {
			d.Suggestion = append(d.Suggestion, f)
		} else {
			d.Issues = append(d.Issues, f)
		}
	}
	for _, t := range o.Todos {
		if t.Command == r.Command {
			d.Todos = append(d.Todos, t)
		}
	}
	todo.Sort(d.Todos)
	if r.Analysis != nil && r.Analysis.Text != "" {
		h, err := Markdown(r.Analysis.Text)
		if err != nil {
			return err
		}
		d.Analysis = h
	}
	return reportT.Execute(w, d)
}

// Markdown converts model output to HTML. goldmark drops raw HTML and
// dangerous link targets unless configured as unsafe, which it is not here.
func Markdown(md string) (template.HTML, error) {
	var b bytes.Buffer
	gm := goldmark.New(goldmark.WithExtensions(extension.GFM))
	if err := gm.Convert([]byte(md), &b); err != nil {
		return "", fmt.Errorf("render ai review: %w", err)
	}
	return template.HTML(b.String()), nil // #nosec G203 -- goldmark escapes raw HTML without WithUnsafe
}

// Tables decodes a run's command-specific payload into display tables.
func Tables(r *run.Run) []Table {
	if len(r.Data) == 0 {
		return nil
	}
	switch r.Command {
	case packages.Command:
		var d packages.Data
		if json.Unmarshal(r.Data, &d) != nil {
			return nil
		}
		return packageTables(packages.Annotate(d.Inventories, nil, nil, ""), r.FinishedAt)
	case environment.Command:
		var d environment.Data
		if json.Unmarshal(r.Data, &d) != nil {
			return nil
		}
		return environmentTables(d)
	}
	return nil
}

func packageTables(as []packages.Annotated, now time.Time) []Table {
	var out []Table
	for _, a := range as {
		inv := a.Inventory
		var note []string
		if inv.ManagerVersion != "" {
			note = append(note, inv.ManagerVersion)
		}
		if inv.Runtime != nil && inv.Runtime.Version != "" {
			note = append(note, inv.Runtime.Name+" "+inv.Runtime.Version)
		}
		switch {
		case !inv.Available:
			note = append(note, "not installed")
		case inv.Error != "":
			note = append(note, "error: "+inv.Error)
		default:
			note = append(note, fmt.Sprintf("%d package(s)", len(inv.Packages)))
			if c := packages.RegistryNote(a, now); c != "" {
				note = append(note, c)
			}
		}
		t := Table{Title: inv.Manager, Note: strings.Join(note, " · "),
			Columns: []string{"Name", "Version", "Latest", "Released", "Runtime", "Tags", "Description", "Source", "Executables"}}
		for _, it := range a.Items {
			latest, released := packages.LatestCells(it, now)
			desc := ""
			if it.Meta != nil {
				desc = it.Meta.Description
			}
			tags := strings.Join(it.Tags, " ")
			t.Rows = append(t.Rows, []string{it.Name, it.Version, latest, released, it.RuntimeVersion, tags, desc,
				it.Source, strings.Join(it.Executables, " ")})
			t.RowTags = append(t.RowTags, tags)
			class := ""
			if it.Gap != packages.GapUnknown {
				class = "gap-" + string(it.Gap)
			}
			if it.Meta != nil && (it.Meta.Deprecated != "" || it.Meta.Archived) {
				class = strings.TrimSpace(class + " gap-dead")
			}
			t.RowClass = append(t.RowClass, class)
		}
		out = append(out, t)
	}
	return out
}

// tagCounts counts the tags of the tables that carry them, most used first.
func tagCounts(ts []Table) []tagCount {
	n := map[string]int{}
	for _, t := range ts {
		for _, tags := range t.RowTags {
			for _, tag := range strings.Fields(tags) {
				n[tag]++
			}
		}
	}
	out := make([]tagCount, 0, len(n))
	for tag, c := range n {
		out = append(out, tagCount{tag, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

func environmentTables(d environment.Data) []Table {
	shells := Table{Title: "Shell startup", Columns: []string{"Shell", "Mode", "Time", "Status", "Unexpected output"}}
	for _, c := range d.Captures {
		status := fmt.Sprintf("exit %d", c.Code)
		switch {
		case c.Err != "":
			status = c.Err
		case c.TimedOut:
			status = "timed out"
		}
		shells.Rows = append(shells.Rows, []string{c.Shell, c.Mode, c.Duration.Round(10 * time.Millisecond).String(),
			status, strings.Join(c.Output, "\n")})
	}
	failed := map[string]bool{}
	for _, s := range d.Syntax {
		failed[s.Path] = true
	}
	scripts := Table{Title: "Scripts", Note: "analyzed environment: " + d.EnvSource,
		Columns: []string{"Dialect", "Role", "State", "Path"}}
	for _, s := range d.Scripts {
		role := "sourced"
		switch {
		case s.Startup:
			role = "startup"
		case s.Executable:
			role = "executable"
		case s.Function != "":
			role = "function"
		case len(s.LoadedBy) == 0 && len(d.Traced) > 0:
			role = "not loaded"
		}
		state := ""
		if failed[s.Path] {
			state = "syntax error"
		}
		scripts.Rows = append(scripts.Rows, []string{string(s.Dialect), role, state, s.Path})
	}
	return []Table{shells, scripts}
}

// IndexRow is one command on the index page.
type IndexRow struct {
	Command    string
	Latest     *store.RunInfo
	Thresholds config.Thresholds
	Open       map[todo.Priority]int
	// Link is the command's report file, relative to the index; "" when none.
	Link string
}

type indexRow struct {
	IndexRow
	Age       string
	Freshness string
	Findings  string
	Tasks     string
}

// WriteIndex renders the cross-command index.
func WriteIndex(w io.Writer, rows []IndexRow, now time.Time) error {
	out := make([]indexRow, len(rows))
	for i, r := range rows {
		out[i] = indexRow{IndexRow: r, Findings: "-", Tasks: tasks(r.Open)}
		if r.Latest != nil {
			age := now.Sub(r.Latest.FinishedAt)
			out[i].Age = run.HumanAge(age)
			out[i].Freshness = freshness(age, r.Thresholds)
			out[i].Findings = counts(r.Latest.Counts)
		}
	}
	return indexT.Execute(w, struct {
		CSS       template.CSS
		Version   string
		Generated time.Time
		Rows      []indexRow
	}{template.CSS(css), version.Version, now, out}) // #nosec G203 -- embedded stylesheet
}

func counts(c finding.Counts) string {
	if c.Total() == 0 {
		return "none"
	}
	var parts []string
	for _, s := range finding.Severities {
		if n := c[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

func tasks(m map[todo.Priority]int) string {
	var parts []string
	for _, p := range todo.Priorities {
		if n := m[p]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, p))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// FileName is the report file of command inside the report directory.
func FileName(command string) string { return command + ".html" }

// Save writes data via render to path atomically, creating the directory.
func Save(path string, render func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".report-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := render(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
