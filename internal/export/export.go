// Package export writes JSON snapshots of the saved results to a directory
// for other programs, such as a desktop dashboard, to read without opening
// the database. The files are a documented contract (man audit, EXPORT
// FILES): within one SchemaVersion fields are only added, never renamed or
// removed.
package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/njhoffman/audit/internal/config"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
	"github.com/njhoffman/audit/internal/todo"
)

// SchemaVersion changes only when a field is renamed or removed.
const SchemaVersion = 1

// File names in the export directory, besides one <command>.json per
// scanning command.
const (
	SummaryFile = "summary.json"
	TasksFile   = "tasks.json"
	UpdatesFile = "updates.json"
)

// Header starts every file.
type Header struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Host          string    `json:"host"`
}

// Summary is summary.json: one row per command plus the task and update
// totals, enough for a status widget.
type Summary struct {
	Header
	Commands   []Command             `json:"commands"`
	OpenTasks  map[todo.Priority]int `json:"open_tasks"`
	LastUpdate *UpdateSummary        `json:"last_update,omitempty"`
}

// Command is one scanning command's state in the summary.
type Command struct {
	Command string `json:"command"`
	// File is the command's own export file, "" when it never ran.
	File string `json:"file,omitempty"`
	// Freshness grades the last run at GeneratedAt: fresh, stale, old or
	// none. Readers that show it later can regrade it from the thresholds.
	Freshness         string                `json:"freshness"`
	StaleAfterSeconds int64                 `json:"stale_after_seconds"`
	OldAfterSeconds   int64                 `json:"old_after_seconds"`
	LastRun           *RunSummary           `json:"last_run,omitempty"`
	OpenTasks         map[todo.Priority]int `json:"open_tasks"`
}

// RunSummary is a run without its findings.
type RunSummary struct {
	ID         int64          `json:"id"`
	Scope      string         `json:"scope,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Findings   finding.Counts `json:"findings"`
	Ignored    int            `json:"ignored"`
	Errors     int            `json:"errors"`
}

// UpdateSummary is the last package update's counts.
type UpdateSummary struct {
	ID         int64     `json:"id"`
	FinishedAt time.Time `json:"finished_at"`
	Updated    int       `json:"updated"`
	Failed     int       `json:"failed"`
	Skipped    int       `json:"skipped"`
}

// RunFile is <command>.json: the latest full run with its findings, without
// the scanner's raw payload, plus the annotated inventory and the runtimes
// for packages.
type RunFile struct {
	Header
	Run      *run.Run                 `json:"run"`
	Packages any                      `json:"packages,omitempty"`
	Runtimes []packages.RuntimeStatus `json:"runtimes,omitempty"`
	// Repos is the annotated repo list, in repos.json.
	Repos any `json:"repos,omitempty"`
	// Files is the files run's sizes and candidates, in files.json.
	Files any `json:"files,omitempty"`
}

// Tasks is tasks.json: every task, closed ones included.
type Tasks struct {
	Header
	Tasks []todo.Todo `json:"tasks"`
}

// Updates is updates.json: the saved package updates, newest first, without
// command output.
type Updates struct {
	Header
	Updates []packages.Update `json:"updates"`
}

// Input is what a snapshot is built from.
type Input struct {
	Host string
	Now  time.Time
	// Commands lists the scanning commands in display order.
	Commands []string
	// Runs holds each command's latest full run; missing means never run.
	Runs       map[string]*run.Run
	Thresholds map[string]config.Thresholds
	Todos      []todo.Todo
	Updates    []packages.Update
	// Packages is the annotated inventory added to packages.json.
	Packages any
	// Runtimes are the runtime statuses added to packages.json.
	Runtimes []packages.RuntimeStatus
	// Repos is the annotated repo list added to repos.json.
	Repos any
	// Files is the files data added to files.json.
	Files any
}

// Build turns in into the export files, by file name.
func Build(in Input) map[string]any {
	h := Header{SchemaVersion: SchemaVersion, GeneratedAt: in.Now.UTC(), Host: in.Host}
	files := map[string]any{}
	byCmd := map[string][]todo.Todo{}
	for _, t := range in.Todos {
		byCmd[t.Command] = append(byCmd[t.Command], t)
	}
	sum := Summary{Header: h, Commands: []Command{}, OpenTasks: openCounts(in.Todos)}
	for _, c := range in.Commands {
		th := in.Thresholds[c]
		row := Command{Command: c, Freshness: "none", StaleAfterSeconds: int64(th.Warn.Seconds()),
			OldAfterSeconds: int64(th.Old.Seconds()), OpenTasks: openCounts(byCmd[c])}
		if r := in.Runs[c]; r != nil {
			row.File = c + ".json"
			row.Freshness = freshness(run.FreshnessOf(r.Age(in.Now), th.Warn, th.Old))
			row.LastRun = &RunSummary{ID: r.ID, Scope: r.Scope, StartedAt: r.StartedAt.UTC(), FinishedAt: r.FinishedAt.UTC(),
				Findings: r.Counts(), Ignored: r.Ignored, Errors: len(r.Errors)}
			rf := RunFile{Header: h, Run: withoutData(r)}
			if c == packages.Command {
				rf.Packages, rf.Runtimes = in.Packages, in.Runtimes
			}
			switch c {
			case "repos":
				rf.Repos = in.Repos
			case "files":
				rf.Files = in.Files
			}
			files[row.File] = rf
		}
		sum.Commands = append(sum.Commands, row)
	}
	updates := make([]packages.Update, len(in.Updates))
	for i, u := range in.Updates {
		u.Items = append([]packages.UpdateResult(nil), u.Items...)
		for j := range u.Items {
			u.Items[j].Output = ""
		}
		updates[i] = u
	}
	if len(updates) > 0 {
		u := updates[0]
		up, failed, skipped := u.Counts()
		sum.LastUpdate = &UpdateSummary{ID: u.ID, FinishedAt: u.FinishedAt.UTC(), Updated: up, Failed: failed, Skipped: skipped}
	}
	todos := in.Todos
	if todos == nil {
		todos = []todo.Todo{}
	}
	files[SummaryFile] = sum
	files[TasksFile] = Tasks{Header: h, Tasks: todos}
	files[UpdatesFile] = Updates{Header: h, Updates: updates}
	return files
}

func withoutData(r *run.Run) *run.Run {
	c := *r
	c.Data = nil
	return &c
}

func openCounts(ts []todo.Todo) map[todo.Priority]int {
	m := map[todo.Priority]int{todo.High: 0, todo.Medium: 0, todo.Low: 0, todo.Suggestion: 0}
	for _, t := range ts {
		if !t.Status.Closed() {
			m[t.Priority]++
		}
	}
	return m
}

func freshness(f run.Freshness) string {
	switch f {
	case run.Stale:
		return "stale"
	case run.Old:
		return "old"
	}
	return "fresh"
}

// Write writes files into dir, each through a temporary file renamed into
// place, so a reader never sees a partial file.
func Write(dir string, files map[string]any) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create export dir: %w", err)
	}
	for name, v := range files {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		tmp, err := os.CreateTemp(dir, "."+name+".*")
		if err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		_, werr := tmp.Write(append(b, '\n'))
		cerr := tmp.Close()
		if werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(tmp.Name(), 0o644) // #nosec G302 -- meant to be read by other programs
		}
		if werr == nil {
			werr = os.Rename(tmp.Name(), filepath.Join(dir, name))
		}
		if werr != nil {
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("write %s: %w", name, werr)
		}
	}
	return nil
}
