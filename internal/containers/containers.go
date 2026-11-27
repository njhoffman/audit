// Package containers checks docker and podman: dangling images, volumes no
// container uses, containers stopped long ago, and what the engine could
// reclaim. Only listing commands run; nothing is removed.
package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/run"
)

// Command is the audit command name.
const Command = "containers"

// Engines are the container engines audit knows.
var Engines = []string{"docker", "podman"}

// Options configure a scan.
type Options struct {
	Env     *exec.Env
	Engines []string
	// StoppedAfter is how long a stopped container may sit before it is
	// reported.
	StoppedAfter time.Duration
	Now          time.Time
}

// Container is one stopped container.
type Container struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Image   string    `json:"image"`
	Created time.Time `json:"created,omitzero"`
}

// Image is one dangling image.
type Image struct {
	ID   string `json:"id"`
	Size string `json:"size"`
}

// Engine is what one engine reported.
type Engine struct {
	Name     string      `json:"name"`
	Version  string      `json:"version,omitempty"`
	Rootless *bool       `json:"rootless,omitempty"`
	Stopped  []Container `json:"stopped,omitempty"`
	Dangling []Image     `json:"dangling,omitempty"`
	Volumes  []string    `json:"unused_volumes,omitempty"`
	// Usage is system df: type to "size (reclaimable)".
	Usage map[string]string `json:"usage,omitempty"`
	Error string            `json:"error,omitempty"`
}

// Data is what a containers run stores.
type Data struct {
	Engines []Engine `json:"engines"`
}

// Result is a finished scan.
type Result struct {
	Findings []finding.Finding
	Stats    []run.Stat
	Data     Data
}

const timeout = 30 * time.Second

// Scan asks each installed engine for its objects.
func Scan(ctx context.Context, o Options) (*Result, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	engines := o.Engines
	if len(engines) == 0 {
		engines = Engines
	}
	var es []Engine
	for _, name := range engines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if o.Env.Which(name) == "" {
			continue
		}
		es = append(es, collect(ctx, o.Env, name))
	}
	res := &Result{Data: Data{Engines: es}}
	res.Findings = Analyze(es, o.StoppedAfter, now)
	res.Stats = stats(es)
	return res, nil
}

func run1(ctx context.Context, env *exec.Env, name string, args ...string) (string, error) {
	r := env.Run(ctx, name, args, exec.Options{Timeout: timeout})
	if !r.OK() {
		msg := strings.TrimSpace(r.Stderr)
		if i := strings.IndexByte(msg, '\n'); i > 0 {
			msg = msg[:i]
		}
		return "", fmt.Errorf("%s %s: %s", name, args[0], msg)
	}
	return r.Stdout, nil
}

func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func collect(ctx context.Context, env *exec.Env, name string) Engine {
	e := Engine{Name: name}
	// The version answers only when the engine is reachable (a docker
	// socket this user may not open fails here first).
	vfmt := "{{.ServerVersion}}"
	if name == "podman" {
		vfmt = "{{.Version.Version}}"
	}
	v, err := run1(ctx, env, name, "info", "--format", vfmt)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	e.Version = strings.TrimSpace(v)
	if name == "podman" {
		if out, err := run1(ctx, env, name, "info", "--format", "{{.Host.Security.Rootless}}"); err == nil {
			r := strings.TrimSpace(out) == "true"
			e.Rootless = &r
		}
	} else if out, err := run1(ctx, env, name, "info", "--format", "{{json .SecurityOptions}}"); err == nil {
		r := strings.Contains(out, "rootless")
		e.Rootless = &r
	}
	if out, err := run1(ctx, env, name, "ps", "-a", "--filter", "status=exited", "--filter", "status=created",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.CreatedAt}}"); err == nil {
		for _, l := range lines(out) {
			f := strings.Split(l, "\t")
			if len(f) < 4 {
				continue
			}
			e.Stopped = append(e.Stopped, Container{ID: f[0], Name: f[1], Image: f[2], Created: parseCreated(f[3])})
		}
	} else {
		e.Error = err.Error()
	}
	if out, err := run1(ctx, env, name, "images", "--filter", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"); err == nil {
		for _, l := range lines(out) {
			id, size, _ := strings.Cut(l, "\t")
			e.Dangling = append(e.Dangling, Image{ID: id, Size: size})
		}
	}
	if out, err := run1(ctx, env, name, "volume", "ls", "--filter", "dangling=true", "--format", "{{.Name}}"); err == nil {
		e.Volumes = lines(out)
	}
	if out, err := run1(ctx, env, name, "system", "df", "--format", "{{json .}}"); err == nil {
		e.Usage = map[string]string{}
		for _, l := range lines(out) {
			var row struct{ Type, Size, Reclaimable string }
			if json.Unmarshal([]byte(l), &row) == nil && row.Type != "" {
				e.Usage[row.Type] = row.Size + " (" + row.Reclaimable + " reclaimable)"
			}
		}
	}
	return e
}

// parseCreated reads the engines' CreatedAt: "2026-05-01 10:00:00 -0500 CDT",
// podman with fractions of a second.
func parseCreated(s string) time.Time {
	f := strings.Fields(s)
	if len(f) < 3 {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05.999999999 -0700"} {
		if t, err := time.Parse(layout, f[0]+" "+f[1]+" "+f[2]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Checks.
const (
	CheckStopped  = "containers.stopped"
	CheckDangling = "containers.dangling_images"
	CheckVolumes  = "containers.unused_volumes"
	CheckError    = "containers.error"
)

// Analyze checks what the engines reported.
func Analyze(es []Engine, stoppedAfter time.Duration, now time.Time) []finding.Finding {
	var fs []finding.Finding
	add := func(check, subject string, sev finding.Severity, msg, hint string, details []string) {
		fs = append(fs, finding.Finding{Command: Command, Check: check, Subject: subject, Kind: finding.Issue, Severity: sev,
			Message: msg, Hint: hint, Details: details})
	}
	for _, e := range es {
		if e.Error != "" {
			add(CheckError, e.Name, finding.Notice, e.Error,
				"Start the engine, or check that you may use it (for docker, membership of the docker group).", nil)
			continue
		}
		var old []string
		for _, c := range e.Stopped {
			if stoppedAfter > 0 && !c.Created.IsZero() && now.Sub(c.Created) > stoppedAfter {
				old = append(old, fmt.Sprintf("%s (%s, %s, created %s ago)", c.Name, c.ID, c.Image, run.HumanAge(now.Sub(c.Created))))
			}
		}
		if len(old) > 0 {
			add(CheckStopped, e.Name, finding.Info, fmt.Sprintf("%d %s container(s) stopped and created over %s ago", len(old), e.Name, run.HumanAge(stoppedAfter)),
				e.Name+" container prune removes every stopped container; "+e.Name+" rm NAME one.", old)
		}
		if len(e.Dangling) > 0 {
			var d []string
			for _, im := range e.Dangling {
				d = append(d, im.ID+" "+im.Size)
			}
			add(CheckDangling, e.Name, finding.Info, fmt.Sprintf("%d dangling %s image(s) (untagged layers nothing uses)", len(e.Dangling), e.Name),
				e.Name+" image prune removes them.", d)
		}
		if len(e.Volumes) > 0 {
			add(CheckVolumes, e.Name, finding.Notice, fmt.Sprintf("%d %s volume(s) no container uses", len(e.Volumes), e.Name),
				"Check they hold nothing you need, then "+e.Name+" volume prune (or "+e.Name+" volume rm NAME).", e.Volumes)
		}
	}
	finding.Sort(fs)
	return fs
}

func stats(es []Engine) []run.Stat {
	out := []run.Stat{{Name: "engines", Value: fmt.Sprint(len(es))}}
	for _, e := range es {
		g := e.Name
		if e.Error != "" {
			out = append(out, run.Stat{Group: g, Name: "state", Value: "unreachable", Note: e.Error})
			continue
		}
		st := run.Stat{Group: g, Name: "version", Value: e.Version}
		if e.Rootless != nil {
			st.Note = map[bool]string{true: "rootless", false: "rootful"}[*e.Rootless]
		}
		out = append(out, st,
			run.Stat{Group: g, Name: "stopped containers", Value: fmt.Sprint(len(e.Stopped))},
			run.Stat{Group: g, Name: "dangling images", Value: fmt.Sprint(len(e.Dangling))},
			run.Stat{Group: g, Name: "unused volumes", Value: fmt.Sprint(len(e.Volumes))})
		for _, t := range []string{"Images", "Containers", "Local Volumes", "Build Cache"} {
			if u, ok := e.Usage[t]; ok {
				out = append(out, run.Stat{Group: g, Name: strings.ToLower(t), Value: u})
			}
		}
	}
	return out
}
