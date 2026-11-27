package containers

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
	"github.com/njhoffman/audit/internal/run"
)

// KindClean marks cleanup steps; it is files.KindClean, so audit files
// clean --last and the fixes log see container cleanups with the others.
const KindClean = "clean"

// Object kinds a cleanup removes, the first part of a step's ident.
const (
	ObjContainer = "container"
	ObjImage     = "image"
	ObjVolume    = "volume"
)

// CleanOptions select what a cleanup plans.
type CleanOptions struct {
	// StoppedAfter and ScannedAt pick the stopped containers the scan
	// reported: created longer than StoppedAfter before ScannedAt.
	StoppedAfter time.Duration
	ScannedAt    time.Time
	// Volumes adds the unused volumes, left out by default because they
	// hold data.
	Volumes bool
	// Names limit the plan to these container names or IDs, image IDs and
	// volume names; none plans everything.
	Names []string
	// Reported says whether the saved run still reports check for engine
	// (false once the finding is ignored).
	Reported func(check, engine string) bool
}

// CleanPlan plans removing what the saved scan reported. Each step uses
// the engine's plain remove, which refuses a container that runs again or
// an image or volume a container uses, so nothing in use since the scan
// goes.
func CleanPlan(d Data, o CleanOptions) packages.Plan {
	reported := o.Reported
	if reported == nil {
		reported = func(string, string) bool { return true }
	}
	wanted := func(ids ...string) bool {
		if len(o.Names) == 0 {
			return true
		}
		return slices.ContainsFunc(ids, func(id string) bool { return id != "" && slices.Contains(o.Names, id) })
	}
	step := func(engine, obj, id, name, detail string, cmd ...string) packages.Planned {
		return packages.Planned{Kind: KindClean, Package: packages.Package{Manager: engine, Name: obj + " " + name,
			Ident: obj + ":" + id, Version: detail}, Latest: "removed", Command: append([]string{engine}, cmd...)}
	}
	var plan packages.Plan
	for _, e := range d.Engines {
		if e.Error != "" {
			continue
		}
		if reported(CheckStopped, e.Name) && o.StoppedAfter > 0 {
			for _, c := range e.Stopped {
				if c.Created.IsZero() || o.ScannedAt.Sub(c.Created) <= o.StoppedAfter || !wanted(c.ID, c.Name) {
					continue
				}
				plan.Items = append(plan.Items, step(e.Name, ObjContainer, c.ID, c.Name,
					run.HumanAge(o.ScannedAt.Sub(c.Created))+" old", "rm", "--", c.ID))
			}
		}
		if reported(CheckDangling, e.Name) {
			for _, im := range e.Dangling {
				if wanted(im.ID) {
					plan.Items = append(plan.Items, step(e.Name, ObjImage, im.ID, im.ID, im.Size, "rmi", "--", im.ID))
				}
			}
		}
		if o.Volumes && reported(CheckVolumes, e.Name) {
			for _, v := range e.Volumes {
				if wanted(v) {
					plan.Items = append(plan.Items, step(e.Name, ObjVolume, v, v, "", "volume", "rm", "--", v))
				}
			}
		}
	}
	return plan
}

// VerifyClean fails a step whose object the engine still knows.
func VerifyClean(ctx context.Context, env *exec.Env, results []packages.UpdateResult) {
	for i := range results {
		r := &results[i]
		if r.Status != packages.UpdateOK || r.Kind != KindClean {
			continue
		}
		obj, id, ok := strings.Cut(r.ID, ":")
		if !ok || !slices.Contains([]string{ObjContainer, ObjImage, ObjVolume}, obj) {
			continue
		}
		if env.Run(ctx, r.Manager, []string{obj, "inspect", "--", id}, exec.Options{Timeout: timeout}).OK() {
			r.Status, r.Reason = packages.UpdateFailed, fmt.Sprintf("%s %s still there after %s", obj, id, r.Command)
			continue
		}
		r.To = r.Latest
	}
}
