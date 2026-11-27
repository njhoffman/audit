package containers

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
	"github.com/njhoffman/audit/internal/packages"
)

func cleanData() Data {
	return Data{Engines: []Engine{
		{Name: "docker",
			Stopped: []Container{
				{ID: "abc123", Name: "web", Image: "nginx", Created: now.Add(-60 * 24 * time.Hour)},
				{ID: "fff000", Name: "fresh", Image: "alpine", Created: now.Add(-time.Hour)},
				{ID: "000aaa", Name: "undated", Image: "alpine"},
			},
			Dangling: []Image{{ID: "sha256:dead", Size: "120MB"}},
			Volumes:  []string{"pgdata"}},
		{Name: "podman", Error: "podman info: unreachable", Dangling: []Image{{ID: "never"}}},
	}}
}

func steps(p packages.Plan) []string {
	var out []string
	for _, it := range p.Items {
		out = append(out, it.ID())
	}
	return out
}

func TestCleanPlan(t *testing.T) {
	base := CleanOptions{StoppedAfter: 30 * 24 * time.Hour, ScannedAt: now}
	for _, tc := range []struct {
		name string
		edit func(*CleanOptions)
		want []string
	}{
		{"old containers and dangling images", func(*CleanOptions) {}, []string{"container:abc123", "image:sha256:dead"}},
		{"volumes on request", func(o *CleanOptions) { o.Volumes = true }, []string{"container:abc123", "image:sha256:dead", "volume:pgdata"}},
		{"by name", func(o *CleanOptions) { o.Volumes, o.Names = true, []string{"web", "pgdata"} }, []string{"container:abc123", "volume:pgdata"}},
		{"by id", func(o *CleanOptions) { o.Names = []string{"abc123"} }, []string{"container:abc123"}},
		{"never with stopped_after 0", func(o *CleanOptions) { o.StoppedAfter = 0 }, []string{"image:sha256:dead"}},
		{"ignored findings stay", func(o *CleanOptions) {
			o.Volumes = true
			o.Reported = func(check, _ string) bool { return check == CheckVolumes }
		}, []string{"volume:pgdata"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			if got := steps(CleanPlan(cleanData(), o)); !slices.Equal(got, tc.want) {
				t.Errorf("steps %v, want %v", got, tc.want)
			}
		})
	}
	p := CleanPlan(cleanData(), CleanOptions{StoppedAfter: time.Hour, ScannedAt: now, Volumes: true})
	cmds := map[string][]string{}
	for _, it := range p.Items {
		cmds[it.ID()] = it.Command
		if it.Kind != KindClean || it.Manager != "docker" || it.Latest != "removed" {
			t.Errorf("step %+v", it)
		}
	}
	for id, want := range map[string][]string{
		"container:abc123":  {"docker", "rm", "--", "abc123"},
		"image:sha256:dead": {"docker", "rmi", "--", "sha256:dead"},
		"volume:pgdata":     {"docker", "volume", "rm", "--", "pgdata"},
	} {
		if !slices.Equal(cmds[id], want) {
			t.Errorf("%s runs %v, want %v", id, cmds[id], want)
		}
	}
}

func TestVerifyClean(t *testing.T) {
	f := &exec.Fake{}
	f.AddOutput("[{}]", "docker", "image", "inspect", "--", "sha256:dead")
	env := &exec.Env{Runner: f}
	rs := []packages.UpdateResult{
		{Manager: "docker", ID: "container:abc123", Kind: KindClean, Status: packages.UpdateOK, Latest: "removed", Command: "docker rm -- abc123"},
		{Manager: "docker", ID: "image:sha256:dead", Kind: KindClean, Status: packages.UpdateOK, Latest: "removed", Command: "docker rmi -- sha256:dead"},
		{Manager: "docker", ID: "volume:x", Kind: KindClean, Status: packages.UpdateFailed},
	}
	VerifyClean(context.Background(), env, rs)
	if rs[0].Status != packages.UpdateOK || rs[0].To != "removed" {
		t.Errorf("gone container: %+v", rs[0])
	}
	if rs[1].Status != packages.UpdateFailed || rs[1].Reason != "image sha256:dead still there after docker rmi -- sha256:dead" {
		t.Errorf("image still there: %+v", rs[1])
	}
	if len(f.Calls) != 2 {
		t.Errorf("a failed step is not inspected: %v", f.Calls)
	}
}
