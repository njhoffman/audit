package containers

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestScan(t *testing.T) {
	bin := t.TempDir()
	for _, b := range []string{"docker", "podman"} {
		if err := os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	f := &exec.Fake{}
	f.AddOutput("28.5.1\n", "docker", "info", "--format", "{{.ServerVersion}}")
	f.AddOutput(`["name=apparmor","name=seccomp,profile=builtin"]`+"\n", "docker", "info", "--format", "{{json .SecurityOptions}}")
	f.AddOutput("abc123\tweb\tnginx:1.25\t2026-08-01 10:00:00 -0500 CDT\nfff000\tfresh\talpine\t2026-09-30 10:00:00 +0000 UTC\n", "docker", "ps")
	f.AddOutput("sha256:dead\t120MB\n", "docker", "images")
	f.AddOutput("pgdata\ncache\n", "docker", "volume")
	f.AddOutput(`{"Type":"Images","Size":"1.2GB","Reclaimable":"120MB (10%)"}`+"\n", "docker", "system", "df")
	f.Add([]string{"podman", "info"}, exec.Result{Code: 125, Stderr: "Error: cannot connect to Podman\nmore\n"})
	env := &exec.Env{Vars: map[string]string{"PATH": bin}, Runner: f}
	res, err := Scan(context.Background(), Options{Env: env, StoppedAfter: 30 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range res.Findings {
		got = append(got, x.Check+" "+x.Subject)
	}
	slices.Sort(got)
	want := []string{"containers.dangling_images docker", "containers.error podman", "containers.stopped docker", "containers.unused_volumes docker"}
	if !slices.Equal(got, want) {
		t.Fatalf("findings %v", got)
	}
	for _, x := range res.Findings {
		switch x.Check {
		case CheckStopped:
			if !strings.Contains(x.Message, "1 docker container(s)") || !strings.Contains(x.Details[0], "web (abc123, nginx:1.25") {
				t.Errorf("only the old container: %+v", x)
			}
		case CheckError:
			if x.Message != "podman info: Error: cannot connect to Podman" {
				t.Errorf("error line: %q", x.Message)
			}
		}
	}
	d := res.Data.Engines[0]
	if d.Rootless == nil || *d.Rootless || d.Usage["Images"] != "1.2GB (120MB (10%) reclaimable)" || len(d.Volumes) != 2 {
		t.Errorf("docker data: %+v", d)
	}
	if len(res.Stats) < 6 || res.Stats[1].Note != "rootful" {
		t.Errorf("stats %+v", res.Stats)
	}
}

func TestNoEngines(t *testing.T) {
	res, err := Scan(context.Background(), Options{Env: &exec.Env{Vars: map[string]string{"PATH": t.TempDir()}, Runner: &exec.Fake{}}})
	if err != nil || len(res.Findings) != 0 || len(res.Data.Engines) != 0 || res.Stats[0].Value != "0" {
		t.Errorf("%+v %v", res, err)
	}
}

func TestParseCreated(t *testing.T) {
	if got := parseCreated("2026-08-01 10:00:00.123456 -0500 CDT"); !got.Equal(time.Date(2026, 8, 1, 15, 0, 0, 123456000, time.UTC)) {
		t.Errorf("podman's fractions: %v", got)
	}
	if !parseCreated("3 weeks ago").IsZero() {
		t.Error("garbage")
	}
}
