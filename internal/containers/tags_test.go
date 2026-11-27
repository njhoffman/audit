package containers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/exec"
)

// tagEnv is PATH with bins installed and a fake runner answering for a
// docker with four images: nginx behind its tag, redis current, a locally
// built app and a private image whose lookup fails.
func tagEnv(t *testing.T, bins ...string) (*exec.Env, *exec.Fake) {
	t.Helper()
	dir := t.TempDir()
	for _, b := range bins {
		if err := os.WriteFile(filepath.Join(dir, b), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	f := &exec.Fake{}
	f.AddOutput("nginx\t1.27\taaa111\nredis\t7\tbbb222\nmyapp\tdev\tccc333\n<none>\t<none>\tddd444\nlocalhost/x\tlatest\teee555\nghcr.io/me/private\tv1\tfff666\nnginx\t1.27\taaa111\n",
		"docker", "images", "--format")
	f.AddOutput(`["nginx@sha256:old"]`+"\n", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", "aaa111")
	f.AddOutput(`["docker.io/library/redis@sha256:list7","redis@sha256:amd64"]`+"\n", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", "bbb222")
	f.AddOutput("[]\n", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", "ccc333")
	f.AddOutput(`["ghcr.io/me/private@sha256:p"]`+"\n", "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", "fff666")
	return &exec.Env{Vars: map[string]string{"PATH": dir}, Runner: f}, f
}

func TestCheckTagsWithBuildx(t *testing.T) {
	env, f := tagEnv(t, "docker")
	f.AddOutput(`{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:new0123456789abcdef","size":1}`+"\n",
		"docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", "nginx:1.27")
	f.AddOutput(`{"digest":"sha256:list7"}`+"\n", "docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", "redis:7")
	f.Add([]string{"docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", "ghcr.io/me/private:v1"},
		exec.Result{Code: 1, Stderr: "ERROR: unauthorized\n"})
	tc := checkTags(context.Background(), env, "docker")
	if tc.Tool != "docker buildx" || tc.Checked != 2 || len(tc.Behind) != 1 || tc.Behind[0].Ref != "nginx:1.27" || tc.Behind[0].Remote != "sha256:new0123456789abcdef" {
		t.Fatalf("check %+v", tc)
	}
	if len(tc.Failed) != 1 || !strings.Contains(tc.Failed[0], "ghcr.io/me/private:v1: docker buildx: ERROR: unauthorized") {
		t.Errorf("failed %v", tc.Failed)
	}
	for _, c := range f.Calls {
		if strings.Contains(strings.Join(c, " "), "myapp") || strings.Contains(strings.Join(c, " "), "localhost/") {
			t.Errorf("a local image was looked up: %v", c)
		}
	}

	fs := Analyze([]Engine{{Name: "docker", Tags: &tc}}, 0, now)
	if len(fs) != 1 || fs[0].Check != CheckBehind || !strings.Contains(fs[0].Details[0], "nginx:1.27 (aaa111 here; the registry has sha256:new012345678)") {
		t.Errorf("findings %+v", fs)
	}
	var stat string
	for _, s := range stats([]Engine{{Name: "docker", Tags: &tc}}) {
		if s.Name == "tags checked" {
			stat = s.Value + " | " + s.Note
		}
	}
	if !strings.HasPrefix(stat, "2 | with docker buildx; 1 lookup(s) failed") {
		t.Errorf("stat %q", stat)
	}
}

func TestCheckTagsPrefersSkopeo(t *testing.T) {
	env, f := tagEnv(t, "podman", "skopeo")
	f.AddOutput("nginx\t1.27\taaa111\n", "podman", "images", "--format")
	f.AddOutput(`["nginx@sha256:old"]`, "podman", "image", "inspect", "--format", "{{json .RepoDigests}}", "aaa111")
	f.AddOutput("sha256:old\n", "skopeo", "inspect", "--format", "{{.Digest}}", "docker://nginx:1.27")
	tc := checkTags(context.Background(), env, "podman")
	if tc.Tool != "skopeo" || tc.Checked != 1 || len(tc.Behind) != 0 {
		t.Errorf("current under skopeo: %+v", tc)
	}
}

func TestCheckTagsWithoutATool(t *testing.T) {
	env, _ := tagEnv(t, "podman")
	tc := checkTags(context.Background(), env, "podman")
	if tc.Error == "" || tc.Checked != 0 {
		t.Errorf("podman without skopeo: %+v", tc)
	}
	var stat string
	for _, s := range stats([]Engine{{Name: "podman", Tags: &tc}}) {
		if s.Name == "tags checked" {
			stat = s.Value + " | " + s.Note
		}
	}
	if !strings.HasPrefix(stat, "not checked | needs skopeo") {
		t.Errorf("stat %q", stat)
	}
	for _, s := range stats([]Engine{{Name: "podman", Tags: &tc}}) {
		if s.Name == "images behind their tag" {
			t.Error("no behind count when nothing was checked")
		}
	}
}

func TestScanChecksTagsOnlyWhenAsked(t *testing.T) {
	for _, check := range []bool{false, true} {
		env, f := tagEnv(t, "docker")
		f.AddOutput("28.5.1\n", "docker", "info", "--format", "{{.ServerVersion}}")
		f.AddOutput("", "docker", "ps")
		f.AddOutput("", "docker", "volume")
		f.AddOutput("", "docker", "system", "df")
		res, err := Scan(context.Background(), Options{Env: env, Engines: []string{"docker"}, CheckTags: check, Now: now, StoppedAfter: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Data.Engines[0].Tags != nil; got != check {
			t.Errorf("check_tags %v: tags checked %v", check, got)
		}
	}
}

func TestDigestHelpers(t *testing.T) {
	if short("sha256:0123456789abcdef") != "sha256:0123456789ab" || short("other") != "other" {
		t.Error("short")
	}
	if _, err := digestOrErr("latest"); err == nil {
		t.Error("an answer without a digest is an error")
	}
}
