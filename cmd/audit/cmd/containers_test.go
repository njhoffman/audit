package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/containers"
	"github.com/njhoffman/audit/internal/files"
)

// fakeDocker is a docker stand-in with one old stopped container, one
// dangling image and one unused volume; rm, rmi and volume rm remove them,
// except that the image refuses (in use since the scan).
const fakeDocker = `#!/bin/sh
s="$STATE"
case "$1 $2" in
"info --format") case "$3" in *Server*) echo 28.5.1 ;; *) echo '["name=seccomp"]' ;; esac ;;
"ps -a") [ -e "$s/rm-old1" ] || printf 'old1\tweb\tnginx\t2020-01-01 10:00:00 +0000 UTC\n' ;;
"images --filter") printf 'sha256:dead\t120MB\n' ;;
"volume ls") [ -e "$s/rm-pgdata" ] || echo pgdata ;;
"system df") ;;
"rm --") /usr/bin/touch "$s/rm-$3" ;;
"rmi --") echo "image is being used by running container" >&2; exit 1 ;;
"volume rm") /usr/bin/touch "$s/rm-$4" ;;
"container inspect") [ ! -e "$s/rm-$4" ] && echo '[{}]' || exit 1 ;;
"image inspect") echo '[{}]' ;;
"volume inspect") [ ! -e "$s/rm-$4" ] && echo '[{}]' || exit 1 ;;
*) echo "unexpected: $*" >&2; exit 2 ;;
esac
`

func TestContainersClean(t *testing.T) {
	cfgHome, _ := env(t)
	bin, state := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("STATE", state)
	writeConfig(t, cfgHome, "containers: {engines: [docker]}\n")
	r := runArgs(t, "containers", "clean", "-N")
	if r.e == nil || !strings.Contains(r.e.Error(), "audit containers -r") {
		t.Fatalf("no saved run: %v", r.e)
	}
	if r = runArgs(t, "containers", "-r", "-l"); r.e != nil || !strings.Contains(r.out, "web (old1)") {
		t.Fatalf("scan: %v\n%s\n%s", r.e, r.out, r.err)
	}
	r = runArgs(t, "containers", "clean", "-N")
	if r.e != nil || !strings.Contains(r.out, "docker rm -- old1") || !strings.Contains(r.out, "docker rmi -- sha256:dead") || strings.Contains(r.out, "pgdata") {
		t.Fatalf("plan without volumes: %v\n%s", r.e, r.out)
	}
	r = runArgs(t, "containers", "clean", "-V", "-N", "pgdata")
	if r.e != nil || !strings.Contains(r.out, "docker volume rm -- pgdata") || strings.Contains(r.out, "old1") {
		t.Fatalf("plan by name: %v\n%s", r.e, r.out)
	}
	r = runArgs(t, "containers", "clean", "-V", "-y")
	if r.e == nil || !strings.Contains(r.out, "2 updated, 1 failed") {
		t.Fatalf("clean: %v\n%s\n%s", r.e, r.out, r.err)
	}
	for _, f := range []string{"rm-old1", "rm-pgdata"} {
		if _, err := os.Stat(filepath.Join(state, f)); err != nil {
			t.Errorf("%s not run: %v", f, err)
		}
	}
	if r = runArgs(t, "containers", "clean", "-L"); r.e != nil || !strings.Contains(r.out, "sha256:dead") {
		t.Errorf("--last: %v\n%s", r.e, r.out)
	}
}

func TestContainersCleanKind(t *testing.T) {
	if containers.KindClean != files.KindClean {
		t.Error("container cleanups must share the files and configs cleanup kind")
	}
}
