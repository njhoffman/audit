package programs

import (
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/scan"
)

func ptrBool(b bool) *bool { return &b }

func TestDockerRules_TCPHostNoTLS(t *testing.T) {
	d := dockerDaemon{
		Hosts: []string{"unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"},
	}
	out := dockerRules(d, nil)
	if len(out) != 1 || out[0].Severity != scan.SeverityCritical {
		t.Errorf("tcp host without tlsverify should be critical, got %+v", out)
	}
}

func TestDockerRules_TCPHostWithTLSVerify_Quiet(t *testing.T) {
	d := dockerDaemon{
		Hosts:     []string{"tcp://0.0.0.0:2376"},
		TLSVerify: ptrBool(true),
		TLS:       ptrBool(true),
	}
	out := dockerRules(d, nil)
	for _, f := range out {
		if strings.Contains(f.Subject, "tcp host") {
			t.Errorf("tlsverify=true should be quiet, got %+v", f)
		}
	}
}

func TestDockerRules_UnixOnly_Quiet(t *testing.T) {
	d := dockerDaemon{Hosts: []string{"unix:///var/run/docker.sock"}}
	out := dockerRules(d, nil)
	for _, f := range out {
		if strings.Contains(f.Subject, "tcp host") {
			t.Errorf("unix-only should not fire tcp rule, got %+v", f)
		}
	}
}

func TestDockerRules_LiveRestoreFalse(t *testing.T) {
	d := dockerDaemon{LiveRestore: ptrBool(false)}
	out := dockerRules(d, nil)
	if len(out) != 1 || !strings.Contains(out[0].Subject, "live-restore") {
		t.Errorf("live-restore=false should fire, got %+v", out)
	}
}

func TestDockerRules_NoNewPrivilegesFalse(t *testing.T) {
	d := dockerDaemon{NoNewPrivileges: ptrBool(false)}
	out := dockerRules(d, nil)
	if len(out) != 1 || !strings.Contains(out[0].Subject, "no-new-privileges") {
		t.Errorf("no-new-privileges=false should fire, got %+v", out)
	}
}

func TestDockerRules_JSONFileWithoutMaxSize(t *testing.T) {
	d := dockerDaemon{LogDriver: "json-file"}
	out := dockerRules(d, nil)
	var found bool
	for _, f := range out {
		if strings.Contains(f.Subject, "max-size") {
			found = true
		}
	}
	if !found {
		t.Errorf("json-file without max-size should fire, got %+v", out)
	}
}

func TestDockerRules_JSONFileWithMaxSize_Quiet(t *testing.T) {
	d := dockerDaemon{
		LogDriver: "json-file",
		LogOpts:   []byte(`{"max-size":"10m","max-file":"3"}`),
	}
	out := dockerRules(d, nil)
	for _, f := range out {
		if strings.Contains(f.Subject, "max-size") {
			t.Errorf("max-size set should be quiet, got %+v", f)
		}
	}
}

func TestDockerRules_Empty(t *testing.T) {
	if out := dockerRules(dockerDaemon{}, nil); len(out) != 0 {
		t.Errorf("empty daemon should be quiet, got %+v", out)
	}
}
