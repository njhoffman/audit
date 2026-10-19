package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/exec"
)

func TestParseSS(t *testing.T) {
	ls := ParseSS(`tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 128 [::]:22 [::]:*
tcp LISTEN 0 50 *:9999 *:* users:(("stash",pid=1,fd=3))
tcp ESTAB 0 0 10.0.0.2:5555 1.2.3.4:443
udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:* users:(("chrome",pid=2,fd=4))
udp UNCONN 0 0 0.0.0.0:111 0.0.0.0:*
tcp LISTEN 0 10 [::1]:5432 [::]:*
tcp LISTEN 0 10 [fe80::1%eth0]:7000 [::]:*
`)
	var got []string
	for _, l := range ls {
		got = append(got, l.Proto+"/"+l.Addr+"/"+l.Process)
	}
	if strings.Join(got, " ") != "tcp/0.0.0.0/ tcp/*/stash udp/0.0.0.0/" {
		t.Errorf("listeners: %v", got)
	}
}

func TestScan(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ssh, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		body string
		mode os.FileMode
	}{
		"id_open":         {"-----BEGIN OPENSSH PRIVATE KEY-----\n", 0o644},
		"id_ok":           {"-----BEGIN OPENSSH PRIVATE KEY-----\n", 0o600},
		"id_ok.pub":       {"ssh-ed25519 AAAA\n", 0o644},
		"authorized_keys": {"ssh-ed25519 AAAA\n", 0o666},
	} {
		p := filepath.Join(ssh, name)
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	keygen := filepath.Join(bin, "ssh-keygen")
	if err := os.WriteFile(keygen, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	loose := filepath.Join(bin, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	fake := &exec.Fake{}
	fake.AddOutput("inactive\ninactive\ninactive\n", "systemctl", "is-active")
	fake.AddOutput("tcp LISTEN 0 10 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=1,fd=6))\n", "ss")
	fake.AddOutput("NTP=yes\nNTPSynchronized=no\n", "timedatectl")
	fake.Add([]string{"ssh-keygen", "-y", "-P", "", "-f", filepath.Join(ssh, "id_ok")}, exec.Result{Code: 1, Stderr: "incorrect passphrase"})
	fake.AddOutput("ssh-ed25519 AAAA", "ssh-keygen", "-y", "-P", "", "-f", filepath.Join(ssh, "id_open"))
	env := &exec.Env{Vars: map[string]string{"PATH": bin}, Runner: fake}
	res, err := Scan(context.Background(), Options{Env: env, Home: home, Path: []string{bin, shared, bin}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	var details []string
	for _, f := range res.Findings {
		got[f.Check+":"+string(f.Severity)]++
		details = append(details, f.Detail)
	}
	want := map[string]int{"firewall:notice": 1, "exposed_port:warning": 1, "ssh_perms:warning": 2, "ssh_perms:error": 1,
		"ssh_passphrase:notice": 1, "writable_path:error": 1, "writable_path:warning": 1, "time_sync:warning": 1}
	if len(got) != len(want) {
		t.Errorf("findings %v\n%s", got, strings.Join(details, "\n"))
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s: %d, want %d\n%s", k, got[k], n, strings.Join(details, "\n"))
		}
	}
}
