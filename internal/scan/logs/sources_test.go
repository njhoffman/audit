package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLogs points every log path into a temp dir and puts fake journalctl
// and dmesg on PATH. journalctl prints $FAKE_JOURNAL (JSON lines) or, with
// FAKE_JOURNAL_FAIL set, fails with stderr; dmesg prints $FAKE_DMESG or,
// with FAKE_DMESG_FAIL set, exits 1 as a restricted ring buffer does.
func fakeLogs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, p := range []*string{&authLogPath, &bootLogPath, &dmesgFile, &kernLogPath, &miscRoot} {
		old := *p
		t.Cleanup(func() { *p = old })
	}
	authLogPath, bootLogPath = filepath.Join(dir, "auth.log"), filepath.Join(dir, "boot.log")
	dmesgFile, kernLogPath = filepath.Join(dir, "dmesg"), filepath.Join(dir, "kern.log")
	miscRoot = filepath.Join(dir, "var-log")
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil { // #nosec G306 -- test executable
			t.Fatal(err)
		}
	}
	write("journalctl", "#!/bin/sh\necho \"$*\" >> \"$FAKE_ARGS\"\n"+
		"if [ -n \"$FAKE_JOURNAL_FAIL\" ]; then echo 'Failed to open journal' >&2; exit 1; fi\nprintf '%s\\n' \"$FAKE_JOURNAL\"\n")
	write("dmesg", "#!/bin/sh\nif [ -n \"$FAKE_DMESG_FAIL\" ]; then echo 'Operation not permitted' >&2; exit 1; fi\nprintf '%s\\n' \"$FAKE_DMESG\"\n")
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("FAKE_ARGS", filepath.Join(dir, "args"))
	t.Setenv("FAKE_JOURNAL", `{"__REALTIME_TIMESTAMP":"1714200000000000","_SYSTEMD_UNIT":"k.service","MESSAGE":"Out of memory: Killed process 42 (java)"}`)
	t.Setenv("FAKE_DMESG", "[Sun Apr 27 03:31:00 2026] kernel: segfault at 0 ip 0 sp 0 error 4 in libc.so")
	return dir
}

func put(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checks(sr SourceResult) map[string]bool {
	out := map[string]bool{}
	for _, f := range sr.Findings {
		out[f.Check] = true
	}
	return out
}

func TestFileSourcesPreferTheirFile(t *testing.T) {
	fakeLogs(t)
	put(t, authLogPath, "Apr 27 03:31:00 host sshd[1]: Failed password for root from 10.0.0.1\n\n")
	put(t, bootLogPath, "  starting\n\n[FAILED] Failed to start x.service\n")
	put(t, kernLogPath, "Apr 27 03:31:00 host kernel: Out of memory: Killed process 7 (a)\n")
	o := Options{MaxLines: 100, TopBuckets: 5}
	for _, tc := range []struct {
		fn    scanner
		path  string
		lines int
	}{{scanAuth, authLogPath, 1}, {scanBoot, bootLogPath, 2}, {scanKern, kernLogPath, 1}} {
		sr, err := tc.fn(context.Background(), o)
		if err != nil || sr.UsedFallback != tc.path || sr.LinesRead != tc.lines || len(sr.Buckets) == 0 {
			t.Errorf("%s: %+v %v", tc.path, sr, err)
		}
	}
	if sr, _ := scanKern(context.Background(), o); !checks(sr)["oom_kill"] && len(sr.Findings) == 0 {
		t.Errorf("kern.log rules apply: %+v", sr.Findings)
	}
	put(t, bootLogPath, "a\nb\nc\n")
	if sr, _ := scanBoot(context.Background(), Options{MaxLines: 2, TopBuckets: 5}); sr.LinesRead != 2 {
		t.Errorf("MaxLines caps boot.log: %d", sr.LinesRead)
	}
}

func TestFileSourcesFallBackToJournal(t *testing.T) {
	dir := fakeLogs(t)
	put(t, authLogPath, "") // empty, like missing, falls back
	o := Options{MaxLines: 100, TopBuckets: 5}
	for _, tc := range []struct {
		fn       scanner
		fallback string
		args     string
	}{
		{scanAuth, "journalctl SYSLOG_FACILITY=4 + 10", "SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 -p info --no-pager --output=json"},
		{scanBoot, "journalctl -b -p err", "-b -p err --no-pager --output=json"},
		{scanKern, "journalctl -k", "-k --no-pager --output=json"},
	} {
		_ = os.Remove(filepath.Join(dir, "args"))
		sr, err := tc.fn(context.Background(), o)
		if err != nil || sr.UsedFallback != tc.fallback || sr.LinesRead != 1 || len(sr.Findings) == 0 {
			t.Errorf("%s: %+v %v", tc.fallback, sr, err)
		}
		if args, _ := os.ReadFile(filepath.Join(dir, "args")); strings.TrimSpace(string(args)) != tc.args {
			t.Errorf("%s ran journalctl %q", tc.fallback, args)
		}
	}
	t.Setenv("FAKE_JOURNAL_FAIL", "1")
	for _, fn := range []scanner{scanAuth, scanBoot, scanKern, scanJournal} {
		if _, err := fn(context.Background(), o); err == nil || !strings.Contains(err.Error(), "Failed to open journal") {
			t.Errorf("journalctl's stderr is in the error: %v", err)
		}
	}
	t.Setenv("PATH", t.TempDir())
	for _, fn := range []scanner{scanAuth, scanBoot, scanKern, scanJournal} {
		if _, err := fn(context.Background(), o); err == nil || !strings.Contains(err.Error(), "journalctl not found") {
			t.Errorf("no journalctl: %v", err)
		}
	}
}

func TestScanJournalPassesArgs(t *testing.T) {
	dir := fakeLogs(t)
	sr, err := scanJournal(context.Background(), Options{JournalArgs: "-p 4  -b", MaxLines: 10, TopBuckets: 5})
	if err != nil || sr.LinesRead != 1 || len(sr.Findings) == 0 {
		t.Fatalf("journal: %+v %v", sr, err)
	}
	if args, _ := os.ReadFile(filepath.Join(dir, "args")); strings.TrimSpace(string(args)) != "-p 4 -b --output=json" {
		t.Errorf("the user's flags, then a forced --output=json: %q", args)
	}
}

func TestScanDmesgFallsBackToFile(t *testing.T) {
	fakeLogs(t)
	o := Options{MaxLines: 10, TopBuckets: 5}
	sr, err := scanDmesg(context.Background(), o)
	if err != nil || sr.UsedFallback != "" || sr.LinesRead != 1 || len(sr.Findings) == 0 {
		t.Fatalf("ring buffer: %+v %v", sr, err)
	}
	t.Setenv("FAKE_DMESG_FAIL", "1")
	if sr, err := scanDmesg(context.Background(), o); err != nil || sr.LinesRead != 0 || sr.UsedFallback != "" {
		t.Errorf("restricted, no file: nothing read and no error: %+v %v", sr, err)
	}
	put(t, dmesgFile, "[    4.212960] usb 1-1: new device\n[    5.0] kernel: segfault at 0 ip 0\n")
	if sr, err := scanDmesg(context.Background(), o); err != nil || sr.UsedFallback != dmesgFile || sr.LinesRead != 2 {
		t.Errorf("restricted: the file is read: %+v %v", sr, err)
	}
}

func TestScanMiscWalksVarLog(t *testing.T) {
	fakeLogs(t)
	put(t, filepath.Join(miscRoot, "app.log"), "segfault at 0 ip 0 sp 0 in x\nok\n")
	put(t, filepath.Join(miscRoot, "app.log.1"), "rotated\n")
	put(t, filepath.Join(miscRoot, "old.gz"), "binary")
	put(t, filepath.Join(miscRoot, "auth.log"), "covered elsewhere\n")
	put(t, filepath.Join(miscRoot, "journal", "x"), "binary journal\n")
	sr, err := scanMisc(context.Background(), Options{MaxLines: 100, TopBuckets: 5})
	if err != nil || sr.LinesRead != 2 || len(sr.Findings) == 0 {
		t.Fatalf("misc: %+v %v", sr, err)
	}
	if !strings.Contains(sr.UsedFallback, "read=1") || !strings.Contains(sr.UsedFallback, "skipped=3") {
		t.Errorf("walk summary: %q", sr.UsedFallback)
	}
}

func TestScanRunsSourcesAndKeepsErrors(t *testing.T) {
	fakeLogs(t)
	t.Setenv("FAKE_DMESG_FAIL", "1")
	put(t, kernLogPath, "Apr 27 03:31:00 host kernel: kernel panic - not syncing\n")
	r, err := Scan(context.Background(), Options{Sources: []Source{SourceKern, SourceJournal, "nope"}})
	if err != nil {
		t.Fatal(err)
	}
	per := r.Summary["per_source"].([]SourceResult)
	if len(per) != 3 || per[2].Source != "nope" || !per[2].NotRunYet || r.Summary["sources_not_run_yet"].([]string)[0] != "nope" {
		t.Fatalf("an unknown source is listed as not run: %+v", per)
	}
	if r.Summary["total_lines_read"] != per[0].LinesRead+per[1].LinesRead {
		t.Errorf("lines read add up: %v", r.Summary["total_lines_read"])
	}
	if len(r.Findings) < 2 || severityRank(r.Findings[0].Severity) < severityRank(r.Findings[len(r.Findings)-1].Severity) {
		t.Errorf("findings from every source, most severe first: %+v", r.Findings)
	}
	t.Setenv("FAKE_JOURNAL_FAIL", "1")
	r, err = Scan(context.Background(), Options{Sources: []Source{SourceJournal}})
	if err != nil || r.Summary["errors"].(map[string]string)["journal"] == "" {
		t.Errorf("a failing source keeps its error in the result, not the call: %+v %v", r.Summary, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, DefaultOptions()); err == nil {
		t.Error("a canceled scan stops")
	}
}
