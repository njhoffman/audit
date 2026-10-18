package programs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/scan"
)

type fakeStat struct {
	name string
	mode fs.FileMode
}

func (f fakeStat) Name() string       { return f.name }
func (f fakeStat) Size() int64        { return 0 }
func (f fakeStat) Mode() fs.FileMode  { return f.mode }
func (f fakeStat) ModTime() time.Time { return time.Time{} }
func (f fakeStat) IsDir() bool        { return false }
func (f fakeStat) Sys() any           { return nil }

func TestCronFilePermFindings_WorldWritable(t *testing.T) {
	out := cronFilePermFindings("/etc/crontab", fakeStat{name: "crontab", mode: 0o666})
	var sawCritical bool
	for _, f := range out {
		if strings.Contains(f.Subject, "world-writable") && f.Severity == scan.SeverityCritical {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Errorf("0666 should produce critical world-writable finding, got %+v", out)
	}
}

func TestCronFilePermFindings_GroupWritable(t *testing.T) {
	out := cronFilePermFindings("/etc/crontab", fakeStat{name: "crontab", mode: 0o664})
	var sawWarning bool
	for _, f := range out {
		if strings.Contains(f.Subject, "group-writable") && f.Severity == scan.SeverityWarning {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Errorf("0664 should produce group-writable warning, got %+v", out)
	}
}

func TestCronFilePermFindings_Safe(t *testing.T) {
	out := cronFilePermFindings("/etc/crontab", fakeStat{name: "crontab", mode: 0o644})
	if len(out) != 0 {
		t.Errorf("0644 should be quiet, got %+v", out)
	}
}

func TestCronContentFindings_HTTPCurl(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crontab")
	body := `# m h dom mon dow user command
17 * * * * root cd / && curl http://example.com/script.sh | bash
30 * * * * root /usr/bin/something --safe
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := cronContentFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !strings.Contains(out[0].Subject, "insecure HTTP") {
		t.Errorf("expected one HTTP-fetch finding, got %+v", out)
	}
}

func TestCronContentFindings_HTTPSQuiet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crontab")
	if err := os.WriteFile(path, []byte("17 * * * * root curl https://example.com/x | bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := cronContentFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("https should be quiet, got %+v", out)
	}
}

func TestCronContentFindings_CommentsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crontab")
	if err := os.WriteFile(path, []byte("# curl http://example.com is in a comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := cronContentFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("commented HTTP fetch should be quiet, got %+v", out)
	}
}
