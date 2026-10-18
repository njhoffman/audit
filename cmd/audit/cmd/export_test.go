package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njhoffman/audit/internal/export"
)

func readExport(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestExportOnSave(t *testing.T) {
	_, dataHome := env(t)
	dir := filepath.Join(dataHome, "audit", "export")
	if r := runArgs(t, "todo"); r.e != nil {
		t.Fatal(r.e)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a command that saves nothing does not export: %v", err)
	}

	if r := runArgs(t, "todo", "add", "clean", "up", "-p", "high"); r.e != nil {
		t.Fatal(r.e)
	}
	var tasks export.Tasks
	readExport(t, dir, export.TasksFile, &tasks)
	if tasks.SchemaVersion != export.SchemaVersion || len(tasks.Tasks) != 1 || tasks.Tasks[0].Title != "clean up" {
		t.Errorf("tasks.json: %+v", tasks)
	}
	var sum export.Summary
	readExport(t, dir, export.SummaryFile, &sum)
	if len(sum.Commands) == 0 || sum.Commands[0].Freshness != "none" || sum.OpenTasks["high"] != 1 {
		t.Errorf("summary.json: %+v", sum)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if r := runArgs(t, "todo", "-j"); r.e != nil {
		t.Fatal(r.e)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a read-only command must not export: %v", err)
	}
}

func TestExportDisabled(t *testing.T) {
	cfgHome, dataHome := env(t)
	if err := os.WriteFile(filepath.Join(cfgHome, "audit.yaml"), []byte("export:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runArgs(t, "todo", "add", "x"); r.e != nil {
		t.Fatal(r.e)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "audit", "export")); !os.IsNotExist(err) {
		t.Errorf("export.enabled false writes nothing: %v", err)
	}
}

func TestExportCommand(t *testing.T) {
	env(t)
	dir := filepath.Join(t.TempDir(), "dash")
	r := runArgs(t, "export", "-d", dir)
	if r.e != nil || strings.TrimSpace(r.out) != dir {
		t.Fatalf("export: %v %q", r.e, r.out)
	}
	var up export.Updates
	readExport(t, dir, export.UpdatesFile, &up)
	if up.Updates == nil || len(up.Updates) != 0 {
		t.Errorf("updates.json with no updates: %+v", up)
	}
	if r := runArgs(t, "export", "extra"); r.e == nil {
		t.Error("export takes no arguments")
	}
}
