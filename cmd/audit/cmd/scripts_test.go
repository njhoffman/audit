package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptsScanDescribeInfo(t *testing.T) {
	cfgHome, _ := env(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"hello": "#!/bin/sh\n# Says hello.\nprintf hi\n", "mystery": "#!/bin/sh\nprintf x\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil { // #nosec G306 -- test script
			t.Fatal(err)
		}
	}
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "printf"), nil, 0o755); err != nil { // #nosec G306 -- test executable
		t.Fatal(err)
	}
	t.Setenv("PATH", tools)
	answer := claudeJSON(t, map[string]any{"subtype": "success", "result": "", "structured_output": map[string]any{
		"descriptions": []map[string]string{{"path": filepath.Join(bin, "mystery"), "description": "Prints an x."}}}})
	claude, stdin, _ := fakeAI(t, "claude", answer)
	writeConfig(t, cfgHome, "scripts: {roots: ["+bin+"]}\nai: {claude: {command: "+claude+"}}\n")
	r := runArgs(t, "scripts", "-r", "-l")
	if r.e != nil || !strings.Contains(r.out, "Says hello.") || !strings.Contains(r.out, "mystery") {
		t.Fatalf("scan: %v\n%s\n%s", r.e, r.out, r.err)
	}
	r = runArgs(t, "scripts", "describe")
	if r.e != nil || !strings.Contains(r.out, "Described 1 of 1 script(s).") {
		t.Fatalf("describe: %v\n%s\n%s", r.e, r.out, r.err)
	}
	if p := readFile(t, stdin); !strings.Contains(p, "=== "+filepath.Join(bin, "mystery")) || strings.Contains(p, "Says hello") {
		t.Errorf("only undescribed scripts are sent:\n%s", p)
	}
	r = runArgs(t, "scripts", "-f", "an x")
	if !strings.Contains(r.out, "Prints an x.") || strings.Contains(r.out, "hello ") {
		t.Errorf("--find after describe:\n%s", r.out)
	}
	r = runArgs(t, "scripts", "info", "mystery")
	if r.e != nil || !strings.Contains(r.out, "Prints an x.") || !strings.Contains(r.out, "ai") {
		t.Errorf("info: %v\n%s", r.e, r.out)
	}
	if r := runArgs(t, "scripts", "describe"); !strings.Contains(r.out, "Every script has a description.") {
		t.Errorf("nothing left to describe:\n%s", r.out)
	}
}
