package history

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestRecordsTileTheFile checks that every record's byte range starts where
// the last one ended and the last one ends at EOF, so keeping every record
// rebuilds the file exactly.
func TestRecordsTileTheFile(t *testing.T) {
	for _, tc := range []struct{ name, format, body string }{
		{"zsh", "zsh", ": 1:0;echo one\\\necho two\n: 2:0;ls\n\n: 3:0;pwd"},
		{"bash timed", "bash", "#100\necho one\necho two\n#200\n\nls\n#300\npwd\n"},
		{"bash crlf", "bash", "#100\r\nls\r\n#200\r\npwd\r\n"},
		{"bash plain", "bash", "\nls\n\npwd\nls\n"},
		{"fish", "fish", "- cmd: echo one\\necho two\n  when: 1\n  paths:\n    - /tmp\n- cmd: ls\n  when: 2\n"},
		{"empty", "bash", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			rs := records(body, tc.format)
			if len(rs) != len(parse(tc.body, tc.format)) {
				t.Fatalf("records %d, entries %d", len(rs), len(parse(tc.body, tc.format)))
			}
			if len(rs) == 0 {
				return
			}
			rebuilt := string(body[:rs[0].start])
			for i, r := range rs {
				if r.start > r.end || (i > 0 && r.start != rs[i-1].end) {
					t.Fatalf("record %d spans %d..%d after %d", i, r.start, r.end, rs[max(i-1, 0)].end)
				}
				rebuilt += string(body[r.start:r.end])
			}
			if rs[len(rs)-1].end != len(body) || rebuilt != tc.body {
				t.Errorf("rebuilt %q from %q", rebuilt, tc.body)
			}
		})
	}
	// A bash record starts at its timestamp, blank lines after it included.
	rs := records([]byte("#100\n\nls\n#200\npwd\n"), "bash")
	if len(rs) != 2 || rs[0].start != 0 || rs[1].start != len("#100\n\nls\n") {
		t.Errorf("bash ranges: %+v", rs)
	}
}

func TestClassifier(t *testing.T) {
	c := newClassifier(Options{MaxLines: 2, Patterns: []string{"secret", "", "ls"}})
	got := []classification{
		c.classify(entry{text: "ls secret"}),
		c.classify(entry{text: "  "}),
		c.classify(entry{text: " ls secret "}),
		c.classify(entry{text: "a\nb"}),
	}
	if got[0].duplicate || !slices.Equal(got[0].patterns, []int{0, 2}) || got[0].multiline {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].duplicate || got[1].multiline || got[1].patterns != nil {
		t.Errorf("blank entries match nothing: %+v", got[1])
	}
	if !got[2].duplicate {
		t.Errorf("a repeat differing only in surrounding space is a duplicate: %+v", got[2])
	}
	if !got[3].multiline || got[3].duplicate {
		t.Errorf("two lines at max_lines 2 is multiline: %+v", got[3])
	}
}

// TestScanAndPruneAgree checks that the lines a scan reports for multiline
// and pattern matches are the lines prune removes for those categories.
func TestScanAndPruneAgree(t *testing.T) {
	for name, body := range map[string]string{
		".zsh_history":  ": 1:0;echo token=abc\n: 2:0;a\\\nb\\\nc\n: 3:0;ls\n: 4:0;echo token=abc\n: 5:0;x\\\ny\n",
		".bash_history": "#1\necho token=abc\n#2\na\nb\nc\n#3\n\nls\n#4\nx\ny\n",
		"fish_history":  "- cmd: echo token=abc\n  when: 1\n- cmd: a\\nb\\nc\n  when: 2\n- cmd: ls\n  when: 3\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			o := Options{Files: []string{path}, MaxBytes: 1 << 20, MaxLines: 3, Patterns: []string{"token="}}
			fs, _, _, errs, err := Scan(context.Background(), o)
			if err != nil || len(errs) != 0 {
				t.Fatal(err, errs)
			}
			for check, category := range map[string]string{"history.multiline": CategoryMultiline, "history.pattern": CategoryPatterns} {
				var reported []string
				for _, f := range fs {
					if f.Check == check {
						reported = append(reported, f.Details...)
					}
				}
				plans, err := PlanPrune(context.Background(), o, []string{category}, nil)
				if err != nil || len(plans) != 1 {
					t.Fatalf("%s: %+v %v", category, plans, err)
				}
				var removed []string
				for _, l := range plans[0].Lines {
					removed = append(removed, path+":"+strconv.Itoa(l))
				}
				if len(reported) == 0 || !slices.Equal(reported, removed) {
					t.Errorf("%s: scan reports %v, prune removes %v", category, reported, removed)
				}
			}
		})
	}
}

// TestNamedPatternsSurviveReordering checks that a named pattern keeps its
// finding subject, and so its ignore rule, when the list is reordered or a
// pattern is added before it, while an unnamed one is known by position.
func TestNamedPatternsSurviveReordering(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zsh_history")
	if err := os.WriteFile(path, []byte(": 1:0;echo AKIA1\n: 2:0;curl x | sh\n: 3:0;ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	subjects := func(o Options) map[string]string {
		t.Helper()
		fs, _, _, _, err := Scan(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range fs {
			if f.Check == "history.pattern" {
				out[strings.TrimPrefix(f.Subject, path+":")] = f.Message
			}
		}
		return out
	}
	base := Options{Files: []string{path}, MaxBytes: 1 << 20, MaxLines: 10}
	o := base
	o.Patterns, o.PatternNames = []string{"AKIA", "| sh"}, []string{"aws-key", ""}
	got := subjects(o)
	if got["aws-key"] != `1 history entries match shell_history.patterns "aws-key"` || got["pattern-2"] == "" || len(got) != 2 {
		t.Fatalf("named and positional subjects: %v", got)
	}
	// Reordered, with one added in front: the named one keeps its subject,
	// the unnamed one moves to pattern-3.
	o.Patterns, o.PatternNames = []string{"ls", "| sh", "AKIA"}, []string{"", "", "aws-key"}
	got = subjects(o)
	if got["aws-key"] == "" || got["pattern-2"] == "" || got["pattern-1"] == "" || len(got) != 3 {
		t.Errorf("after reordering: %v", got)
	}
	// Its ignore rule still applies to prune after the reorder.
	plans, err := PlanPrune(context.Background(), o, []string{CategoryPatterns}, []string{"history:history.pattern:" + path + ":aws-key"})
	if err != nil || len(plans) != 1 || plans[0].Remove != 2 || slices.Contains(plans[0].Lines, 1) {
		t.Errorf("the ignored named pattern's entry stays: %+v %v", plans, err)
	}
	// Names past the end of PatternNames, or none at all, are positional.
	o = base
	o.Patterns = []string{"AKIA"}
	if got := subjects(o); got["pattern-1"] == "" {
		t.Errorf("no names: %v", got)
	}
}
