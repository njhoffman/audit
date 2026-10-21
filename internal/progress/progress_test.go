package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestBarCountsAndClears(t *testing.T) {
	var out syncBuf
	b := NewBar(&out, func() int { return 200 })
	b.Phase("collecting", 3)
	b.Step("uv")
	b.Step("cargo")
	line := ansi.Strip(b.Line())
	if !strings.Contains(line, "collecting") || !strings.Contains(line, "2/3") || !strings.Contains(line, "cargo") {
		t.Errorf("line = %q", line)
	}
	b.Done()
	if !strings.HasSuffix(out.String(), "\r\x1b[2K") {
		t.Errorf("not cleared: %q", out.String())
	}
}

func TestIndeterminatePhaseHasNoCount(t *testing.T) {
	b := NewBar(&syncBuf{}, func() int { return 200 })
	b.Phase("waiting", 0)
	defer b.Done()
	if line := ansi.Strip(b.Line()); strings.Contains(line, "/") {
		t.Errorf("line = %q", line)
	}
}

func TestDrawTruncatesToWidth(t *testing.T) {
	var out syncBuf
	b := NewBar(&out, func() int { return 20 })
	b.Phase(strings.Repeat("x", 100), 2)
	b.Done()
	for _, seg := range strings.Split(out.String(), "\r\x1b[2K") {
		if w := ansi.StringWidth(seg); w > 19 {
			t.Errorf("segment width %d: %q", w, seg)
		}
	}
}

func TestNopAndConcurrentSteps(t *testing.T) {
	Nop.Phase("x", 1)
	Nop.Step("y")
	Nop.Done()
	b := NewBar(&syncBuf{}, func() int { return 80 })
	b.Phase("p", 50)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.Step("s") }()
	}
	wg.Wait()
	if !strings.Contains(ansi.Strip(b.Line()), "50/50") {
		t.Errorf("line = %q", b.Line())
	}
	b.Done()
}

func TestLiner(t *testing.T) {
	var out syncBuf
	b := NewBar(&out, func() int { return 200 })
	b.Phase("updating", 2)
	Status(b, "uv:ruff 0.9.0 -> 0.9.5")
	if line := ansi.Strip(b.Line()); !strings.Contains(line, "0/2") || !strings.Contains(line, "uv:ruff") {
		t.Errorf("status should name the item without counting it: %q", line)
	}
	Println(b, nil, "ok  uv:ruff")
	if !strings.Contains(out.String(), "\r\x1b[2Kok  uv:ruff\n") {
		t.Errorf("line not printed above the bar: %q", out.String())
	}
	b.Done()

	var plain syncBuf
	Status(Nop, "ignored")
	Println(Nop, &plain, "ok  uv:ruff")
	if plain.String() != "ok  uv:ruff\n" {
		t.Errorf("without a bar the line goes to the writer: %q", plain.String())
	}
}

func TestBoard(t *testing.T) {
	var out syncBuf
	b := NewBoard(&out, func() int { return 200 }, []string{"system", "environment", "ai"})
	b.Start()
	r := b.Task("environment")
	r.Phase("tracing", 2)
	r.Step("zsh")
	r.Done()
	b.Finish("system", "12s  3 task(s) updated", false)
	b.Finish("ai", "exit status 1", true)
	strip := func() []string {
		var ls []string
		for _, l := range b.Lines() {
			ls = append(ls, ansi.Strip(l))
		}
		return ls
	}
	got := strip()
	if got[0] != "✓ system       12s  3 task(s) updated" || !strings.Contains(got[1], "environment  tracing 1/2") ||
		!strings.HasSuffix(got[1], "zsh") || got[2] != "✗ ai           exit status 1" {
		t.Errorf("lines = %q", got)
	}
	r.(Liner).Println("note")
	b.Stop()
	if !strings.Contains(out.String(), "note\n") {
		t.Error("Println prints above the block")
	}
	if got := strip(); !strings.Contains(got[1], "tracing") {
		t.Errorf("Done between phases keeps the task running: %q", got[1])
	}
	if w := NewBoard(&out, func() int { return 200 }, []string{"x"}).Lines()[0]; ansi.Strip(w) != "· x  waiting" {
		t.Errorf("waiting line %q", w)
	}
}
