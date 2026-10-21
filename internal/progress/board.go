package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/x/ansi"
)

// Board shows one line per task while several run at once: waiting, the
// current phase with a spinner, or how the task ended. It redraws the whole
// block in place, so it is only for terminals.
type Board struct {
	mu    sync.Mutex
	out   io.Writer
	width func() int
	tasks []*boardTask
	frame int
	drawn int // lines of the block on screen
	stop  chan struct{}
}

type boardTask struct {
	name    string
	label   string
	item    string
	total   int
	done    int
	started time.Time
	running bool
	result  string // set when the task ended
	failed  bool
}

// NewBoard returns a Board for the named tasks, in that order; width
// reports the terminal width.
func NewBoard(out io.Writer, width func() int, names []string) *Board {
	b := &Board{out: out, width: width}
	for _, n := range names {
		b.tasks = append(b.tasks, &boardTask{name: n})
	}
	return b
}

// Start draws the block and keeps the spinners moving until Stop.
func (b *Board) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		return
	}
	b.stop = make(chan struct{})
	go b.tick(b.stop)
	b.draw()
}

// Stop draws the final state and leaves it on screen.
func (b *Board) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
	b.draw()
}

// Task returns the Reporter of the named task; its phases show on the
// task's line. The task counts as running from its first phase.
func (b *Board) Task(name string) Reporter {
	return &boardReporter{b: b, t: b.find(name)}
}

// Finish ends the named task with result, in red when failed.
func (b *Board) Finish(name, result string, failed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.find(name)
	t.running, t.result, t.failed = false, result, failed
	b.draw()
}

func (b *Board) find(name string) *boardTask {
	for _, t := range b.tasks {
		if t.name == name {
			return t
		}
	}
	t := &boardTask{name: name}
	b.tasks = append(b.tasks, t)
	return t
}

func (b *Board) tick(stop chan struct{}) {
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			b.mu.Lock()
			b.frame++
			b.draw()
			b.mu.Unlock()
		}
	}
}

// Lines renders the block without writing it.
func (b *Board) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lines()
}

func (b *Board) lines() []string {
	nameW := 0
	for _, t := range b.tasks {
		nameW = max(nameW, len(t.name))
	}
	out := make([]string, len(b.tasks))
	for i, t := range b.tasks {
		name := t.name + strings.Repeat(" ", nameW-len(t.name))
		switch {
		case t.result != "" && t.failed:
			out[i] = fmt.Sprintf("\x1b[31m✗\x1b[0m %s  \x1b[31m%s\x1b[0m", name, t.result)
		case t.result != "":
			out[i] = fmt.Sprintf("\x1b[32m✓\x1b[0m %s  %s", name, t.result)
		case t.running:
			var sb strings.Builder
			fmt.Fprintf(&sb, "%s %s  %s", spinner[b.frame%len(spinner)], name, t.label)
			if t.total > 0 {
				fmt.Fprintf(&sb, " %d/%d", t.done, t.total)
			}
			fmt.Fprintf(&sb, "  %.0fs", time.Since(t.started).Seconds())
			if t.item != "" {
				fmt.Fprintf(&sb, "  \x1b[90m%s\x1b[0m", t.item)
			}
			out[i] = sb.String()
		default:
			out[i] = fmt.Sprintf("\x1b[90m· %s  waiting\x1b[0m", name)
		}
	}
	return out
}

func (b *Board) draw() {
	w := b.width()
	if w <= 1 {
		w = 80
	}
	var sb strings.Builder
	if b.drawn > 0 {
		fmt.Fprintf(&sb, "\x1b[%dA", b.drawn)
	}
	lines := b.lines()
	for _, l := range lines {
		fmt.Fprintf(&sb, "\r\x1b[2K%s\n", ansi.Truncate(l, w-1, "…"))
	}
	b.drawn = len(lines)
	_, _ = io.WriteString(b.out, sb.String())
}

// println prints line above the block and redraws it.
func (b *Board) println(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sb strings.Builder
	if b.drawn > 0 {
		fmt.Fprintf(&sb, "\x1b[%dA\x1b[J", b.drawn)
	}
	fmt.Fprintln(&sb, line)
	_, _ = io.WriteString(b.out, sb.String())
	b.drawn = 0
	b.draw()
}

// boardReporter is one task's Reporter on a Board.
type boardReporter struct {
	b *Board
	t *boardTask
}

func (r *boardReporter) Phase(label string, total int) {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	if !r.t.running && r.t.result == "" {
		r.t.running, r.t.started = true, time.Now()
	}
	r.t.label, r.t.total, r.t.done, r.t.item = label, total, 0, ""
}

func (r *boardReporter) Step(item string) {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	r.t.done++
	r.t.item = item
}

func (r *boardReporter) Status(item string) {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	r.t.item = item
}

// Done keeps the line: a scan calls it between its own phases, and the
// task ends only through Board.Finish.
func (r *boardReporter) Done() {}

func (r *boardReporter) Println(line string) { r.b.println(line) }

// Writer returns a writer whose lines print above the block, for logs
// written while the board is up.
func (b *Board) Writer() io.Writer { return boardWriter{b} }

type boardWriter struct{ b *Board }

func (w boardWriter) Write(p []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.b.println(l)
	}
	return len(p), nil
}
