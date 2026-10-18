// Package progress shows a one-line progress bar on stderr while a scan runs.
// It draws only when stderr is a terminal, so redirected output stays clean.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

// Reporter receives scan progress. Implementations are safe for concurrent
// use.
type Reporter interface {
	// Phase starts a named phase of total units; total 0 means the amount
	// of work is unknown and a spinner is shown instead of a bar.
	Phase(label string, total int)
	// Step marks one unit of the current phase finished; item names it.
	Step(item string)
	// Done clears the line. The reporter can be reused afterwards.
	Done()
}

// Nop discards progress.
var Nop Reporter = nop{}

type nop struct{}

func (nop) Phase(string, int) {}
func (nop) Step(string)       {}
func (nop) Done()             {}

// New returns a bar on stderr when it is a terminal and enabled is true, and
// Nop otherwise.
func New(enabled bool) Reporter {
	fd := int(os.Stderr.Fd()) // #nosec G115 -- file descriptors fit in int
	if !enabled || !term.IsTerminal(fd) {
		return Nop
	}
	return NewBar(os.Stderr, func() int {
		w, _, err := term.GetSize(fd)
		if err != nil {
			return 80
		}
		return w
	})
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Bar draws progress to a writer, redrawing on every step and on a ticker so
// the spinner and elapsed time keep moving between steps.
type Bar struct {
	mu      sync.Mutex
	out     io.Writer
	width   func() int
	bar     progress.Model
	label   string
	item    string
	total   int
	done    int
	frame   int
	started time.Time
	stop    chan struct{}
	drawn   bool
}

// NewBar returns a Bar writing to out; width reports the terminal width.
func NewBar(out io.Writer, width func() int) *Bar {
	return &Bar{
		out:   out,
		width: width,
		bar:   progress.New(progress.WithDefaultGradient(), progress.WithWidth(28), progress.WithoutPercentage()),
	}
}

// Phase implements Reporter.
func (b *Bar) Phase(label string, total int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.label, b.total, b.done, b.item = label, total, 0, ""
	b.started = time.Now()
	if b.stop == nil {
		b.stop = make(chan struct{})
		go b.tick(b.stop)
	}
	b.draw()
}

// Step implements Reporter.
func (b *Bar) Step(item string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done++
	b.item = item
	b.draw()
}

// Done implements Reporter.
func (b *Bar) Done() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
	if b.drawn {
		_, _ = io.WriteString(b.out, "\r\x1b[2K")
		b.drawn = false
	}
}

func (b *Bar) tick(stop chan struct{}) {
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

// Line renders the current state without writing it.
func (b *Bar) Line() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.line()
}

func (b *Bar) line() string {
	var sb strings.Builder
	sb.WriteString(spinner[b.frame%len(spinner)])
	sb.WriteString(" ")
	sb.WriteString(b.label)
	if b.total > 0 {
		pct := float64(b.done) / float64(b.total)
		if pct > 1 {
			pct = 1
		}
		fmt.Fprintf(&sb, "  %s  %d/%d", b.bar.ViewAs(pct), b.done, b.total)
	}
	fmt.Fprintf(&sb, "  %.1fs", time.Since(b.started).Seconds())
	if b.item != "" {
		sb.WriteString("  ")
		sb.WriteString(b.item)
	}
	return sb.String()
}

func (b *Bar) draw() {
	w := b.width()
	if w <= 1 {
		w = 80
	}
	_, _ = io.WriteString(b.out, "\r\x1b[2K"+ansi.Truncate(b.line(), w-1, "…"))
	b.drawn = true
}
