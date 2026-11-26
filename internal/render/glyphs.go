package render

import (
	"github.com/njhoffman/audit/internal/finding"
	"github.com/njhoffman/audit/internal/todo"
)

// Glyphs are the markers and icons of terminal output. Unicode markers
// work in any font; Nerd Font icons need a patched font
// (display.nerd_fonts). A name with no icon gets "".
type Glyphs struct {
	Nerd     bool
	Severity map[finding.Severity]string
	Priority map[todo.Priority]string
	// Icons are keyed by command, summary group and section heading.
	Icons map[string]string
}

// UnicodeGlyphs are plain Unicode markers and no icons. A priority shares
// the marker (and color) of the severity whose findings become tasks of it
// (error high, warning medium, notice low); critical, info and suggestion
// map to nothing else and have markers of their own.
var UnicodeGlyphs = Glyphs{
	Severity: map[finding.Severity]string{
		finding.Critical: "◉", finding.Error: "●", finding.Warning: "▲", finding.Notice: "◆", finding.Info: "○",
	},
	Priority: map[todo.Priority]string{
		todo.High: "●", todo.Medium: "▲", todo.Low: "◆", todo.Suggestion: "◇",
	},
}

// NerdGlyphs are Nerd Font icons, all from the Basic Multilingual Plane:
// terminals draw the supplementary-plane ones (md-*) two cells wide while
// width calculations count one, which breaks alignment.
var NerdGlyphs = Glyphs{
	Nerd: true,
	Severity: map[finding.Severity]string{
		finding.Critical: "\uf06a", // fa-exclamation_circle
		finding.Error:    "\uf057", // fa-times_circle
		finding.Warning:  "\uf071", // fa-warning
		finding.Notice:   "\uf0f3", // fa-bell
		finding.Info:     "\uf05a", // fa-info_circle
	},
	// As in UnicodeGlyphs, a priority shares its severity's icon.
	Priority: map[todo.Priority]string{
		todo.High:       "\uf057", // fa-times_circle, as error
		todo.Medium:     "\uf071", // fa-warning, as warning
		todo.Low:        "\uf0f3", // fa-bell, as notice
		todo.Suggestion: "\uf0eb", // fa-lightbulb_o
	},
	Icons: map[string]string{
		// commands
		"system":      "\uf108", // fa-desktop
		"environment": "\uf489", // oct-terminal
		"packages":    "\uf487", // oct-package
		"repos":       "\ue725", // dev-git_branch
		"files":       "\uf07b", // fa-folder
		"configs":     "\uf013", // fa-cog
		"scripts":     "\uf1c9", // fa-file_code_o
		"history":     "\uf1da", // fa-history
		"ai":          "\uf0d0", // fa-magic
		"tasks":       "\uf4a0", // oct-tasklist
		// report sections
		"Summary":     "\uf080", // fa-bar_chart
		"Scan errors": "\uf057", // fa-times_circle
		"Issues":      "\uf188", // fa-bug
		"Suggestions": "\uf0eb", // fa-lightbulb_o
		"AI review":   "\uf0d0", // fa-magic
		// summary groups
		"startup":   "\uf135", // fa-rocket
		"zsh":       "\uf489", // oct-terminal
		"bash":      "\uf489",
		"github":    "\uf09b", // fa-github
		"registry":  "\uf0c2", // fa-cloud
		"managers":  "\uf487",
		"update":    "\uf021", // fa-refresh
		"updates":   "\uf021",
		"largest":   "\uf07b",
		"procs":     "\uf4bc", // oct-cpu
		"services":  "\uf013",
		"users":     "\uf0c0", // fa-users
		"logs":      "\uf0f6", // fa-file_text_o
		"programs":  "\uf00a", // fa-th
		"storage":   "\uf0a0", // fa-hdd_o
		"resources": "\uf0e4", // fa-tachometer
		"security":  "\uf132", // fa-shield
	},
}

// GlyphsFor picks the Nerd Font icons or the Unicode markers.
func GlyphsFor(nerd bool) Glyphs {
	if nerd {
		return NerdGlyphs
	}
	return UnicodeGlyphs
}

// Icon is name's icon followed by a space, or "" when it has none.
// PriorityLabel is a priority with its marker in front ("● high"), as the
// task editor, audit todo and the fzf task list show it.
func (g Glyphs) PriorityLabel(p todo.Priority) string {
	if m := g.Priority[p]; m != "" {
		return m + " " + string(p)
	}
	return string(p)
}

func (g Glyphs) Icon(name string) string {
	if i := g.Icons[name]; i != "" {
		return i + " "
	}
	return ""
}
