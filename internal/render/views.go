package render

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/packages"
)

// Packages prints the inventory of a packages run, one table per manager.
func (p *Printer) Packages(d packages.Data) {
	for i, inv := range d.Inventories {
		if i > 0 {
			p.println("")
		}
		head := p.bold().Foreground(lipgloss.Color("12")).Render(inv.Manager)
		var meta []string
		if inv.ManagerVersion != "" {
			meta = append(meta, inv.ManagerVersion)
		}
		if inv.Runtime != nil && inv.Runtime.Version != "" {
			meta = append(meta, inv.Runtime.Name+" "+inv.Runtime.Version)
		}
		switch {
		case !inv.Available:
			meta = append(meta, "not installed")
		case inv.Error != "":
			meta = append(meta, p.fg("9").Render("error: "+inv.Error))
		default:
			meta = append(meta, fmt.Sprintf("%d package(s)", len(inv.Packages)),
				inv.Duration.Round(time.Millisecond).String())
		}
		p.printf("%s  %s\n", head, p.faint().Render(strings.Join(meta, "  ")))
		if len(inv.Packages) == 0 {
			continue
		}
		cols := []column{{title: "NAME"}, {title: "VERSION"}, {title: "RUNTIME"}, {title: "SOURCE", flex: !p.Verbose}}
		if p.Verbose {
			cols = append(cols, column{title: "EXECUTABLES", flex: true})
		}
		rows := make([][]string, len(inv.Packages))
		for j, pkg := range inv.Packages {
			rows[j] = []string{pkg.Name, pkg.Version, pkg.RuntimeVersion, pkg.Source}
			if p.Verbose {
				rows[j] = append(rows[j], strings.Join(pkg.Executables, " "))
			}
		}
		p.table(cols, rows, func(_, col int) lipgloss.Style {
			if col == 0 {
				return p.bold()
			}
			if col >= 2 {
				return p.faint()
			}
			return p.style()
		})
	}
}

// Environment prints the captured shells and the startup scripts found.
func (p *Printer) Environment(d environment.Data) {
	p.println(p.heading("Shell startup"))
	rows := make([][]string, len(d.Captures))
	for i, c := range d.Captures {
		status := fmt.Sprintf("exit %d", c.Code)
		switch {
		case c.Err != "":
			status = c.Err
		case c.TimedOut:
			status = "timed out"
		}
		rows[i] = []string{c.Shell, c.Mode, c.Duration.Round(10 * time.Millisecond).String(), status,
			fmt.Sprintf("%d", len(c.Output))}
	}
	p.table([]column{{title: "SHELL"}, {title: "MODE"}, {title: "TIME"}, {title: "STATUS", flex: true}, {title: "UNEXPECTED OUTPUT"}},
		rows, nil)

	p.printf("\n%s  %s\n", p.heading("Scripts"), p.faint().Render("analyzed env: "+d.EnvSource))
	failed := map[string]bool{}
	for _, s := range d.Syntax {
		failed[s.Path] = true
	}
	srows := make([][]string, len(d.Scripts))
	for i, s := range d.Scripts {
		role := "sourced"
		switch {
		case s.Startup:
			role = "startup"
		case s.Executable:
			role = "executable"
		case s.Function != "":
			role = "function"
		case len(s.LoadedBy) == 0 && len(d.Traced) > 0:
			role = "not loaded"
		}
		state := ""
		if failed[s.Path] {
			state = "syntax error"
		}
		srows[i] = []string{string(s.Dialect), role, state, s.Path}
	}
	p.table([]column{{title: "DIALECT"}, {title: "ROLE"}, {title: "STATE"}, {title: "PATH", flex: true}},
		srows, func(row, col int) lipgloss.Style {
			if col == 2 {
				return p.fg("9")
			}
			if col == 1 && srows[row][1] == "not loaded" {
				return p.faint()
			}
			return p.style()
		})
}
