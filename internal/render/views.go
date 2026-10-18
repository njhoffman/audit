package render

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/environment"
	"github.com/njhoffman/audit/internal/packages"
)

// Packages prints each manager's inventory with the cached registry data:
// the latest release colored by how far behind the install is, its age, and
// the package's tags. The header says how old the registry data is.
func (p *Printer) Packages(as []packages.Annotated) {
	now := p.Now()
	for i, a := range as {
		inv := a.Inventory
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
			if c := packages.RegistryNote(a, now); c != "" {
				meta = append(meta, c)
			}
		}
		p.printf("%s  %s\n", head, p.faint().Render(strings.Join(meta, "  ")))
		if len(a.Items) == 0 {
			continue
		}
		cols := []column{{title: "NAME"}, {title: "VERSION"}, {title: "LATEST"}, {title: "RELEASED"}, {title: "RUNTIME"},
			{title: "TAGS", flex: !p.Verbose}}
		if p.Verbose {
			cols = append(cols, column{title: "SOURCE"}, column{title: "EXECUTABLES", flex: true})
		}
		rows := make([][]string, len(a.Items))
		for j, it := range a.Items {
			latest, released := packages.LatestCells(it, now)
			rows[j] = []string{it.Name, it.Version, latest, released, it.RuntimeVersion, strings.Join(it.Tags, " ")}
			if p.Verbose {
				rows[j] = append(rows[j], it.Source, strings.Join(it.Executables, " "))
			}
		}
		p.table(cols, rows, func(row, col int) lipgloss.Style {
			switch col {
			case 0:
				return p.bold()
			case 1:
				return p.style()
			case 2:
				return p.gapStyle(a.Items[row])
			}
			return p.faint()
		})
	}
}

// gapStyle colors a latest version by how far behind the install is.
func (p *Printer) gapStyle(it packages.Item) lipgloss.Style {
	if it.Meta != nil && (it.Meta.Deprecated != "" || it.Meta.Archived || (it.Meta.InstalledYanked && it.Meta.Installed == it.Version)) {
		return p.fg("9")
	}
	switch it.Gap {
	case packages.GapMajor:
		return p.fg("9")
	case packages.GapMinor:
		return p.fg("11")
	case packages.GapPatch:
		return p.fg("3")
	case packages.GapCurrent:
		return p.fg("10")
	case packages.GapAhead:
		return p.fg("12")
	}
	return p.faint()
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

// Table prints rows under titles; the last column absorbs the width limit.
func (p *Printer) Table(titles []string, rows [][]string) {
	cols := make([]column, len(titles))
	for i, t := range titles {
		cols[i] = column{title: t, flex: i == len(titles)-1}
	}
	p.table(cols, rows, func(_, col int) lipgloss.Style {
		if col == 0 {
			return p.bold()
		}
		return p.style()
	})
}

// PackageInfo prints everything known about one package. tags are its
// stored tags with their sources; auto tags are those in it.Tags not stored.
func (p *Printer) PackageInfo(it packages.Item, tags []packages.Tag) {
	now := p.Now()
	head := p.bold().Foreground(lipgloss.Color("12")).Render(it.Name)
	sub := []string{it.Manager}
	if r := it.Registry(); r != "" {
		sub = append(sub, r)
	}
	if it.ID() != it.Name {
		sub = append(sub, it.ID())
	}
	p.printf("%s  %s\n", head, p.faint().Render(strings.Join(sub, "  ")))
	var rows [][]string
	add := func(k, v string) {
		if v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	add("installed", it.Version)
	m := it.Meta
	latest, released := packages.LatestCells(it, now)
	if it.Gap != packages.GapUnknown {
		latest += "  " + string(it.Gap)
	}
	if released != "" {
		latest += "; released " + released
	}
	add("latest", latest)
	if m != nil {
		if !m.CheckedAt.IsZero() {
			add("checked", packages.Age(now.Sub(m.CheckedAt))+" ago")
		}
		add("description", m.Description)
		add("repo", m.Repo)
		if m.Homepage != m.Repo {
			add("homepage", m.Homepage)
		}
		add("license", m.License)
		add("keywords", strings.Join(m.Keywords, ", "))
		if m.Deprecated != "" {
			add("deprecated", m.Deprecated)
		}
		if m.Archived {
			add("archived", "the repository is archived")
		}
		if m.InstalledYanked && m.Installed == it.Version {
			add("yanked", "version "+it.Version+" was withdrawn from the registry")
		}
		add("last error", m.Error)
	}
	source := map[string]string{}
	for _, t := range tags {
		source[t.Tag] = t.Source
	}
	tagCells := make([]string, len(it.Tags))
	for i, t := range it.Tags {
		s := source[t]
		if s == "" {
			s = packages.TagAuto
		}
		tagCells[i] = t + " (" + s + ")"
	}
	add("tags", strings.Join(tagCells, " "))
	add("runtime", strings.TrimSpace(it.Runtime+" "+it.RuntimeVersion))
	add("executables", strings.Join(it.Executables, " "))
	add("source", it.Source)
	add("location", it.Location)
	if it.Gap.Behind() {
		add("update", packages.UpdateHint(it.Package))
	}
	p.table([]column{{title: ""}, {title: "", flex: true}}, rows, func(row, col int) lipgloss.Style {
		switch {
		case col == 0:
			return p.faint()
		case rows[row][0] == "latest":
			return p.gapStyle(it)
		case rows[row][0] == "deprecated" || rows[row][0] == "archived" || rows[row][0] == "yanked" || rows[row][0] == "last error":
			return p.fg("9")
		}
		return p.style()
	})
}
