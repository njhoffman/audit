package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/njhoffman/audit/internal/repos"
	"github.com/njhoffman/audit/internal/run"
)

// RepoState is a short summary of a repo's local state: "clean", or the
// parts that need attention ("2 staged", "+3 -1", "rebase", ...).
func RepoState(r repos.Repo) string {
	var parts []string
	if r.Operation != "" {
		parts = append(parts, r.Operation)
	}
	if r.Conflicts > 0 {
		parts = append(parts, fmt.Sprintf("%d conflicted", r.Conflicts))
	}
	if r.Staged > 0 {
		parts = append(parts, fmt.Sprintf("%d staged", r.Staged))
	}
	if r.Modified > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", r.Modified))
	}
	if r.Untracked > 0 {
		parts = append(parts, fmt.Sprintf("%d untracked", r.Untracked))
	}
	if r.Ahead > 0 || r.Behind > 0 {
		parts = append(parts, fmt.Sprintf("+%d -%d", r.Ahead, r.Behind))
	}
	if r.Stashes > 0 {
		parts = append(parts, fmt.Sprintf("%d stash", r.Stashes))
	}
	if r.Error != "" {
		parts = append(parts, "error")
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, ", ")
}

// Repos prints the repo inventory, one row per repo; home is shortened to ~.
func (p *Printer) Repos(items []repos.Item, home string) {
	now := p.Now()
	cols := []column{{title: "REPO"}, {title: "BRANCH"}, {title: "STATE"}, {title: "COMMITTED"}, {title: "FETCHED"},
		{title: "TAGS", flex: true}}
	rows := make([][]string, len(items))
	for i, it := range items {
		name := it.Slug()
		if it.Host == "" {
			name = shortHome(it.Path, home)
		}
		branch := it.Branch
		if it.Detached {
			branch = "(detached)"
		}
		committed, fetched := "-", "never"
		if !it.LastCommit.IsZero() {
			committed = run.HumanAge(now.Sub(it.LastCommit))
		}
		if !it.LastFetch.IsZero() {
			fetched = run.HumanAge(now.Sub(it.LastFetch))
		}
		if it.Remotes == 0 {
			fetched = "-"
		}
		rows[i] = []string{name, branch, RepoState(it.Repo), committed, fetched, strings.Join(it.Tags, " ")}
	}
	p.table(cols, rows, func(row, col int) lipgloss.Style {
		it := items[row]
		switch col {
		case 0:
			if it.IsMine {
				return p.bold().Foreground(lipgloss.Color("12"))
			}
			return p.bold()
		case 2:
			switch {
			case it.Operation != "" || it.Conflicts > 0 || it.Error != "":
				return p.fg("9")
			case it.Dirty() || it.Ahead > 0:
				return p.fg("11")
			case !it.Clean() || it.Behind > 0 || it.Stashes > 0:
				return p.fg("3")
			}
			return p.fg("10")
		}
		return p.faint()
	})
	mine := 0
	for _, it := range items {
		if it.IsMine {
			mine++
		}
	}
	p.printf("%d repo(s), %d yours.\n", len(items), mine)
}

func shortHome(path, home string) string {
	if home != "" && strings.HasPrefix(path, home+"/") {
		return "~" + path[len(home):]
	}
	return path
}
