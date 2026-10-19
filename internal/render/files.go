package render

import (
	"fmt"

	"github.com/njhoffman/audit/internal/files"
)

// Files prints where space goes and the cleanup candidates of a files run.
func (p *Printer) Files(d files.Data, home string) {
	section := func(title string, rows [][]string, cols ...string) {
		if len(rows) == 0 {
			return
		}
		p.printf("\n%s\n", p.heading(title))
		p.Table(cols, rows)
	}
	var rows [][]string
	for _, f := range d.Top {
		rows = append(rows, []string{files.Human(f.Bytes), pct(f.Bytes, d.Bytes), shortHome(f.Path, home)})
	}
	section("Largest directories", rows, "SIZE", "SHARE", "PATH")
	rows = nil
	for _, c := range d.Caches {
		where := c.Path
		if where == "" {
			where = "-"
		}
		rows = append(rows, []string{files.Human(c.Bytes), c.Name, shortHome(where, home)})
	}
	section("Caches", rows, "SIZE", "CACHE", "PATH")
	rows = nil
	for _, b := range d.Build {
		rows = append(rows, []string{files.Human(b.Bytes), b.Kind, b.ModTime.Format("2006-01-02"), shortHome(b.Path, home)})
	}
	section("Idle build and dependency directories", rows, "SIZE", "KIND", "CHANGED", "PATH")
	rows = nil
	for _, o := range d.Orphans {
		rows = append(rows, []string{files.Human(o.Bytes), shortHome(o.Path, home)})
	}
	section("Data of programs that look uninstalled", rows, "SIZE", "PATH")
	rows = nil
	for _, f := range d.Big {
		rows = append(rows, []string{files.Human(f.Bytes), f.ModTime.Format("2006-01-02"), shortHome(f.Path, home)})
	}
	section("Largest files", rows, "SIZE", "CHANGED", "PATH")
	rows = nil
	for _, x := range d.Dups {
		rows = append(rows, []string{files.Human(x.Bytes), fmt.Sprint(len(x.Paths)), shortHome(x.Paths[0], home)})
	}
	section("Duplicates", rows, "SIZE", "COPIES", "FIRST")
	p.printf("\n%s scanned, about %s reclaimable.\n", files.Human(d.Bytes), files.Human(d.Reclaimable))
}

func pct(n, total int64) string {
	if total == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", float64(n)*100/float64(total))
}
