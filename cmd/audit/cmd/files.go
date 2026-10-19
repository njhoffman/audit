package cmd

import (
	"context"
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/njhoffman/audit/internal/core"
	"github.com/njhoffman/audit/internal/files"
	"github.com/njhoffman/audit/internal/render"
	"github.com/njhoffman/audit/internal/run"
)

func newFilesCmd(a *app) *cobra.Command {
	c, f := scanCommand(a, "files", "Show where disk space goes and what can be reclaimed",
		`Measure files.roots (home by default) without crossing into other
filesystems, and find space to reclaim: tool and system caches (uv, pip,
go, pnpm, npm, yarn, cargo, thumbnails, apt archives, the journal,
disabled snap revisions, docker), node_modules, target, .venv and other
build directories of projects idle for files.stale_after, data in
~/.cache, ~/.local/share and ~/.local/state of programs that look
uninstalled, the largest files, downloads older than files.old_downloads,
a large trash, duplicate files (confirmed by hash), core dumps, empty
directories and broken symlinks.

--list prints the largest directories and every candidate. Nothing is
deleted here; audit files clean plans the cleanup.`,
		func() (core.Scanner, error) { return core.NewFiles(a.cfg, a.env), nil },
		func(_ context.Context, p *render.Printer, r *run.Run) {
			var d files.Data
			if err := json.Unmarshal(r.Data, &d); err != nil {
				a.log.Warn("read files data", "err", err)
				return
			}
			p.Files(d, a.env.Home)
		})
	f.jsonExtra = func(_ context.Context, r *run.Run) (any, error) {
		var d files.Data
		err := json.Unmarshal(r.Data, &d)
		return d, err
	}
	return c
}
