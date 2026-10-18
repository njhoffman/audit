package cmd

import (
	"github.com/spf13/cobra"
)

func newExportCmd(a *app) *cobra.Command {
	var dir string
	c := &cobra.Command{
		Use:   "export",
		Short: "Write the JSON snapshots that other programs read",
		Long: `Write summary.json, tasks.json, updates.json and one file per scanned
command into the export directory (export.dir, by default
<data_dir>/export) and print its path. With export.enabled, the default,
the files are already rewritten whenever a command saves something; this
writes them on demand, or somewhere else with --dir. Nothing is scanned.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := a.load(); err != nil {
				return err
			}
			if dir == "" {
				dir = a.cfg.ExportDir()
			}
			if err := a.export(c.Context(), dir); err != nil {
				return err
			}
			sayln(a.out, dir)
			return nil
		},
	}
	c.Flags().StringVarP(&dir, "dir", "d", "", "write the files here instead of export.dir")
	return c
}
